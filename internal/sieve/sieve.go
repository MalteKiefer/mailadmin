// Package sieve manages per-mailbox Sieve scripts via doveadm sieve (get/put/
// list/activate) through internal/sys. Addresses are validated before use and
// every argument reaches doveadm as a slice element (never a shell string).
package sieve

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"mailadmin/internal/sys"
	"mailadmin/internal/valid"
)

const binDoveadm = "/usr/bin/doveadm"

// managedName is the script name mailadmin owns and keeps active for a mailbox.
// It matches the convention used by the previous system so existing scripts are
// picked up unchanged.
const managedName = "mailadmin"

// maxScript bounds a single Sieve script body to avoid unbounded input.
const maxScript = 1 << 16 // 64 KiB

// ErrNotFound is returned when a mailbox has no active Sieve script.
var ErrNotFound = errors.New("sieve: no active script")

// Script is a named Sieve script for a mailbox.
type Script struct {
	Address string `json:"address"`
	Name    string `json:"name"`
	Active  bool   `json:"active"`
	Body    string `json:"body,omitempty"`
}

// Service runs doveadm sieve.
type Service struct {
	runner *sys.Runner
}

// New builds a Service.
func New(runner *sys.Runner) *Service { return &Service{runner: runner} }

// Show returns the active Sieve script for the mailbox address. If the mailbox
// has scripts but none is active, or no scripts at all, it returns ErrNotFound.
func (s *Service) Show(ctx context.Context, address string) (Script, error) {
	user, err := normalizeUser(address)
	if err != nil {
		return Script{}, err
	}

	scripts, err := s.list(ctx, user)
	if err != nil {
		return Script{}, err
	}

	active, ok := activeScript(scripts)
	if !ok {
		return Script{}, ErrNotFound
	}

	body, err := s.get(ctx, user, active.Name)
	if err != nil {
		return Script{}, err
	}

	return Script{Address: user, Name: active.Name, Active: true, Body: body}, nil
}

// Set replaces the managed Sieve script for address with body and activates it.
func (s *Service) Set(ctx context.Context, address, body string) error {
	user, err := normalizeUser(address)
	if err != nil {
		return err
	}
	if len(body) > maxScript {
		return fmt.Errorf("%w: script too large (%d > %d bytes)", valid.ErrInvalid, len(body), maxScript)
	}

	if err := s.put(ctx, user, managedName, body); err != nil {
		return err
	}
	return s.activate(ctx, user, managedName)
}

// normalizeUser validates a mailbox address and returns its canonical
// "local@domain" form for use as the doveadm -u argument.
func normalizeUser(address string) (string, error) {
	local, domain, err := valid.Address(address)
	if err != nil {
		return "", err
	}
	return local + "@" + domain, nil
}

// list runs `doveadm sieve list -u <user>` and parses the result.
func (s *Service) list(ctx context.Context, user string) ([]Script, error) {
	res, err := s.runner.Run(ctx, nil, binDoveadm, "sieve", "list", "-u", user)
	if err := checkResult(res, err, "doveadm sieve list"); err != nil {
		return nil, err
	}
	scripts := parseList(string(res.Stdout))
	for i := range scripts {
		scripts[i].Address = user
	}
	return scripts, nil
}

// get runs `doveadm sieve get -u <user> <name>` and returns the script body.
func (s *Service) get(ctx context.Context, user, name string) (string, error) {
	res, err := s.runner.Run(ctx, nil, binDoveadm, "sieve", "get", "-u", user, name)
	if err := checkResult(res, err, "doveadm sieve get"); err != nil {
		return "", err
	}
	return string(res.Stdout), nil
}

// put runs `doveadm sieve put -u <user> <name>` feeding the body on stdin. The
// body is passed via stdin, never as an argv element.
func (s *Service) put(ctx context.Context, user, name, body string) error {
	res, err := s.runner.Run(ctx, []byte(body), binDoveadm, "sieve", "put", "-u", user, name)
	return checkResult(res, err, "doveadm sieve put")
}

// activate runs `doveadm sieve activate -u <user> <name>`.
func (s *Service) activate(ctx context.Context, user, name string) error {
	res, err := s.runner.Run(ctx, nil, binDoveadm, "sieve", "activate", "-u", user, name)
	return checkResult(res, err, "doveadm sieve activate")
}

// checkResult maps a sys.Result plus runner error into a single wrapped error.
// A nil error and zero exit code mean success. Stderr (capped by sys) is folded
// into the message so failures are diagnosable without leaking script bodies.
func checkResult(res sys.Result, runErr error, op string) error {
	if runErr != nil {
		if detail := strings.TrimSpace(string(res.Stderr)); detail != "" {
			return fmt.Errorf("%s: %w: %s", op, runErr, detail)
		}
		return fmt.Errorf("%s: %w", op, runErr)
	}
	if res.ExitCode != 0 {
		detail := strings.TrimSpace(string(res.Stderr))
		if detail == "" {
			detail = strings.TrimSpace(string(res.Stdout))
		}
		return fmt.Errorf("%s: exit %d: %s", op, res.ExitCode, detail)
	}
	return nil
}

// parseList parses `doveadm sieve list` output. Each non-empty line is a script
// name, optionally followed by "(active)" (case-insensitive), e.g.:
//
//	roundcube
//	mailadmin (active)
func parseList(out string) []Script {
	var scripts []Script
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		active := false
		if name, ok := trimActiveSuffix(line); ok {
			active = true
			line = name
		}
		if line == "" {
			continue
		}
		scripts = append(scripts, Script{Name: line, Active: active})
	}
	return scripts
}

// trimActiveSuffix strips a trailing "(active)" marker (any case, any spacing)
// and reports whether it was present.
func trimActiveSuffix(line string) (string, bool) {
	const marker = "(active)"
	if len(line) < len(marker) {
		return line, false
	}
	tail := line[len(line)-len(marker):]
	if !strings.EqualFold(tail, marker) {
		return line, false
	}
	return strings.TrimSpace(line[:len(line)-len(marker)]), true
}

// activeScript returns the active script from a parsed list, if any.
func activeScript(scripts []Script) (Script, bool) {
	for _, sc := range scripts {
		if sc.Active {
			return sc, true
		}
	}
	return Script{}, false
}
