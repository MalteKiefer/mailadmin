// Package services wraps systemctl for an explicit unit allowlist only — never
// a wildcard unit. Verbs are limited to status/start/stop/restart/reload.
//
// systemctl is invoked exclusively through internal/sys (arg slices, no shell,
// context timeout, captured output). Every unit name is validated and checked
// against the allowlist before it reaches the command line, so a caller can
// never act on a unit outside the configured set.
package services

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"mailadmin/internal/sys"
	"mailadmin/internal/valid"
)

const binSystemctl = "/usr/bin/systemctl"

// showProperties are the systemctl unit properties queried for a status view.
// Order matters: parseShow keys on the property name, but requesting a stable,
// minimal set keeps output small and injection-free.
var showProperties = []string{"ActiveState", "SubState", "UnitFileState"}

// ErrUnitNotAllowed is returned when a unit is not in the configured allowlist.
var ErrUnitNotAllowed = errors.New("services: unit not allowed")

// Status is the state of one managed unit.
type Status struct {
	Unit    string `json:"unit"`
	Active  string `json:"active"`  // active|inactive|failed|...
	Sub     string `json:"sub"`     // running|dead|exited|...
	Enabled string `json:"enabled"` // enabled|disabled|static
}

// Service runs systemctl against an allowlist of units.
type Service struct {
	runner  *sys.Runner
	allowed map[string]struct{}
}

// New builds a Service allowing only the named units. Blank or malformed unit
// names in allowedUnits are dropped so they can never be acted upon.
func New(runner *sys.Runner, allowedUnits []string) *Service {
	set := make(map[string]struct{}, len(allowedUnits))
	for _, u := range allowedUnits {
		name, err := valid.Unit(u)
		if err != nil {
			continue
		}
		set[name] = struct{}{}
	}
	return &Service{runner: runner, allowed: set}
}

// Allowed reports whether unit is in the allowlist.
func (s *Service) Allowed(unit string) bool {
	_, ok := s.allowed[strings.TrimSpace(unit)]
	return ok
}

// checkUnit validates and allowlist-gates a unit name, returning the normalized
// name. It fails closed: unknown units never reach systemctl.
func (s *Service) checkUnit(unit string) (string, error) {
	name, err := valid.Unit(unit)
	if err != nil {
		return "", fmt.Errorf("services: %w", err)
	}
	if _, ok := s.allowed[name]; !ok {
		return "", fmt.Errorf("%w: %q", ErrUnitNotAllowed, name)
	}
	return name, nil
}

// units returns the allowlisted unit names sorted for stable output.
func (s *Service) units() []string {
	out := make([]string, 0, len(s.allowed))
	for u := range s.allowed {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

// List returns the status of every allowlisted unit, sorted by unit name.
func (s *Service) List(ctx context.Context) ([]Status, error) {
	names := s.units()
	out := make([]Status, 0, len(names))
	for _, u := range names {
		st, err := s.status(ctx, u)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, nil
}

// StatusOf returns the status of one allowlisted unit.
func (s *Service) StatusOf(ctx context.Context, unit string) (Status, error) {
	name, err := s.checkUnit(unit)
	if err != nil {
		return Status{}, err
	}
	return s.status(ctx, name)
}

// status queries systemctl show for a single (already-validated) unit.
func (s *Service) status(ctx context.Context, unit string) (Status, error) {
	argv := []string{
		binSystemctl, "show",
		"--property=" + strings.Join(showProperties, ","),
		"--no-pager",
		"--",
		unit,
	}
	res, err := s.runner.Run(ctx, nil, argv...)
	if err != nil {
		return Status{}, fmt.Errorf("services: systemctl show %s: %w", unit, err)
	}
	if res.ExitCode != 0 {
		return Status{}, fmt.Errorf("services: systemctl show %s: exit %d: %s",
			unit, res.ExitCode, firstLine(res.Stderr))
	}
	return parseShow(unit, string(res.Stdout)), nil
}

// Start starts an allowlisted unit.
func (s *Service) Start(ctx context.Context, unit string) error {
	return s.action(ctx, "start", unit)
}

// Stop stops an allowlisted unit.
func (s *Service) Stop(ctx context.Context, unit string) error {
	return s.action(ctx, "stop", unit)
}

// Restart restarts an allowlisted unit.
func (s *Service) Restart(ctx context.Context, unit string) error {
	return s.action(ctx, "restart", unit)
}

// Reload reloads an allowlisted unit.
func (s *Service) Reload(ctx context.Context, unit string) error {
	return s.action(ctx, "reload", unit)
}

// action runs a single mutating systemctl verb against a gated unit. verb is a
// compile-time constant from the methods above, never user input.
func (s *Service) action(ctx context.Context, verb, unit string) error {
	name, err := s.checkUnit(unit)
	if err != nil {
		return err
	}
	argv := []string{binSystemctl, verb, "--no-pager", "--", name}
	res, err := s.runner.Run(ctx, nil, argv...)
	if err != nil {
		return fmt.Errorf("services: systemctl %s %s: %w", verb, name, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("services: systemctl %s %s: exit %d: %s",
			verb, name, res.ExitCode, firstLine(res.Stderr))
	}
	return nil
}

// parseShow turns `systemctl show --property=...` KEY=VALUE lines into a Status.
// Unknown or missing keys leave their field empty rather than erroring, so a
// partial systemctl output still yields a usable record.
func parseShow(unit, out string) Status {
	st := Status{Unit: unit}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "ActiveState":
			st.Active = val
		case "SubState":
			st.Sub = val
		case "UnitFileState":
			st.Enabled = val
		}
	}
	return st
}

// firstLine returns the first non-empty trimmed line of b, for terse error
// context. It never includes secrets: systemctl argv/output carry none.
func firstLine(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}
