package dnsrepo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ErrUnchanged is returned when the repository already holds the record.
var ErrUnchanged = errors.New("dnsrepo: dnsconfig.js already holds this record")

// ErrDirty is returned when the repository has local changes. mailadmin never
// commits over someone's work.
var ErrDirty = errors.New("dnsrepo: repository has local changes, commit or stash them first")

// Repo is a local checkout of the DNSControl repository.
type Repo struct {
	Dir string
}

// Proposal is the pull request that carries one change.
type Proposal struct {
	Branch string
	URL    string
}

// State is a change that waits for its pull request to be merged and live.
type State struct {
	Domain  string    `json:"domain"`
	PR      string    `json:"pr"`
	Branch  string    `json:"branch"`
	TLSA    string    `json:"tlsa"` // "usage selector matching hex"
	Created time.Time `json:"created"`
}

// Propose writes the TLSA record for domain into dnsconfig.js and opens a pull request.
func (r Repo) Propose(ctx context.Context, domain, name string, usage, selector, matching int, cert, title, body string) (Proposal, error) {
	return r.ProposeEdit(ctx, "mailadmin/tlsa-"+domain, title, body, func(src string) (string, error) {
		return SetTLSA(src, domain, name, usage, selector, matching, cert)
	})
}

// ProposeEdit applies edit to dnsconfig.js on a new branch from origin/main, commits
// the result and opens a pull request. branchPrefix names the branch; a timestamp is
// appended. Nothing is merged here. ErrUnchanged is returned when edit changes nothing.
func (r Repo) ProposeEdit(ctx context.Context, branchPrefix, title, body string, edit func(src string) (string, error)) (Proposal, error) {
	dirty, err := r.git(ctx, "status", "--porcelain")
	if err != nil {
		return Proposal{}, err
	}
	if dirty != "" {
		return Proposal{}, ErrDirty
	}
	prev, err := r.git(ctx, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return Proposal{}, err
	}
	if _, err := r.git(ctx, "fetch", "--quiet", "origin", "main"); err != nil {
		return Proposal{}, err
	}
	branch := branchPrefix + "-" + time.Now().UTC().Format("20060102-1504")
	if _, err := r.git(ctx, "checkout", "-q", "-B", branch, "origin/main"); err != nil {
		return Proposal{}, err
	}
	back := func() { _, _ = r.git(ctx, "checkout", "-q", prev) }

	path := filepath.Join(r.Dir, "dnsconfig.js")
	info, err := os.Stat(path)
	if err != nil {
		back()
		return Proposal{}, err
	}
	src, err := os.ReadFile(path) // #nosec G304 -- dnsconfig.js in the configured repository
	if err != nil {
		back()
		return Proposal{}, err
	}
	out, err := edit(string(src))
	if err != nil {
		back()
		return Proposal{}, err
	}
	if out == string(src) {
		back()
		return Proposal{}, ErrUnchanged
	}
	if err := os.WriteFile(path, []byte(out), info.Mode().Perm()); err != nil { // #nosec G703 -- fixed file name in the configured repository
		back()
		return Proposal{}, err
	}
	if _, err := r.git(ctx, "add", "dnsconfig.js"); err != nil {
		back()
		return Proposal{}, err
	}
	if _, err := r.git(ctx, "commit", "-q", "-m", title, "-m", body); err != nil {
		back()
		return Proposal{}, err
	}
	if _, err := r.git(ctx, "push", "-q", "-u", "origin", branch); err != nil {
		return Proposal{}, err
	}
	url, err := r.run(ctx, "gh", "pr", "create", "--base", "main", "--head", branch, "--title", title, "--body", body)
	if err != nil {
		return Proposal{}, err
	}
	back()
	return Proposal{Branch: branch, URL: url}, nil
}

// PRState returns the state of a pull request: OPEN, MERGED or CLOSED.
func (r Repo) PRState(ctx context.Context, pr string) (string, error) {
	return r.run(ctx, "gh", "pr", "view", pr, "--json", "state", "--jq", ".state")
}

func (r Repo) git(ctx context.Context, args ...string) (string, error) {
	return r.run(ctx, "git", args...)
}

func (r Repo) run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- fixed tools, arguments built by mailadmin
	cmd.Dir = r.Dir
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// SaveState writes the pending change for a domain.
func SaveState(path string, s State) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// LoadState reads the pending change. ok is false when there is none.
func LoadState(path string) (State, bool, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- state file in the fixed state directory
	if errors.Is(err, os.ErrNotExist) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, false, fmt.Errorf("pending change %s: %w", path, err)
	}
	return s, true, nil
}

// ClearState removes the pending change file.
func ClearState(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
