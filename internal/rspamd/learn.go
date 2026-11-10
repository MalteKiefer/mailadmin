// Package rspamd wraps rspamc's Bayes feedback commands (learn_spam/
// learn_ham) through internal/sys. This replaces the deleted shell helper
// mailadmin-rspamd-learn (see docs/SECURITY-AUDIT.md L-3): a message source is
// either a Postfix queue id (fetched via postcat and streamed to rspamc on
// stdin) or a file path, which must resolve, after symlink resolution, to a
// location strictly inside the vmail root (internal/valid.PathUnder). No path
// reaches rspamc without that confinement check, since this runs as root.
package rspamd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mailadmin/internal/maildir"
	"mailadmin/internal/sys"
	"mailadmin/internal/valid"
)

// Binary paths (absolute; matches the rest of the codebase's exec chokepoint
// convention, no PATH lookup, no shell).
const (
	binRspamc  = "/usr/bin/rspamc"
	binPostcat = "/usr/sbin/postcat"
)

// Service runs rspamc learn_spam/learn_ham, confining file-path sources to a
// configured vmail root.
type Service struct {
	runner *sys.Runner
	root   string
}

// New builds a Service. An empty vmailRoot falls back to maildir.DefaultRoot
// (/var/vmail), the same root the rest of mailadmin confines mailbox paths to.
func New(runner *sys.Runner, vmailRoot string) *Service {
	if vmailRoot == "" {
		vmailRoot = maildir.DefaultRoot
	}
	return &Service{runner: runner, root: filepath.Clean(vmailRoot)}
}

// LearnSpam trains rspamd's Bayes classifier that source is spam. source is
// either a Postfix queue id or a file path under the vmail root. It returns
// the resolved identifier used (queue id, or the confined absolute path) so
// callers can use it as an audit target.
func (s *Service) LearnSpam(ctx context.Context, source string) (string, error) {
	return s.learn(ctx, "learn_spam", source)
}

// LearnHam trains rspamd's Bayes classifier that source is ham (not spam).
func (s *Service) LearnHam(ctx context.Context, source string) (string, error) {
	return s.learn(ctx, "learn_ham", source)
}

// Resolve validates source with no side effects, returning its kind
// ("queue-id"|"path") and the identifier the learn commands would use (the
// normalised queue id, or the confined absolute file path). CLI callers use
// this to validate before a --dry-run check or a confirmation prompt, so bad
// input is rejected before anything runs.
func (s *Service) Resolve(source string) (kind, identifier string, err error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return "", "", fmt.Errorf("%w: empty message source", valid.ErrInvalid)
	}
	if qid, err := valid.QueueID(source); err == nil {
		return "queue-id", qid, nil
	}
	path, err := s.resolvePath(source)
	if err != nil {
		return "", "", err
	}
	return "path", path, nil
}

// learn resolves source and feeds the message to `rspamc <action>`. action is
// a compile-time constant ("learn_spam"|"learn_ham"), never user input.
func (s *Service) learn(ctx context.Context, action, source string) (string, error) {
	kind, identifier, err := s.Resolve(source)
	if err != nil {
		return "", err
	}

	// A bare queue id is fetched via postcat and streamed to rspamc on stdin,
	// matching the previous script's queue-id form.
	if kind == "queue-id" {
		body, perr := s.postcat(ctx, identifier)
		if perr != nil {
			return identifier, perr
		}
		if err := s.rspamcStdin(ctx, action, body); err != nil {
			return identifier, err
		}
		return identifier, nil
	}

	if err := s.rspamcFile(ctx, action, identifier); err != nil {
		return identifier, err
	}
	return identifier, nil
}

// resolvePath confines source under the configured vmail root (rejecting
// traversal and symlink escapes) and checks it names a regular file.
func (s *Service) resolvePath(source string) (string, error) {
	resolved, err := valid.PathUnder(s.root, source)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("rspamd: stat %s: %w", resolved, err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%w: %s is not a regular file", valid.ErrInvalid, resolved)
	}
	return resolved, nil
}

// postcat runs `postcat -q <qid>` and returns the raw message bytes.
func (s *Service) postcat(ctx context.Context, qid string) ([]byte, error) {
	// -bh prints the message (headers and body) only; plain -q adds envelope
	// records and markers that rspamd would learn as message content.
	res, err := s.runner.Run(ctx, nil, binPostcat, "-bh", "-q", qid)
	if err != nil {
		return nil, fmt.Errorf("postcat -q %s: %w", qid, wrapDetail(err, res.Stderr))
	}
	if len(res.Stdout) == 0 {
		return nil, fmt.Errorf("postcat -q %s: empty output (queue id not found?)", qid)
	}
	return res.Stdout, nil
}

// rspamcFile runs `rspamc <action> <path>`, letting rspamc read the file
// itself (path is already confined by resolvePath).
func (s *Service) rspamcFile(ctx context.Context, action, path string) error {
	res, err := s.runner.Run(ctx, nil, binRspamc, action, path)
	if err != nil {
		return fmt.Errorf("rspamc %s: %w", action, wrapDetail(err, res.Stderr))
	}
	return nil
}

// rspamcStdin runs `rspamc <action>` feeding body on stdin (used for the
// queue-id form, where the message came from postcat rather than a file).
func (s *Service) rspamcStdin(ctx context.Context, action string, body []byte) error {
	res, err := s.runner.Run(ctx, body, binRspamc, action)
	if err != nil {
		return fmt.Errorf("rspamc %s: %w", action, wrapDetail(err, res.Stderr))
	}
	return nil
}

// wrapDetail folds captured stderr into a runner error when present, without
// altering the error's Is/As chain (the underlying sys error is still %w'd by
// the caller).
func wrapDetail(err error, stderr []byte) error {
	detail := strings.TrimSpace(string(stderr))
	if detail == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, detail)
}
