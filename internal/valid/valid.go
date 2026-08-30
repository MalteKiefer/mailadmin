// Package valid centralises validation/normalisation of every external token
// that reaches an exec argv, a DNS query, or a SQL parameter. Injection defence
// per REQUIREMENTS: local-part, domain, address, queue-id, IP, port, systemd
// unit and DKIM selector are all validated here so no ad-hoc regexps drift.
package valid

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// ErrInvalid is the sentinel wrapped by every validator.
	ErrInvalid = errors.New("invalid input")

	reDomain   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	reLocal    = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,63}$`)
	reQueueID  = regexp.MustCompile(`^[A-F0-9]{6,16}$`)
	reSelector = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	reUnit     = regexp.MustCompile(`^[a-zA-Z0-9@._-]{1,128}$`)
	reDuration = regexp.MustCompile(`^[0-9]{1,8}(s|m|h|d)$`)
)

func fail(what, v string) error { return fmt.Errorf("%w: %s %q", ErrInvalid, what, v) }

// Domain lower-cases and validates a DNS domain name.
func Domain(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
	if !reDomain.MatchString(s) {
		return "", fail("domain", s)
	}
	return s, nil
}

// Address validates a mailbox address and returns (local, domain).
func Address(s string) (local, domain string, err error) {
	s = strings.ToLower(strings.TrimSpace(s))
	parts := strings.Split(s, "@")
	if len(parts) != 2 || !reLocal.MatchString(parts[0]) {
		return "", "", fail("address", s)
	}
	d, err := Domain(parts[1])
	if err != nil {
		return "", "", fail("address", s)
	}
	return parts[0], d, nil
}

// AliasSource validates an alias source: a full address or "@domain" catch-all.
func AliasSource(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(s, "@") {
		d, err := Domain(s[1:])
		if err != nil {
			return "", fail("alias source", s)
		}
		return "@" + d, nil
	}
	if _, _, err := Address(s); err != nil {
		return "", fail("alias source", s)
	}
	return s, nil
}

// QueueID validates a Postfix queue id.
func QueueID(s string) (string, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !reQueueID.MatchString(s) {
		return "", fail("queue id", s)
	}
	return s, nil
}

// Selector validates a DKIM selector.
func Selector(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !reSelector.MatchString(s) {
		return "", fail("selector", s)
	}
	return s, nil
}

// Unit validates a systemd unit name (allowlist enforcement is the caller's job).
func Unit(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !reUnit.MatchString(s) {
		return "", fail("unit", s)
	}
	return s, nil
}

// CIDR validates a bare IP or CIDR (for ban/allowlist entries).
func CIDR(s string) (string, error) {
	s = strings.TrimSpace(s)
	if net.ParseIP(s) != nil {
		return s, nil
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return s, nil
	}
	return "", fail("ip/cidr", s)
}

// Port validates a TCP/UDP port (1-65535).
func Port(n int) (int, error) {
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("%w: port %d", ErrInvalid, n)
	}
	return n, nil
}

// Proto validates a firewall protocol ("tcp"|"udp").
func Proto(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s != "tcp" && s != "udp" {
		return "", fail("proto", s)
	}
	return s, nil
}

// Duration validates a ban duration like "4h" or "30m".
func Duration(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !reDuration.MatchString(s) {
		return "", fail("duration", s)
	}
	return s, nil
}

// PathUnder confines raw to root, defending in depth against path traversal
// and symlink escapes for a path that will reach a privileged command (this
// process runs as root). raw may be an absolute path (which must itself fall
// under root) or a path relative to root.
//
// The path is resolved with filepath.EvalSymlinks, so it must already exist
// on disk — this validator is for reading an existing file (e.g. a message
// under the vmail spool), not for computing a not-yet-created path. A dangling
// symlink, a missing file, or a resolved target outside root are all rejected.
//
// This mirrors, and generalises, the realpath-confinement fix recommended in
// docs/SECURITY-AUDIT.md L-3 for the deleted mailadmin-rspamd-learn helper,
// whose path regex (`^/var/vmail/...glob.../.*$`) permitted `..` traversal.
func PathUnder(root, raw string) (string, error) {
	root = filepath.Clean(root)
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsRune(raw, 0) {
		return "", fail("path", raw)
	}
	clean := filepath.Clean(raw)
	if !filepath.IsAbs(clean) {
		clean = filepath.Join(root, clean)
	}

	// Resolve both the candidate and root itself through EvalSymlinks before
	// comparing: root may itself be reached via a symlink (or, as on Windows,
	// through a different short/long path alias), so comparing un-resolved
	// forms would either false-reject a legitimate path or — worse — let a
	// symlinked root make the prefix check meaningless. The resolved-vs-
	// resolved comparison below is the actual security boundary.
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", fmt.Errorf("%w: path %q: %w", ErrInvalid, raw, err)
	}
	resolved = filepath.Clean(resolved)
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("%w: root %q: %w", ErrInvalid, root, err)
	}
	resolvedRoot = filepath.Clean(resolvedRoot)

	if !pathWithin(resolvedRoot, resolved) {
		return "", fail("path", raw)
	}
	return resolved, nil
}

// pathWithin reports whether p is root itself or strictly inside it.
func pathWithin(root, p string) bool {
	if p == root {
		return true
	}
	prefix := root + string(os.PathSeparator)
	return strings.HasPrefix(p, prefix)
}
