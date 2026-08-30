package rspamdconf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// DefaultConfDir is rspamd's local.d override directory. It is not currently
// exposed as a mailadmin config setting (internal/config/config.go is out of
// scope for this change), so it is hardcoded to the well-known Debian/rspamd
// default, matching the paths doctor.go and this package's callers already
// assume for rspamd.
const DefaultConfDir = "/etc/rspamd/local.d"

// RatelimitFile is the config file the rspamd ratelimit module reads from
// local.d.
const RatelimitFile = "ratelimit.conf"

// RatelimitBuckets are the rate-limit module's named buckets, as documented
// by rspamd's ratelimit module (the `rates { }` map). This is the full,
// fixed set the module supports; mailadmin does not allow tuning arbitrary
// keys under `rates`.
var RatelimitBuckets = []string{"to", "to_ip", "to_ip_from", "bounce_to", "bounce_to_ip"}

// ErrUnknownBucket is returned for a bucket name outside RatelimitBuckets.
var ErrUnknownBucket = errors.New("rspamdconf: unknown ratelimit bucket")

// ErrInvalidRate is returned when a rate string does not match "<number> /
// <number><unit>" (unit one of s, m, h, d, w).
var ErrInvalidRate = errors.New("rspamdconf: invalid rate")

// reRate matches a rate string such as "20 / 1m" or "20/1h". The unit
// alphabet (s/m/h/d/w) mirrors internal/valid.Duration's (s/m/h/d) plus "w"
// for the weekly-scale bounce buckets, kept in one letter per unit for
// consistency with the rest of the tool's duration handling. rspamd itself
// additionally accepts word units ("min", "hour", ...); this narrower
// grammar is what mailadmin writes and validates — an operator who wants a
// word-unit rate can still hand-edit the file, mailadmin will simply not
// offer to "set" it afterwards until it's changed back to a unit letter.
var reRate = regexp.MustCompile(`^\s*(\d+(?:\.\d+)?)\s*/\s*(\d{1,4})\s*([smhdw])\s*$`)

// IsBucket reports whether name is a recognised ratelimit bucket.
func IsBucket(name string) bool {
	for _, b := range RatelimitBuckets {
		if b == name {
			return true
		}
	}
	return false
}

// ValidateRate normalises and validates a rate string, returning the
// canonical "N / Mu" form (single space around the slash, no space between
// the count and unit) that Set writes to disk.
func ValidateRate(s string) (string, error) {
	m := reRate.FindStringSubmatch(s)
	if m == nil {
		return "", fmt.Errorf("%w: %q (want \"<count> / <n><unit>\", unit one of s,m,h,d,w)", ErrInvalidRate, s)
	}
	return m[1] + " / " + m[2] + m[3], nil
}

// RatelimitPath returns the full path to ratelimit.conf under dir (DefaultConfDir if dir is empty).
func RatelimitPath(dir string) string {
	if dir == "" {
		dir = DefaultConfDir
	}
	return filepath.Join(dir, RatelimitFile)
}

// ratelimitKeyPath returns the dotted key rspamdconf.Document uses for a
// bucket, matching how ratelimit.conf nests rates under a `rates { }` block.
func ratelimitKeyPath(bucket string) string { return "rates." + bucket }

// ReadRatelimit loads dir/ratelimit.conf and returns the configured rate for
// every known bucket that has an explicit entry in the file. Buckets absent
// from the file are omitted (rspamd's built-in default applies to them); the
// caller decides how to present that.
func ReadRatelimit(dir string) (map[string]string, error) {
	content, err := os.ReadFile(RatelimitPath(dir)) // #nosec G304 -- fixed, well-known rspamd config path
	if err != nil {
		return nil, fmt.Errorf("rspamdconf: read %s: %w", RatelimitPath(dir), err)
	}
	doc := Parse(content)
	out := make(map[string]string, len(RatelimitBuckets))
	for _, b := range RatelimitBuckets {
		if v, ok := doc.Get(ratelimitKeyPath(b)); ok {
			out[b] = unquote(v)
		}
	}
	return out, nil
}

// SetRatelimit reads dir/ratelimit.conf, sets bucket's rate, and writes the
// file back, preserving every other line untouched. It returns the previous
// value (empty if the bucket had no explicit entry before) and the raw old
// file content, so the caller can validate the write (e.g. via `rspamadm
// configtest`) and restore the old content on failure.
func SetRatelimit(dir, bucket, rate string) (oldContent []byte, oldValue string, err error) {
	if !IsBucket(bucket) {
		return nil, "", fmt.Errorf("%w: %q", ErrUnknownBucket, bucket)
	}
	normalized, err := ValidateRate(rate)
	if err != nil {
		return nil, "", err
	}

	path := RatelimitPath(dir)
	content, err := os.ReadFile(path) // #nosec G304 -- operator-configured rspamd config dir, not user-tainted
	if err != nil {
		return nil, "", fmt.Errorf("rspamdconf: read %s: %w", path, err)
	}

	doc := Parse(content)
	old, err := doc.Set(ratelimitKeyPath(bucket), `"`+normalized+`"`)
	if err != nil {
		return nil, "", err
	}

	if err := os.WriteFile(path, doc.Bytes(), 0o644); err != nil { // #nosec G304 G306 -- operator-configured rspamd config dir; 0644 matches rspamd's own file perms, not secret material
		return content, "", fmt.Errorf("rspamdconf: write %s: %w", path, err)
	}
	return content, unquote(old), nil
}

// unquote strips a single layer of double quotes from a UCL string value, if
// present. Bare (unquoted) values are returned unchanged.
func unquote(s string) string {
	if len(s) >= 2 && strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		return s[1 : len(s)-1]
	}
	return s
}
