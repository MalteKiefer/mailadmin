package rspamdconf

import (
	"fmt"
	"os"
	"path/filepath"
)

// GreylistFile is the config file the rspamd greylist module reads from
// local.d.
const GreylistFile = "greylist.conf"

// GreylistSettings are the two most commonly tuned greylist module values:
// timeout (how long a first-seen triplet is soft-rejected for) and expire
// (how long a triplet stays valid once it has passed greylisting). Both are
// written as bare (unquoted) UCL duration literals, matching rspamd's own
// example configs (e.g. `timeout = 300s;`).
var GreylistSettings = []string{"timeout", "expire"}

// IsGreylistSetting reports whether name is a recognised greylist setting.
func IsGreylistSetting(name string) bool {
	for _, s := range GreylistSettings {
		if s == name {
			return true
		}
	}
	return false
}

// GreylistPath returns the full path to greylist.conf under dir
// (DefaultConfDir if dir is empty).
func GreylistPath(dir string) string {
	if dir == "" {
		dir = DefaultConfDir
	}
	return filepath.Join(dir, GreylistFile)
}

// ReadGreylist loads dir/greylist.conf and returns the configured value for
// every GreylistSettings entry that has an explicit line in the file.
// Settings absent from the file are omitted (rspamd's built-in default
// applies); the caller decides how to present that.
func ReadGreylist(dir string) (map[string]string, error) {
	content, err := os.ReadFile(GreylistPath(dir)) //nolint:gosec // fixed, well-known rspamd config path
	if err != nil {
		return nil, fmt.Errorf("rspamdconf: read %s: %w", GreylistPath(dir), err)
	}
	doc := Parse(content)
	out := make(map[string]string, len(GreylistSettings))
	for _, s := range GreylistSettings {
		if v, ok := doc.Get(s); ok {
			out[s] = unquote(v)
		}
	}
	return out, nil
}

// SetGreylist reads dir/greylist.conf, sets setting's value, and writes the
// file back, preserving every other line untouched. It returns the previous
// raw file content (for rollback) and the previous value (empty if the
// setting had no explicit entry before).
func SetGreylist(dir, setting, duration string) (oldContent []byte, oldValue string, err error) {
	if !IsGreylistSetting(setting) {
		return nil, "", fmt.Errorf("%w: %q", ErrUnknownSetting, setting)
	}

	path := GreylistPath(dir)
	content, err := os.ReadFile(path) //nolint:gosec // fixed, well-known rspamd config path
	if err != nil {
		return nil, "", fmt.Errorf("rspamdconf: read %s: %w", path, err)
	}

	doc := Parse(content)
	old, err := doc.Set(setting, duration)
	if err != nil {
		return nil, "", err
	}

	if err := os.WriteFile(path, doc.Bytes(), 0o644); err != nil { //nolint:gosec // matches rspamd config perms; not secret material
		return content, "", fmt.Errorf("rspamdconf: write %s: %w", path, err)
	}
	return content, unquote(old), nil
}

// RestoreFile writes content back to dir's ratelimit.conf/greylist.conf verbatim,
// for rollback after a failed post-write validation. path must be one of
// RatelimitPath(dir) or GreylistPath(dir).
func RestoreFile(path string, content []byte) error {
	if err := os.WriteFile(path, content, 0o644); err != nil { //nolint:gosec // matches rspamd config perms; not secret material
		return fmt.Errorf("rspamdconf: restore %s: %w", path, err)
	}
	return nil
}
