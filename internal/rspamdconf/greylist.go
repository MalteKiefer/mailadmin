package rspamdconf

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
	content, err := readLocal(GreylistPath(dir)) // #nosec G304 -- fixed, well-known rspamd config path
	if err != nil {
		return nil, fmt.Errorf("rspamdconf: read %s: %w", GreylistPath(dir), err)
	}
	doc := Parse(content)
	out := make(map[string]string, len(GreylistSettings))
	for _, s := range GreylistSettings {
		if v, ok := doc.Get(s); ok {
			out[s] = showDuration(unquote(v))
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
	content, err := readLocal(path) // #nosec G304 -- operator-configured rspamd config dir, not user-tainted
	if err != nil {
		return nil, "", fmt.Errorf("rspamdconf: read %s: %w", path, err)
	}

	doc := Parse(content)
	old, err := doc.Set(setting, uclDuration(duration))
	if err != nil {
		return nil, "", err
	}

	if err := writeConf(path, doc.Bytes()); err != nil {
		return content, "", fmt.Errorf("rspamdconf: write %s: %w", path, err)
	}
	return content, unquote(old), nil
}

// writeConf replaces a local.d file through a synced temp file and a rename, so
// a crash never leaves rspamd a half-written config. 0644 matches rspamd's own
// file modes; these files hold no secrets.
func writeConf(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(data); err == nil {
		err = tmp.Chmod(0o644)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

// readLocal reads a local.d override. rspamd ships only *.example files and
// install writes neither greylist.conf nor ratelimit.conf, so a missing file is
// an empty one: set creates it, show reports rspamd's defaults.
func readLocal(path string) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- rspamd local.d path
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

// uclDuration spells a validated duration (5m, 2h) the way libucl reads it. A
// bare "m" is libucl's mega multiplier (5m = 5,000,000 seconds); minutes are
// "min". s, h and d are time units in libucl already.
func uclDuration(d string) string {
	if n, ok := strings.CutSuffix(d, "m"); ok {
		return n + "min"
	}
	return d
}

// showDuration presents a stored greylist value: "5min" (what set writes) as
// "5m", and a bare "5m" written before v1.27.0, which libucl reads as
// 5,000,000 seconds, with that meaning spelled out.
func showDuration(v string) string {
	if n, ok := strings.CutSuffix(v, "min"); ok && n != "" {
		return n + "m"
	}
	if n, ok := strings.CutSuffix(v, "m"); ok && n != "" && strings.Trim(n, "0123456789") == "" {
		return v + " (read by rspamd as " + n + "000000 seconds; set it again)"
	}
	return v
}

// RestoreFile writes content back to dir's ratelimit.conf/greylist.conf verbatim,
// for rollback after a failed post-write validation. path must be one of
// RatelimitPath(dir) or GreylistPath(dir).
func RestoreFile(path string, content []byte) error {
	if err := writeConf(path, content); err != nil {
		return fmt.Errorf("rspamdconf: restore %s: %w", path, err)
	}
	return nil
}
