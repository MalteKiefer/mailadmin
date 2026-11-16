package install

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AppArmorSourceDir holds the upstream profiles shipped by apparmor-profiles.
const AppArmorSourceDir = "/usr/share/apparmor/extra-profiles"

// AppArmorProfileDir is where the profiles are loaded from.
const AppArmorProfileDir = "/etc/apparmor.d"

//go:embed apparmor
var appArmorFS embed.FS

// upstreamMailProfiles selects the Postfix and Dovecot profiles from the Debian
// package, with the rules that exception file adds to them.
var upstreamMailProfiles = []struct {
	glob       string
	exceptions string
}{
	{"postfix-*", "apparmor/exceptions/postfix.rules"},
	{"usr.lib.dovecot.*", "apparmor/exceptions/dovecot.rules"},
}

// ownMailProfiles are written by mailadmin, because upstream has no profile for
// these binaries.
var ownMailProfiles = []string{"usr.bin.rspamd", "usr.bin.caddy", "usr.bin.valkey-server"}

// ApplyMailAppArmor installs the mail-stack AppArmor profiles and loads them in
// complain mode. Complain mode logs what enforce would deny without blocking.
// Enforce is a separate step, after the complain events have been reviewed.
func ApplyMailAppArmor(ctx context.Context, x Exec) error {
	for _, up := range upstreamMailProfiles {
		matches, err := filepath.Glob(filepath.Join(AppArmorSourceDir, up.glob))
		if err != nil {
			return fmt.Errorf("apparmor glob %s: %w", up.glob, err)
		}
		rules, err := appArmorFS.ReadFile(up.exceptions)
		if err != nil {
			return fmt.Errorf("read %s: %w", up.exceptions, err)
		}
		for _, src := range matches {
			data, err := os.ReadFile(src) // #nosec G304 -- fixed package directory
			if err != nil {
				return fmt.Errorf("read %s: %w", src, err)
			}
			merged, err := insertProfileRules(data, rules)
			if err != nil {
				return fmt.Errorf("%s: %w", src, err)
			}
			if err := loadAppArmorProfile(ctx, x, filepath.Base(src), merged); err != nil {
				return err
			}
		}
	}
	for _, name := range ownMailProfiles {
		data, err := appArmorFS.ReadFile("apparmor/" + name)
		if err != nil {
			return fmt.Errorf("read embedded %s: %w", name, err)
		}
		if err := loadAppArmorProfile(ctx, x, name, data); err != nil {
			return err
		}
	}
	return nil
}

// loadAppArmorProfile writes one profile to /etc/apparmor.d and loads it in complain mode.
func loadAppArmorProfile(ctx context.Context, x Exec, name string, data []byte) error {
	dst := filepath.Join(AppArmorProfileDir, name)
	if err := writeAtomic(dst, data, 0o644); err != nil {
		return err
	}
	if _, err := x.Run(ctx, nil, "apparmor_parser", "-r", "-C", dst); err != nil {
		return fmt.Errorf("load %s in complain mode: %w", dst, err)
	}
	return nil
}

// insertProfileRules adds rules right after the opening brace of the first
// profile in data. The rules are indented by the caller.
func insertProfileRules(data, rules []byte) ([]byte, error) {
	lines := bytes.SplitAfter(data, []byte("\n"))
	for i, line := range lines {
		t := strings.TrimSpace(string(line))
		if strings.HasPrefix(t, "#") || !strings.HasSuffix(t, "{") {
			continue
		}
		var out bytes.Buffer
		for _, l := range lines[:i+1] {
			out.Write(l)
		}
		out.Write(rules)
		if len(rules) > 0 && rules[len(rules)-1] != '\n' {
			out.WriteByte('\n')
		}
		for _, l := range lines[i+1:] {
			out.Write(l)
		}
		return out.Bytes(), nil
	}
	return nil, fmt.Errorf("no profile opening brace found")
}
