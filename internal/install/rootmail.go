package install

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// Paths that send root's mail somewhere a person reads it.
const (
	AliasesPath       = "/etc/aliases"
	AidePath          = "/etc/default/aide"
	UnattendedMailCfg = "/etc/apt/apt.conf.d/52mailadmin-notify.conf"
)

// RootAliasConf returns the aliases file with exactly one "root:" line pointing
// at addr. Other lines stay as they are.
func RootAliasConf(existing, addr string) string {
	var out []string
	done := false
	for _, line := range strings.Split(strings.TrimRight(existing, "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "root:") {
			if !done {
				out = append(out, "root: "+addr)
				done = true
			}
			continue
		}
		if line != "" {
			out = append(out, line)
		}
	}
	if !done {
		out = append(out, "root: "+addr)
	}
	return strings.Join(out, "\n") + "\n"
}

// AideMailConf sets MAILTO in /etc/default/aide, replacing a commented or old
// value. The file keeps its other settings.
func AideMailConf(existing, addr string) string {
	var out []string
	done := false
	for _, line := range strings.Split(strings.TrimRight(existing, "\n"), "\n") {
		trimmed := strings.TrimLeft(line, "# \t")
		if strings.HasPrefix(trimmed, "MAILTO=") {
			if !done {
				out = append(out, "MAILTO="+addr)
				done = true
			}
			continue
		}
		out = append(out, line)
	}
	if !done {
		out = append(out, "MAILTO="+addr)
	}
	return strings.Join(out, "\n") + "\n"
}

// UnattendedMailConf routes unattended-upgrades reports to addr.
func UnattendedMailConf(addr string) string {
	return fmt.Sprintf("// Managed by mailadmin install.\nUnattended-Upgrade::Mail \"%s\";\nUnattended-Upgrade::MailReport \"on-change\";\n", addr)
}

// ApplyRootMail sends root's mail (cron, AIDE, unattended-upgrades) to addr and
// rebuilds the alias database. Each file is rewritten only when it changes.
func ApplyRootMail(ctx context.Context, x Exec, addr string) error {
	if addr == "" {
		return nil
	}
	aliases, err := os.ReadFile(AliasesPath) // #nosec G304 -- fixed system path
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", AliasesPath, err)
	}
	if want := RootAliasConf(string(aliases), addr); want != string(aliases) {
		if err := writeAtomic(AliasesPath, []byte(want), 0o644); err != nil {
			return err
		}
		if _, err := x.Run(ctx, nil, "newaliases"); err != nil {
			return fmt.Errorf("newaliases: %w", err)
		}
	}
	if aide, err := os.ReadFile(AidePath); err == nil { // #nosec G304 -- fixed system path
		if want := AideMailConf(string(aide), addr); want != string(aide) {
			if err := writeAtomic(AidePath, []byte(want), 0o644); err != nil {
				return err
			}
		}
	}
	return writeAtomic(UnattendedMailCfg, []byte(UnattendedMailConf(addr)), 0o644)
}
