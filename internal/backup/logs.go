package backup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// LogsDir is the directory inside a bundle that holds the log copies.
const LogsDir = "logs"

// LogArchiveDir is where a restored log set is placed, one subdirectory per
// bundle. Owner-only: logs carry client addresses and mail metadata.
const LogArchiveDir = "/var/lib/mailadmin/log-archive"

// LogFiles are the on-disk logs that show who changed what and who tried to get
// in. Missing files are skipped. The copies keep their own rotation history.
var LogFiles = []string{
	"/var/log/audit/audit.log",
	"/var/log/auth.log",
	"/var/log/mail.log",
	"/var/log/crowdsec.log",
	"/var/log/unattended-upgrades/unattended-upgrades.log",
}

// JournalUnits are the services whose journal is exported with each bundle.
var JournalUnits = []string{
	"postfix", "dovecot", "rspamd", "caddy", "mailadmin-webmail",
	"crowdsec", "ssh", "mailadmin-borg", "mailadmin-cert-sync",
}

// JournalSince bounds the exported journal.
const JournalSince = "-7d"

// CollectLogs copies the existing LogFiles into bundleDir/logs and returns the
// base names it copied.
func CollectLogs(bundleDir string, files []string) ([]string, error) {
	dst := filepath.Join(bundleDir, LogsDir)
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return nil, fmt.Errorf("logs dir: %w", err)
	}
	var copied []string
	for _, src := range files {
		if _, err := os.Stat(src); err != nil {
			continue // not every host has every log
		}
		name := filepath.Base(src)
		copyPath := filepath.Join(dst, name)
		if _, err := CopyFile(src, copyPath); err != nil {
			return copied, fmt.Errorf("copy %s: %w", src, err)
		}
		// Logs carry client IPs and sender addresses: owner-only, whatever the source mode.
		if err := os.Chmod(copyPath, 0o600); err != nil {
			return copied, fmt.Errorf("chmod %s: %w", copyPath, err)
		}
		copied = append(copied, name)
	}
	return copied, nil
}

// JournalExport writes the journal of units since JournalSince to
// bundleDir/logs/journal.log. The arguments are fixed, nothing comes from input.
func JournalExport(ctx context.Context, bundleDir string, units []string) error {
	args := []string{"--no-pager", "-o", "short-iso", "--since", JournalSince}
	for _, u := range units {
		args = append(args, "-u", u)
	}
	out, err := exec.CommandContext(ctx, "journalctl", args...).Output() // #nosec G204 -- fixed binary and unit list
	if err != nil {
		return fmt.Errorf("journalctl: %w", err)
	}
	path := filepath.Join(bundleDir, LogsDir, "journal.log")
	return os.WriteFile(path, out, 0o600) // #nosec G306 -- bundle dir is owner-only
}
