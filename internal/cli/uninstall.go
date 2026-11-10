package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"mailadmin/internal/backup"
	"mailadmin/internal/config"
	"mailadmin/internal/install"
	"mailadmin/internal/sys"
)

// uninstallBackupRoot holds the backups of uninstall. It is outside mailadmin's
// own directories, so it survives the removal.
const uninstallBackupRoot = "/var/backups"

func newUninstallCmd(app *App) *cobra.Command {
	var noBackup bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove mailadmin and everything install added (full backup first)",
		Long: "Removes what `mailadmin install` installed: services, packages, repositories,\n" +
			"configuration, mail data, databases, users and firewall rules.\n\n" +
			"A full backup is written first to " + uninstallBackupRoot + "/mailadmin-uninstall-<time>/\n" +
			"(database, mail, DKIM keys, config with secrets, install record). If the backup\n" +
			"fails, nothing is removed. --no-backup skips it and removes everything at once.\n" +
			"The host name is asked for; --yes skips the prompt.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runUninstall(app, c, noBackup)
		},
	}
	cmd.Flags().BoolVar(&noBackup, "no-backup", false, "remove without a backup (mail and databases are lost)")
	return cmd
}

func runUninstall(app *App, c *cobra.Command, noBackup bool) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	m, err := install.LoadManifest()
	if err != nil {
		return err
	}
	cfg, _, cerr := app.Config()
	host := "this host"
	if cerr == nil && cfg.Mail.Hostname != "" {
		host = cfg.Mail.Hostname
	}
	r.Message("uninstall plan for %s:", host)
	for _, line := range install.Summary(m) {
		r.Message("  %s", line)
	}
	if app.flags.dryRun {
		r.Message("dry-run: nothing changed")
		return nil
	}
	if err := confirmHostName(app, host); err != nil {
		return err
	}

	dir := ""
	if noBackup {
		r.Message("--no-backup: mail, databases and keys are deleted without a copy")
		if err := confirmHostName(app, host); err != nil {
			return err
		}
	} else {
		if cerr != nil {
			return fmt.Errorf("uninstall: the backup needs the config file (%w); nothing was removed", cerr)
		}
		dir = filepath.Join(uninstallBackupRoot, "mailadmin-uninstall-"+time.Now().UTC().Format("20060102-150405"))
		r.Message("writing the full backup to %s", dir)
		if err := uninstallBackup(c, app, cfg, dir); err != nil {
			return fmt.Errorf("backup failed, nothing was removed: %w", err)
		}
		r.Message("backup verified: %s", dir)
	}

	x := install.Resolve(app.sysRunner())
	errs := install.Uninstall(ctx(c), x, m, func(msg string) { r.Message("  %s", msg) })
	if err := os.Remove(installBinaryPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Errorf("remove %s: %w", installBinaryPath, err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("uninstall finished with %d failed step(s) (listed above); fix them by hand", len(errs))
	}
	r.Message("mailadmin is removed")
	if dir != "" {
		r.Message("backup kept at %s", dir)
	}
	return nil
}

// confirmHostName asks the operator to type the host name. --yes skips it.
func confirmHostName(app *App, host string) error {
	if app.flags.yes {
		return nil
	}
	line, err := app.readLine(fmt.Sprintf("type the host name %s to confirm: ", host))
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != host {
		return fmt.Errorf("%w: the host name does not match, nothing was changed", ErrDeclined)
	}
	return nil
}

// uninstallBackup writes the full backup of this host into dir and verifies it.
func uninstallBackup(c *cobra.Command, app *App, cfg *config.Config, dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if _, err := app.db(ctx(c)); err != nil { // sets PGSERVICEFILE for pg_dump
		return fmt.Errorf("database: %w", err)
	}
	long := sys.New(dbToolTimeout, nil)
	dump := filepath.Join(dir, backup.DBDumpFile)
	if _, err := long.Run(ctx(c), nil, backup.PgDumpArgs(cfg.Postgres.Service, dump)...); err != nil {
		return fmt.Errorf("pg_dump: %w", err)
	}
	if _, err := backup.CopyTree(cfg.Mail.DKIMDir, filepath.Join(dir, "dkim")); err != nil {
		return fmt.Errorf("dkim keys: %w", err)
	}
	if _, err := backup.CopyTree(config.ConfigDir, filepath.Join(dir, "etc-mailadmin")); err != nil {
		return fmt.Errorf("config (with secrets): %w", err)
	}
	if _, err := backup.CopyTree(install.StateDir, filepath.Join(dir, "var-lib-mailadmin")); err != nil {
		return fmt.Errorf("install record: %w", err)
	}
	if _, err := os.Stat("/var/vmail"); err == nil {
		tarball := filepath.Join(dir, "vmail.tar.gz")
		if _, err := long.Run(ctx(c), nil, "/usr/bin/tar", "--numeric-owner", "-czf", tarball, "-C", "/var/vmail", "."); err != nil {
			return fmt.Errorf("mail directories: %w", err)
		}
		if _, err := long.Run(ctx(c), nil, "/usr/bin/tar", "-tzf", tarball); err != nil {
			return fmt.Errorf("verify mail archive: %w", err)
		}
	}
	if fi, err := os.Stat(dump); err != nil || fi.Size() == 0 {
		return fmt.Errorf("verify database dump: empty or missing")
	}
	return writeChecksums(dir)
}

// writeChecksums records a SHA-256 for every file of the backup, so a later copy
// of it can be checked.
func writeChecksums(dir string) error {
	var lines []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		f, err := os.Open(p) // #nosec G304 -- files of the backup just written
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		lines = append(lines, hex.EncodeToString(h.Sum(nil))+"  "+rel)
		return nil
	})
	if err != nil {
		return fmt.Errorf("checksums: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}
