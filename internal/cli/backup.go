package cli

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"mailadmin/internal/backup"
	"mailadmin/internal/config"
	"mailadmin/internal/output"
	"mailadmin/internal/sieve"
)

func newBackupCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "backup", Short: "Create, restore, and list disaster-recovery backup bundles"}

	var createOut string
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a self-contained backup bundle (Postgres DB, DKIM keys, Sieve scripts, config.toml)",
		Long: "Writes one timestamped bundle directory containing a pg_dump of the\n" +
			"mailadmin database, a copy of the DKIM key directory, every mailbox's\n" +
			"active Sieve script, and mailadmin's own config.toml.\n\n" +
			"secrets.env is NEVER included — back it up separately.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error { return app.backupCreate(c, createOut) },
	}
	create.Flags().StringVar(&createOut, "out", "", "backup directory (default: [backup] dir in config.toml)")

	var restoreComponent string
	restore := &cobra.Command{
		Use:   "restore <bundle-path>",
		Short: "Restore one or all components from a backup bundle",
		Long: "Restores a bundle produced by `backup create`. This is destructive: it\n" +
			"overwrites live Postgres rows, DKIM key files, and/or Sieve scripts.\n" +
			"Confirms interactively unless --yes; --dry-run prints what would change\n" +
			"without touching anything.",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error { return app.backupRestore(c, args[0], restoreComponent) },
	}
	restore.Flags().StringVar(&restoreComponent, "component", "",
		"restore only this component: "+strings.Join(backup.AllComponents, "|")+" (default: every component in the bundle)")

	var listDir string
	list := &cobra.Command{
		Use:   "list",
		Short: "List available backup bundles",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, args []string) error { return app.backupList(c, listDir) },
	}
	list.Flags().StringVar(&listDir, "dir", "", "backup directory (default: [backup] dir in config.toml)")

	cmd.AddCommand(create, restore, list)
	return cmd
}

// backupDir resolves the directory `backup create`/`backup list` operate on:
// an explicit --out/--dir flag wins, else the configured [backup] dir. Unlike
// backup.dns_backup_dir (required, DNS takeover always needs somewhere to
// snapshot to), a full DR bundle directory is optional in config so a fresh
// deploy does not need it set until the operator actually wants backups.
func backupDir(cfg *config.Config, flagVal string) (string, error) {
	if flagVal != "" {
		if !filepath.IsAbs(flagVal) {
			return "", fmt.Errorf("%w: backup directory must be an absolute path", ErrUsage)
		}
		return flagVal, nil
	}
	if cfg.Backup.Dir != "" {
		return cfg.Backup.Dir, nil
	}
	return "", fmt.Errorf("%w: no backup directory configured; set [backup] dir in config.toml or pass --out/--dir", ErrUsage)
}

// backupCreate builds one self-contained bundle: pg_dump, a copy of the DKIM
// key directory, every mailbox's active Sieve script, and config.toml.
func (a *App) backupCreate(cmd *cobra.Command, outFlag string) error {
	cfg, _, err := a.Config()
	if err != nil {
		return err
	}
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	dir, err := backupDir(cfg, outFlag)
	if err != nil {
		return err
	}

	database, err := a.db(ctx(cmd))
	if err != nil {
		return err
	}
	domains, err := database.ListDomains(ctx(cmd))
	if err != nil {
		return fmt.Errorf("backup create: list domains: %w", err)
	}
	names := make([]string, 0, len(domains))
	for _, d := range domains {
		names = append(names, d.Name)
	}
	sort.Strings(names)

	mailboxes, err := database.ListMailboxes(ctx(cmd), "")
	if err != nil {
		return fmt.Errorf("backup create: list mailboxes: %w", err)
	}

	if a.flags.dryRun {
		dkimBytes, _ := backup.DirSize(cfg.Mail.DKIMDir)
		r.Message("dry-run: would create a backup bundle under %s", dir)
		r.Message("  domain-db: pg_dump --format=custom via postgres.service %q", cfg.Postgres.Service)
		r.Message("  dkim: copy %s (%s on disk today)", cfg.Mail.DKIMDir, backup.FormatBytes(dkimBytes))
		r.Message("  sieve: active script for up to %d mailbox(es), fetched via doveadm", len(mailboxes))
		r.Message("  config: %s (secrets.env is NEVER included in a backup)", cfg.Path)
		r.Message("  domains covered: %s", strings.Join(names, ", "))
		return nil
	}

	name := backup.BundleName(time.Now())
	bundleDir := filepath.Join(dir, name)
	if err := os.MkdirAll(bundleDir, 0o700); err != nil {
		return fmt.Errorf("backup create: %w", err)
	}

	var components []string

	// 1. Postgres dump (custom format: supports --list previews and a clean
	// --clean --if-exists restore; see internal/backup.PgDumpArgs).
	dumpPath := filepath.Join(bundleDir, backup.DBDumpFile)
	if _, err := a.runner().Run(ctx(cmd), nil, backup.PgDumpArgs(cfg.Postgres.Service, dumpPath)...); err != nil {
		return fmt.Errorf("backup create: pg_dump: %w", err)
	}
	components = append(components, backup.ComponentDB)

	// 2. DKIM key directory, copied verbatim.
	dkimCopy, err := backup.CopyTree(cfg.Mail.DKIMDir, filepath.Join(bundleDir, backup.DKIMDir))
	if err != nil {
		return fmt.Errorf("backup create: dkim: %w", err)
	}
	if _, serr := os.Stat(cfg.Mail.DKIMDir); serr == nil {
		components = append(components, backup.ComponentDKIM)
	}

	// 3. Every mailbox's active Sieve script (addressed the same way
	// `sieve show`/`sieve set` address one: local@domain via doveadm -u).
	svc := sieve.New(a.runner())
	sieveDir := filepath.Join(bundleDir, backup.SieveDir)
	var sieveAddrs []string
	for _, mbox := range mailboxes {
		addr := mbox.Address()
		script, serr := svc.Show(ctx(cmd), addr)
		if serr != nil {
			if errors.Is(serr, sieve.ErrNotFound) {
				continue
			}
			return fmt.Errorf("backup create: sieve %s: %w", addr, serr)
		}
		if err := os.MkdirAll(sieveDir, 0o700); err != nil {
			return fmt.Errorf("backup create: sieve: %w", err)
		}
		fp := filepath.Join(sieveDir, backup.SieveFileName(addr))
		if err := os.WriteFile(fp, []byte(script.Body), 0o600); err != nil {
			return fmt.Errorf("backup create: write sieve %s: %w", addr, err)
		}
		sieveAddrs = append(sieveAddrs, addr)
	}
	components = append(components, backup.ComponentSieve)

	// 4. mailadmin's own config.toml — never secrets.env.
	if _, err := backup.CopyFile(cfg.Path, filepath.Join(bundleDir, backup.ConfigFile)); err != nil {
		return fmt.Errorf("backup create: config: %w", err)
	}
	components = append(components, backup.ComponentConfig)

	man := backup.NewManifest(Version, components)
	man.DBService = cfg.Postgres.Service
	man.DBFormat = "custom"
	man.Domains = names
	man.Mailboxes = len(mailboxes)
	man.DKIMKeyFiles = dkimCopy.Files
	man.SieveScripts = sieveAddrs
	if err := backup.WriteManifest(bundleDir, man); err != nil {
		return fmt.Errorf("backup create: %w", err)
	}

	rec, err := a.auditor(ctx(cmd))
	if err != nil {
		return err
	}
	if err := rec.Record(ctx(cmd), "backup.create", bundleDir, nil, map[string]any{
		"domains":       len(names),
		"mailboxes":     len(mailboxes),
		"dkim_files":    dkimCopy.Files,
		"sieve_scripts": len(sieveAddrs),
	}); err != nil {
		return err
	}

	r.Message("backup created at %s", bundleDir)
	r.Message("NOTE: secrets.env was NOT included in this bundle — back it up separately")
	return r.Value(man)
}

// backupRestore restores one or every component of a bundle. It is
// destructive (overwrites live DB rows / DKIM keys / Sieve scripts / config),
// so it confirms unless --yes and fully honours --dry-run.
func (a *App) backupRestore(cmd *cobra.Command, bundlePath, component string) error {
	if component != "" && !backup.ValidComponent(component) {
		return fmt.Errorf("%w: %s (must be one of %s)", backup.ErrUnknownComponent, component, strings.Join(backup.AllComponents, ", "))
	}
	man, err := backup.ReadManifest(bundlePath)
	if err != nil {
		return fmt.Errorf("backup restore: %w", err)
	}
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	cfg, _, err := a.Config()
	if err != nil {
		return err
	}

	components := man.Components
	if component != "" {
		if !man.HasComponent(component) {
			return fmt.Errorf("%w: bundle %s does not include component %q", ErrUsage, bundlePath, component)
		}
		components = []string{component}
	}

	// A bundle from a host without a DKIM directory lists dkim but has no dkim/.
	// Skip that component so the other components still restore.
	var kept []string
	for _, comp := range components {
		if comp == backup.ComponentDKIM {
			if _, serr := os.Stat(filepath.Join(bundlePath, backup.DKIMDir)); serr != nil {
				r.Message("warning: bundle %s has no %s directory, skipping dkim", bundlePath, backup.DKIMDir)
				continue
			}
		}
		kept = append(kept, comp)
	}
	components = kept
	r.Message("bundle %s — taken %s, mailadmin %s", bundlePath, man.CreatedAt.Format(time.RFC3339), man.MailadminVersion)
	if len(man.Domains) > 0 {
		r.Message("  domains: %s", strings.Join(man.Domains, ", "))
	}
	r.Message("  mailboxes: %d, dkim key files: %d, sieve scripts: %d", man.Mailboxes, man.DKIMKeyFiles, len(man.SieveScripts))

	if a.flags.dryRun {
		return a.backupRestoreDryRun(cmd, cfg, bundlePath, man, components, r)
	}

	warn := fmt.Sprintf("RESTORE overwrites live data for component(s): %s. This cannot be undone automatically.", strings.Join(components, ", "))
	if err := a.confirm(warn + " Continue?"); err != nil {
		return err
	}

	rec, err := a.auditor(ctx(cmd))
	if err != nil {
		return err
	}

	for _, comp := range components {
		switch comp {
		case backup.ComponentDB:
			if err := a.restoreDomainDB(cmd, cfg, bundlePath); err != nil {
				return err
			}
		case backup.ComponentDKIM:
			if err := a.restoreDKIM(cmd, cfg, bundlePath); err != nil {
				return err
			}
		case backup.ComponentSieve:
			if err := a.restoreSieve(cmd, bundlePath, man); err != nil {
				return err
			}
		case backup.ComponentConfig:
			if err := a.restoreConfig(cmd, cfg, bundlePath); err != nil {
				return err
			}
		}
	}

	if err := rec.Record(ctx(cmd), "backup.restore", bundlePath, nil, map[string]any{"components": components}); err != nil {
		return err
	}
	r.Message("restore complete: %s", strings.Join(components, ", "))
	if contains(components, backup.ComponentConfig) {
		r.Message("config.toml was replaced — review it before restarting any mailadmin-managed service")
	}
	return nil
}

// backupRestoreDryRun prints exactly what a restore would change, per
// component, without mutating anything. For domain-db it shells out to
// `pg_restore --list`, which is read-only against the dump file and never
// connects to a database.
func (a *App) backupRestoreDryRun(cmd *cobra.Command, cfg *config.Config, bundlePath string, man backup.Manifest, components []string, r *output.Renderer) error {
	for _, comp := range components {
		switch comp {
		case backup.ComponentDB:
			dumpPath := filepath.Join(bundlePath, backup.DBDumpFile)
			toc, err := a.runner().Output(ctx(cmd), backup.PgRestoreListArgs(dumpPath)...)
			if err != nil {
				r.Message("dry-run: domain-db: could not read %s (%v) — pg_restore not available in this environment?", dumpPath, err)
				continue
			}
			r.Message("dry-run: domain-db: would run pg_restore --clean --if-exists into service %q; table of contents:", cfg.Postgres.Service)
			r.Message("%s", toc)
		case backup.ComponentDKIM:
			n, _ := backup.DirSize(filepath.Join(bundlePath, backup.DKIMDir))
			r.Message("dry-run: dkim: would overwrite %s with %d key file(s) (%s) from the bundle",
				cfg.Mail.DKIMDir, man.DKIMKeyFiles, backup.FormatBytes(n))
		case backup.ComponentSieve:
			r.Message("dry-run: sieve: would overwrite the active script for %d mailbox(es): %s",
				len(man.SieveScripts), strings.Join(man.SieveScripts, ", "))
		case backup.ComponentConfig:
			r.Message("dry-run: config: would overwrite %s from the bundle's config.toml (review before restarting services)", cfg.Path)
		}
	}
	return nil
}

// restoreDomainDB replaces the live database with the bundle's pg_dump, via
// pg_restore --clean --if-exists (drops known objects first, then recreates
// them — a clean replacement rather than a merge with what is currently live).
func (a *App) restoreDomainDB(cmd *cobra.Command, cfg *config.Config, bundlePath string) error {
	dumpPath := filepath.Join(bundlePath, backup.DBDumpFile)
	if _, err := os.Stat(dumpPath); err != nil {
		return fmt.Errorf("backup restore: domain-db: %w", err)
	}
	if _, err := a.runner().Run(ctx(cmd), nil, backup.PgRestoreArgs(cfg.Postgres.Service, dumpPath)...); err != nil {
		return fmt.Errorf("backup restore: pg_restore: %w", err)
	}
	return nil
}

// restoreDKIM overwrites the live DKIM key directory with the bundle's copy.
func (a *App) restoreDKIM(_ *cobra.Command, cfg *config.Config, bundlePath string) error {
	src := filepath.Join(bundlePath, backup.DKIMDir)
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("backup restore: dkim: %w", err)
	}
	if _, err := backup.CopyTree(src, cfg.Mail.DKIMDir); err != nil {
		return fmt.Errorf("backup restore: dkim: %w", err)
	}
	return chownDKIM(cfg.Mail.DKIMDir)
}

// chownDKIM gives the restored key directory the owner the installer uses.
// rspamd runs as _rspamd and cannot read keys that root owns.
func chownDKIM(dir string) error {
	owner, err := user.Lookup("mailadmin")
	if err != nil {
		return fmt.Errorf("lookup mailadmin: %w", err)
	}
	group, err := user.LookupGroup("_rspamd")
	if err != nil {
		return fmt.Errorf("lookup _rspamd: %w", err)
	}
	uid, err := strconv.Atoi(owner.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return err
	}
	// The DKIM directory is flat (one key and one .pub per domain), so a single
	// directory read is enough and avoids a recursive walk.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if err := os.Lchown(dir, uid, gid); err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.Lchown(filepath.Join(dir, e.Name()), uid, gid); err != nil {
			return err
		}
	}
	return nil
}

// restoreSieve replaces and reactivates the managed Sieve script for every
// mailbox address the manifest recorded, using the same put+activate path as
// `sieve set`.
func (a *App) restoreSieve(cmd *cobra.Command, bundlePath string, man backup.Manifest) error {
	svc := sieve.New(a.runner())
	sieveDir := filepath.Join(bundlePath, backup.SieveDir)
	for _, addr := range man.SieveScripts {
		fp := filepath.Join(sieveDir, backup.SieveFileName(addr))
		// fp is built from the bundle's own manifest (operator-supplied bundle
		// path) joined with a fixed-suffix filename derived from an address that
		// was validated by valid.Address before ever being written; no untrusted
		// path component reaches ReadFile.
		body, err := os.ReadFile(fp) // #nosec G304 -- path derived from a validated address recorded in the bundle's own manifest
		if err != nil {
			return fmt.Errorf("backup restore: sieve %s: %w", addr, err)
		}
		if err := svc.Set(ctx(cmd), addr, string(body)); err != nil {
			return fmt.Errorf("backup restore: sieve %s: %w", addr, err)
		}
	}
	return nil
}

// restoreConfig overwrites the live config.toml with the bundle's copy.
func (a *App) restoreConfig(_ *cobra.Command, cfg *config.Config, bundlePath string) error {
	src := filepath.Join(bundlePath, backup.ConfigFile)
	if _, err := backup.CopyFileFollow(src, cfg.Path); err != nil {
		return fmt.Errorf("backup restore: config: %w", err)
	}
	return nil
}

// backupList renders every discovered bundle under the configured (or
// flag-given) backup directory, newest first. Read-only: no --dry-run needed.
func (a *App) backupList(_ *cobra.Command, dirFlag string) error {
	cfg, _, err := a.Config()
	if err != nil {
		return err
	}
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	dir, err := backupDir(cfg, dirFlag)
	if err != nil {
		return err
	}

	bundles, err := backup.ListBundles(dir)
	if err != nil {
		return fmt.Errorf("backup list: %w", err)
	}
	if len(bundles) == 0 {
		r.Message("no backups found in %s", dir)
		return nil
	}

	rows := make([][]string, 0, len(bundles))
	for _, b := range bundles {
		comps := strings.Join(b.Manifest.Components, ",")
		created := "?"
		domains, mailboxes := "?", "?"
		if b.ManifestErr != nil {
			comps = "broken manifest"
		} else {
			created = b.Manifest.CreatedAt.Format("2006-01-02 15:04:05")
			domains = strconv.Itoa(len(b.Manifest.Domains))
			mailboxes = strconv.Itoa(b.Manifest.Mailboxes)
		}
		rows = append(rows, []string{b.Name, created, backup.FormatBytes(b.Bytes), comps, domains, mailboxes})
	}
	return r.Table(output.Table{
		Columns: []string{"NAME", "CREATED (UTC)", "SIZE", "COMPONENTS", "DOMAINS", "MAILBOXES"},
		Rows:    rows,
	})
}

// contains reports whether s holds v.
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
