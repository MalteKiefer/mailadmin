package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"mailadmin/internal/backup"
	"mailadmin/internal/config"
	"mailadmin/internal/install"
	"mailadmin/internal/sys"
)

// borgCheckStamp records the last repository check, so check_every is respected.
const borgCheckStamp = "/var/lib/mailadmin/.borg-checked"

func newBackupBorgCmd(app *App) *cobra.Command {
	borg := &cobra.Command{Use: "borg", Short: "Archive backups to the borg repository in [backup.borg]"}
	borg.AddCommand(&cobra.Command{
		Use:   "init",
		Short: "Create the borg repository with the configured encryption",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			b, _, err := app.borgFor()
			if err != nil {
				return err
			}
			if err := b.Init(ctx(c)); err != nil {
				return err
			}
			r, err := app.Renderer()
			if err != nil {
				return err
			}
			r.OK("borg repository initialised: %s", b.Cfg.Repo)
			return nil
		},
	}, &cobra.Command{
		Use:   "run",
		Short: "Write a fresh backup bundle, archive it, then prune, compact and check",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			b, cfg, err := app.borgFor()
			if err != nil {
				return err
			}
			// A new bundle first, so the archive holds the current database dump.
			if err := app.backupCreate(c, ""); err != nil {
				return err
			}
			sources := []string(b.Cfg.Source)
			if len(sources) == 0 {
				sources = []string{cfg.Backup.Dir}
			}
			name, err := b.Run(ctx(c), sources, borgCheckStamp, time.Now())
			r, rerr := app.Renderer()
			if rerr != nil {
				return rerr
			}
			if name != "" {
				r.OK("archived %s", name)
			}
			if err != nil {
				return err
			}
			// Local bundles go only after the run archived them, and only when the
			// bundle directory is part of the archive.
			if cfg.Backup.Borg.LocalKeep > 0 && archivesDir(sources, cfg.Backup.Dir) {
				removed, perr := backup.PruneLocalBundles(cfg.Backup.Dir, cfg.Backup.Borg.LocalKeep)
				for _, n := range removed {
					r.Info("removed local bundle %s", n)
				}
				return perr
			}
			return nil
		},
	}, &cobra.Command{
		Use:   "list",
		Short: "List the mailadmin archives in the repository",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			b, _, err := app.borgFor()
			if err != nil {
				return err
			}
			out, err := b.List(ctx(c))
			if err != nil {
				return err
			}
			r, rerr := app.Renderer()
			if rerr != nil {
				return rerr
			}
			r.Message("%s", out)
			return nil
		},
	}, &cobra.Command{
		Use:   "check",
		Short: "Verify the repository now",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			b, _, err := app.borgFor()
			if err != nil {
				return err
			}
			if err := b.Check(ctx(c)); err != nil {
				return err
			}
			return backup.MarkChecked(borgCheckStamp, time.Now())
		},
	})
	return borg
}

// borgFor builds the borg runner from the config. It refuses when [backup.borg] is off.
func (a *App) borgFor() (backup.Borg, *config.Config, error) {
	cfg, secrets, err := a.Config()
	if err != nil {
		return backup.Borg{}, nil, err
	}
	if !cfg.Backup.Borg.Enabled {
		return backup.Borg{}, nil, fmt.Errorf("%w: [backup.borg] enabled is false", ErrUsage)
	}
	// Six hours bounds one borg step; a large first archive can take long.
	return backup.Borg{
		Cfg:        cfg.Backup.Borg,
		Passphrase: secrets.BorgPassphrase(),
		Exec:       sys.New(6*time.Hour, nil),
	}, cfg, nil
}

// ApplyBorgTimerConfig installs the borg timer for the config. Used by install.
func ApplyBorgTimerConfig(ctx context.Context, x install.Exec, cfg *config.Config) error {
	return install.ApplyBorgTimer(ctx, x, cfg.Backup.Borg.Enabled, cfg.Backup.Borg.Schedule)
}

// archivesDir reports whether dir is one of the archived sources.
func archivesDir(sources []string, dir string) bool {
	want := filepath.Clean(dir)
	for _, s := range sources {
		if filepath.Clean(s) == want {
			return true
		}
	}
	return false
}
