package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"

	"mailadmin/internal/output"
	"mailadmin/internal/selfupdate"
)

// upgradeStep is one row of the upgrade summary.
type upgradeStep struct {
	name   string
	status string // ok, failed, skipped
	detail string
	took   time.Duration
}

func newUpgradeCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "upgrade",
		Short: "Back up, update mailadmin, reconcile the host from config, check it",
		Long: "Runs the upgrade in order: backup, self-update to the latest release,\n" +
			"install --adopt (reads every value from config.toml, asks only for what the\n" +
			"config lacks), config check, doctor. The summary table shows each step.\n" +
			"The steps after a failed step do not run.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error { return runUpgrade(app, c) },
	}
}

func runUpgrade(app *App, c *cobra.Command) error {
	out := c.OutOrStdout()
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	if !app.flags.dryRun && os.Geteuid() != 0 {
		return errors.New("upgrade must run as root (try: sudo mailadmin upgrade)")
	}
	if _, _, err := app.Config(); err != nil {
		return fmt.Errorf("upgrade needs a readable config: %w", err)
	}
	rel, err := selfupdate.Latest(ctx(c))
	if err != nil {
		return err
	}
	target := rel.Tag
	if !selfupdate.IsNewer(Version, target) {
		target = Version + " (no newer release)"
	}
	if app.flags.dryRun {
		return printUpgradePlan(r, Version, target)
	}
	if err := app.confirm(fmt.Sprintf("back up, update %s -> %s and reconcile this host?", Version, rel.Tag)); err != nil {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate running binary: %w", err)
	}
	cfgArgs := []string{"--config", app.flags.configPath, "--yes"}
	steps := []struct {
		name string
		run  func() error
	}{
		{"backup", func() error { return app.backupCreate(c, "") }},
		{"update", func() error { return childRun(app, c, exe, append([]string{"update"}, cfgArgs...)) }},
		{"reconcile", func() error {
			return childRun(app, c, exe, append([]string{"install", "--adopt"}, cfgArgs...))
		}},
		{"check", func() error {
			return childRun(app, c, exe, []string{"--config", app.flags.configPath, "config", "check"})
		}},
		{"doctor", func() error { return childRun(app, c, exe, []string{"--config", app.flags.configPath, "doctor"}) }},
	}

	var rows []upgradeStep
	failed := false
	for _, s := range steps {
		if failed {
			rows = append(rows, upgradeStep{name: s.name, status: "skipped", detail: "an earlier step failed"})
			continue
		}
		_, _ = fmt.Fprintf(out, "\n== %s\n", s.name)
		start := time.Now()
		err := s.run()
		st := upgradeStep{name: s.name, status: "ok", took: time.Since(start)}
		if err != nil {
			st.status, st.detail = "failed", err.Error()
			// doctor only reports; a failing check does not undo the upgrade.
			if s.name != "doctor" {
				failed = true
			}
		}
		rows = append(rows, st)
	}
	return renderUpgradeSummary(r, rows)
}

// childRun runs the binary as a separate process so that the updated binary, not
// the one still in memory, performs the step. stdin, stdout and stderr are the
// command's own, so prompts for missing values reach the terminal.
func childRun(app *App, c *cobra.Command, exe string, args []string) error {
	cmd := exec.CommandContext(ctx(c), exe, args...) // #nosec G204 -- the running binary with fixed subcommands
	cmd.Stdin = app.stdin()
	cmd.Stdout = c.OutOrStdout()
	cmd.Stderr = c.ErrOrStderr()
	return cmd.Run()
}

func printUpgradePlan(r *output.Renderer, current, target string) error {
	rows := [][]string{
		{"backup", "planned", "pg_dump, DKIM keys, Sieve, config.toml"},
		{"update", "planned", current + " -> " + target},
		{"reconcile", "planned", "install --adopt from config.toml"},
		{"check", "planned", "config check"},
		{"doctor", "planned", "read-only report"},
	}
	if err := r.StatusTable(output.Table{Columns: []string{"STEP", "STATUS", "DETAIL"}, Rows: rows}, 1); err != nil {
		return err
	}
	r.Message("dry-run: no changes made")
	return nil
}

func renderUpgradeSummary(r *output.Renderer, rows []upgradeStep) error {
	t := output.Table{Columns: []string{"STEP", "STATUS", "TIME", "DETAIL"}}
	for _, s := range rows {
		took := "-"
		if s.took > 0 {
			took = s.took.Round(time.Second).String()
		}
		t.Rows = append(t.Rows, []string{s.name, s.status, took, s.detail})
	}
	return r.StatusTable(t, 1)
}
