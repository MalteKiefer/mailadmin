package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	if err := printUpgradePlan(r, Version, target); err != nil {
		return err
	}
	if app.flags.dryRun {
		r.Message("dry-run: no changes made")
		return nil
	}
	if err := app.confirm(fmt.Sprintf("back up, update %s -> %s and reconcile this host?", Version, rel.Tag)); err != nil {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate running binary: %w", err)
	}
	cfgArgs := []string{"--config", app.flags.configPath, "--yes"}
	logPath, logFile, err := openUpgradeLog()
	if err != nil {
		return err
	}
	defer func() { _ = logFile.Close() }()

	steps := []struct {
		name string
		run  func() error
	}{
		{"backup", func() error {
			c.SetOut(logFile)
			defer c.SetOut(nil)
			return app.backupCreate(c, "")
		}},
		{"update", func() error { return childRun(c, exe, logFile, append([]string{"update"}, cfgArgs...)) }},
		{"reconcile", func() error {
			return childRun(c, exe, logFile, append([]string{"install", "--adopt"}, cfgArgs...))
		}},
		{"check", func() error {
			return childRun(c, exe, logFile, []string{"--config", app.flags.configPath, "config", "check"})
		}},
		{"doctor", func() error {
			return childRun(c, exe, logFile, []string{"--config", app.flags.configPath, "doctor"})
		}},
	}

	var rows []upgradeStep
	failed := false
	var failLog string
	for _, s := range steps {
		if failed {
			rows = append(rows, upgradeStep{name: s.name, status: "skipped", detail: "an earlier step failed"})
			continue
		}
		r.Message("running %s ...", s.name)
		start := time.Now()
		err := s.run()
		st := upgradeStep{name: s.name, status: "ok", took: time.Since(start)}
		if err != nil {
			st.status, st.detail = "failed", err.Error()
			// doctor only reports; a failing check does not undo the upgrade.
			if s.name != "doctor" {
				failed = true
				failLog = tailFile(logPath, 15)
			}
		}
		rows = append(rows, st)
	}
	if err := renderUpgradeSummary(r, rows); err != nil {
		return err
	}
	r.Message("full log: %s", logPath)
	if failLog != "" {
		r.Message("last lines of the failing step:\n%s", failLog)
		return errors.New("upgrade stopped, see the table above")
	}
	return nil
}

// openUpgradeLog creates the log of one upgrade run, owner-only. The log keeps the
// output of every step, so the terminal shows only the summary.
func openUpgradeLog() (string, *os.File, error) {
	name := "upgrade-" + time.Now().UTC().Format("20060102T150405Z") + ".log"
	path := filepath.Join(upgradeLogDir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- fixed directory, timestamped name
	if err != nil {
		path = filepath.Join(os.TempDir(), name)
		f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- fallback, owner-only
		if err != nil {
			return "", nil, fmt.Errorf("create upgrade log: %w", err)
		}
	}
	return path, f, nil
}

// tailFile returns the last n lines of path, or "" when it cannot be read.
func tailFile(path string, n int) string {
	data, err := os.ReadFile(path) // #nosec G304 -- log written by this run
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// childRun runs the binary as a separate process, so the updated binary performs the
// step, not the one still in memory. The step gets no terminal: a missing value fails
// the step with a message instead of waiting for input. Output goes to the log.
func childRun(c *cobra.Command, exe string, log io.Writer, args []string) error {
	cmd := exec.CommandContext(ctx(c), exe, args...) // #nosec G204 -- the running binary with fixed subcommands
	cmd.Stdin = nil
	cmd.Stdout = log
	cmd.Stderr = log
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

// upgradeLogDir holds the logs of upgrade runs.
const upgradeLogDir = "/var/lib/mailadmin"
