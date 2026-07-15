package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"mailadmin/internal/config"
	"mailadmin/internal/output"
)

func newConfigCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Inspect and initialise configuration"}

	show := &cobra.Command{
		Use:   "show",
		Short: "Show the loaded config (secrets redacted)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runConfigShow(app)
		},
	}

	check := &cobra.Command{
		Use:   "check",
		Short: "Validate config and secrets",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runConfigCheck(app)
		},
	}

	edit := &cobra.Command{
		Use:   "edit",
		Short: "Edit the config file in $EDITOR",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runConfigEdit(app, c)
		},
	}

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Write starter config.toml and secrets.env",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runConfigInit(app)
		},
	}

	cmd.AddCommand(show, check, edit, initCmd)
	return cmd
}

// runConfigShow renders the redacted config view. Secrets are never included;
// only booleans reporting whether each secret is configured.
func runConfigShow(app *App) error {
	cfg, secrets, err := app.Config()
	if err != nil {
		return err
	}
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	return r.Value(config.View(cfg, secrets))
}

// runConfigCheck runs the config/secret sanity checks and renders a table. It
// returns a runtime error (exit 1) if any check failed so scripts can gate on
// the exit code, while still printing the full result set first.
func runConfigCheck(app *App) error {
	cfg, secrets, err := app.Config()
	if err != nil {
		return err
	}
	results, err := config.Check(cfg, secrets)
	if err != nil {
		return err
	}
	r, err := app.Renderer()
	if err != nil {
		return err
	}

	table := output.Table{Columns: []string{"CHECK", "STATUS", "DETAIL"}}
	failed := 0
	for _, res := range results {
		status := "ok"
		if !res.OK {
			status = "FAIL"
			failed++
		}
		table.Rows = append(table.Rows, []string{res.Name, status, res.Detail})
	}
	if err := r.Table(table); err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("config check: %d of %d checks failed", failed, len(results))
	}
	return nil
}

// runConfigEdit opens the config file in $EDITOR (falling back to a sane
// default). The editor inherits the terminal directly; on return the edited
// config is reloaded and validated so a broken edit is reported immediately.
func runConfigEdit(app *App, cmd *cobra.Command) error {
	path := app.flags.configPath
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: config %s does not exist (run 'mailadmin config init' first)", ErrNotFound, path)
		}
		return err
	}

	editor := editorCommand()
	// #nosec G204 -- editor is taken from the trusted root operator's own
	// environment, and the only argument is the fixed config path; no external
	// or user-supplied input reaches the argv, and no shell is involved.
	ed := exec.Command(editor[0], append(editor[1:], path)...)
	ed.Stdin = app.stdin()
	ed.Stdout = app.stdout()
	ed.Stderr = app.stderr()
	if err := ed.Run(); err != nil {
		return fmt.Errorf("config edit: editor %q failed: %w", editor[0], err)
	}

	if _, _, err := config.Load(path); err != nil {
		return fmt.Errorf("config edit: saved file is invalid: %w", err)
	}

	r, err := app.Renderer()
	if err != nil {
		return err
	}
	r.Message("config %s edited and validated", path)
	return nil
}

// editorCommand resolves the editor invocation as an argv slice from $EDITOR /
// $VISUAL, falling back to a common default. No shell is used.
func editorCommand() []string {
	for _, key := range []string{"VISUAL", "EDITOR"} {
		if v := os.Getenv(key); v != "" {
			if fields := splitFields(v); len(fields) > 0 {
				return fields
			}
		}
	}
	return []string{"vi"}
}

// splitFields splits an editor command on spaces into an argv slice, tolerating
// simple "editor --flag" values. It does not attempt shell-quote parsing; the
// operator controls this value.
func splitFields(s string) []string {
	var out []string
	field := ""
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if field != "" {
				out = append(out, field)
				field = ""
			}
			continue
		}
		field += string(r)
	}
	if field != "" {
		out = append(out, field)
	}
	return out
}

// runConfigInit writes a starter config.toml (0644) and secrets.env (0600) next
// to the --config path, refusing to overwrite existing files.
func runConfigInit(app *App) error {
	dir := filepath.Dir(app.flags.configPath)
	configPath, secretsPath, err := config.Init(dir)
	if err != nil {
		return err
	}
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	r.Message("wrote %s (0644)", configPath)
	r.Message("wrote %s (0600) — set NJALLA_TOKEN / RSPAMD_CONTROLLER_PW", secretsPath)
	return nil
}
