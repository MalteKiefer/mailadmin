package cli

import (
	"fmt"
	"mailadmin/defaults"
	"os"
	"os/exec"

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
			return runConfigCheck(app, c)
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

	var force, offline bool
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Write the default config file (from the latest release, or built in)",
		Long: "Writes /etc/mailadmin/config.toml (0600) from the default file of the latest\n" +
			"release. Without network access the copy built into this binary is used.\n" +
			"Convert the file to YAML or JSON if you prefer; mailadmin reads all three.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runConfigInit(app, c, force, offline)
		},
	}
	initCmd.Flags().BoolVar(&force, "force", false, "replace an existing config file")
	initCmd.Flags().BoolVar(&offline, "offline", false, "use the copy built into the binary, do not download")

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
func runConfigCheck(app *App, c *cobra.Command) error {
	cfg, secrets, err := app.Config()
	if err != nil {
		return err
	}
	results, err := config.Check(cfg, secrets)
	if err != nil {
		return err
	}
	// Tokens are optional in general, but a domain on an automated provider needs
	// that provider's credentials (renewal publishes TLSA through it).
	if domains, derr := app.listDomains(ctx(c)); derr == nil {
		for _, d := range domains {
			if automatedDNS(d.DNSProvider) {
				ok := providerConfigured(d.DNSProvider, secrets)
				detail := d.DNSProvider + " credentials present"
				if !ok {
					detail = d.DNSProvider + " credentials missing in secrets.env"
				}
				results = append(results, config.CheckResult{Name: "dns_provider:" + d.Name, OK: ok, Detail: detail})
			}
		}
	} else {
		results = append(results, config.CheckResult{Name: "dns_providers", OK: true,
			Detail: "not checked: database unreachable (" + derr.Error() + ")"})
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

	if app.flags.dryRun {
		r, err := app.Renderer()
		if err != nil {
			return err
		}
		r.Message("dry-run: would edit config %s", path)
		return nil
	}

	editor := editorCommand()
	// #nosec G204 -- editor is taken from the trusted root operator's own
	// environment, and the only argument is the fixed config path; no external
	// or user-supplied input reaches the argv, and no shell is involved.
	ed := exec.CommandContext(ctx(cmd), editor[0], append(editor[1:], path)...)
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

// runConfigInit writes the default config file into the config directory.
func runConfigInit(app *App, c *cobra.Command, force, offline bool) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	dir := config.ConfigDir
	if app.flags.dryRun {
		r.Message("dry-run: would write the default config into %s", dir)
		return nil
	}
	content, source := defaults.ConfigTOML, "built-in copy (--offline)"
	if !offline {
		content, source = config.FetchDefault(ctx(c), config.DefaultConfigURL, defaults.ConfigTOML)
	}
	path, err := config.Init(dir, content, force)
	if err != nil {
		return err
	}
	r.Message("wrote %s (0600) from %s", path, source)
	r.Message("fill in the values marked required, then run: mailadmin config check")
	return nil
}
