package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	"mailadmin/internal/config"
	"mailadmin/internal/output"
	"mailadmin/internal/selfupdate"
)

// Version is the build version, overridable via -ldflags at build time.
var Version = "dev"

//nolint:unparam // app kept for signature parity with the other newXCmd(app, ...) constructors in this package; unused today, a natural extension point (e.g. reading app.flags) tomorrow
func newVersionCmd(app *App) *cobra.Command {
	var check bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version (optionally check for updates)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			out := c.OutOrStdout()
			if _, err := fmt.Fprintln(out, "mailadmin "+Version); err != nil {
				return err
			}
			if !check {
				return nil
			}
			rel, err := selfupdate.Latest(ctx(c))
			if err != nil {
				return err
			}
			if selfupdate.IsNewer(Version, rel.Tag) {
				_, err = fmt.Fprintf(out, "update available: %s (run `mailadmin update`)\n", rel.Tag)
			} else {
				_, err = fmt.Fprintln(out, "up to date")
			}
			return err
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "check GitHub for a newer release")
	return cmd
}

// newManCmd generates a full man-page tree for the CLI (one page per command)
// via cobra/doc, alongside the shell-completion generators above. It is
// registered as `completion man <output-dir>` rather than a top-level command
// since, like shell completion, it is generated documentation derived from the
// command tree rather than an operational subcommand.
func newManCmd(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "man <output-dir>",
		Short: "Generate man pages for every command into <output-dir>",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			dir := args[0]
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return fmt.Errorf("man: %w", err)
			}
			header := &doc.GenManHeader{
				Title:   "MAILADMIN",
				Section: "1",
				Source:  "mailadmin " + Version,
			}
			if err := doc.GenManTree(root, header, dir); err != nil {
				return fmt.Errorf("man: %w", err)
			}
			_, err := fmt.Fprintf(c.OutOrStdout(), "man pages written to %s\n", dir)
			return err
		},
	}
}

// newUpdateCmd downloads the latest release binary (verified against its
// published SHA256SUMS) and atomically replaces the running executable.
func newUpdateCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Self-update to the latest release from GitHub",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			out := c.OutOrStdout()
			rel, err := selfupdate.Latest(ctx(c))
			if err != nil {
				return err
			}
			if !selfupdate.IsNewer(Version, rel.Tag) {
				_, err = fmt.Fprintf(out, "already up to date (%s)\n", Version)
				if err != nil {
					return err
				}
				// The config still gets every key the running release knows.
				return syncConfig(c, app, out, "v"+Version)
			}
			if _, err := fmt.Fprintf(out, "updating %s -> %s\n", Version, rel.Tag); err != nil {
				return err
			}
			if app.flags.dryRun {
				_, err = fmt.Fprintln(out, "dry-run: no changes made")
				return err
			}
			if err := app.confirm(fmt.Sprintf("replace this binary with %s", rel.Tag)); err != nil {
				return err
			}
			if err := selfupdate.Apply(ctx(c), rel); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(out, "updated to %s\n", rel.Tag); err != nil {
				return err
			}
			// Warnings only: the binary is already replaced at this point.
			return syncConfig(c, app, out, rel.Tag)
		},
	}
}

func newCompletionCmd(root *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:       "completion <shell>",
		Short:     "Generate shell completion (bash|zsh|fish|powershell)",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		RunE: func(c *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return root.GenBashCompletionV2(c.OutOrStdout(), true)
			case "zsh":
				return root.GenZshCompletion(c.OutOrStdout())
			case "fish":
				return root.GenFishCompletion(c.OutOrStdout(), true)
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(c.OutOrStdout())
			default:
				return fmt.Errorf("%w: unsupported shell %q", ErrNotImplemented, args[0])
			}
		},
	}
	cmd.AddCommand(newManCmd(root))
	return cmd
}

// configUpdateHint compares the host config with the default config of the
// release just installed. It writes that default to config.default.toml next to
// the host config (the file in use, also when --config points elsewhere), as a reference for a diff, and names the keys the host lacks. The
// host config itself is never changed.
func configUpdateHint(c context.Context, out io.Writer, host, tag string) error {
	def, err := config.FetchDefaultFor(c, tag)
	if err != nil {
		return err
	}
	ref := filepath.Join(filepath.Dir(host), "config.default.toml")
	if err := os.WriteFile(ref, def, 0o644); err != nil { // #nosec G306 -- reference copy, holds no secrets
		return fmt.Errorf("write %s: %w", ref, err)
	}
	keys, err := config.NewDefaultKeys(host, def)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		_, err = fmt.Fprintf(out, "config: no new keys in %s (reference: %s)\n", tag, ref)
		return err
	}
	_, err = fmt.Fprintf(out, "config: %d new key(s) in %s: %s\n  review: diff %s %s\n  add them to %s (secrets stay in [secrets])\n",
		len(keys), tag, config.FormatKeys(keys), host, ref, host)
	return err
}

// syncConfig brings the live config in line with the release tag: missing keys
// are added, keys the release dropped are marked. Problems are warnings only.
func syncConfig(c *cobra.Command, app *App, out io.Writer, tag string) error {
	cfg, _, cerr := app.Config()
	switch {
	case errors.Is(cerr, config.ErrNoConfig),
		errors.Is(cerr, fs.ErrNotExist) && app.flags.configPath == config.DefaultPath:
		return nil // no config file yet: nothing to compare
	case cerr != nil:
		_, _ = fmt.Fprintf(out, "warning: config check skipped: %v\n", cerr)
		return nil
	}
	if err := configAutoMerge(ctx(c), app, out, cfg.Path, tag); err != nil {
		_, _ = fmt.Fprintf(out, "warning: config merge skipped: %v\n", err)
	}
	return nil
}

// configAutoMerge adds the keys the new release introduced to the live config.
// The config is copied to config.toml.before-<tag> first. Existing values, comments
// and [secrets] stay as they are. YAML and JSON configs get the review hint only.
func configAutoMerge(c context.Context, app *App, out io.Writer, host, tag string) error {
	if strings.ToLower(filepath.Ext(host)) != ".toml" {
		return configUpdateHint(c, out, host, tag)
	}
	if !reReleaseTag.MatchString(tag) {
		return fmt.Errorf("unexpected release tag %q", tag)
	}
	def, err := config.FetchDefaultFor(c, tag)
	if err != nil {
		return err
	}
	ref := filepath.Join(filepath.Dir(host), "config.default.toml")
	if err := os.WriteFile(ref, def, 0o644); err != nil { // #nosec G306 -- reference copy, holds no secrets
		return fmt.Errorf("write %s: %w", ref, err)
	}
	cur, err := os.ReadFile(host) // #nosec G304 -- operator config path
	if err != nil {
		return err
	}
	before := host + ".before-" + tag
	if err := os.WriteFile(before, cur, 0o600); err != nil { // #nosec G703 -- tag matches reReleaseTag
		return fmt.Errorf("save %s: %w", before, err)
	}
	res, err := config.MergeNewKeys(host, def, tag)
	if err != nil {
		return err
	}
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	if len(res.Added) == 0 && len(res.Obsolete) == 0 {
		r.Message("config: up to date with %s (backup: %s)", tag, before)
		return nil
	}
	r.Message("config: %s, backup: %s", tag, before)
	if len(res.Added) > 0 {
		rows := make([][]string, 0, len(res.Added))
		for _, k := range res.Added {
			rows = append(rows, []string{k, "added"})
		}
		if err := r.StatusTable(output.Table{Columns: []string{"KEY", "STATUS"}, Rows: rows}, 1); err != nil {
			return err
		}
	}
	if len(res.Obsolete) > 0 {
		rows := make([][]string, 0, len(res.Obsolete))
		for _, k := range res.Obsolete {
			rows = append(rows, []string{k, "obsolete"})
		}
		return r.StatusTable(output.Table{Columns: []string{"KEY", "STATUS"}, Rows: rows}, 1)
	}
	return nil
}

// reReleaseTag matches the release tags mailadmin publishes, e.g. v1.32.0.
var reReleaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
