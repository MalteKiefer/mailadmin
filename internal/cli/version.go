package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"mailadmin/internal/selfupdate"
)

// Version is the build version, overridable via -ldflags at build time.
var Version = "dev"

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
				return err
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
			_, err = fmt.Fprintf(out, "updated to %s\n", rel.Tag)
			return err
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
	return cmd
}
