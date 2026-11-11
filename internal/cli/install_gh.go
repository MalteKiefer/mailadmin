package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// ensureGHLogin makes sure the GitHub CLI can open pull requests. The dns sync flow
// runs gh on this host, so an unauthenticated gh is asked about during install. Off a
// terminal, the install only reports what is missing.
func ensureGHLogin(app *App, out io.Writer) {
	if !ghInstalled() {
		_, _ = fmt.Fprintln(out, "warning: gh is not installed, dns sync cannot open pull requests")
		return
	}
	if ghLoggedIn() {
		_, _ = fmt.Fprintln(out, "gh: logged in to GitHub")
		return
	}
	if !app.interactive() || app.flags.yes {
		_, _ = fmt.Fprintln(out, "warning: gh is not logged in, run: gh auth login (needed by dns sync)")
		return
	}
	if app.confirm("gh is not logged in to GitHub. Log in now with gh auth login?") != nil {
		_, _ = fmt.Fprintln(out, "gh login skipped, run later: gh auth login")
		return
	}
	cmd := exec.CommandContext(context.Background(), "gh", "auth", "login") // #nosec G204 -- fixed tool and arguments, interactive by design
	cmd.Stdin = os.Stdin
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		_, _ = fmt.Fprintf(out, "warning: gh auth login failed: %v\n", err)
	}
}

func ghInstalled() bool {
	_, err := exec.LookPath("gh")
	return err == nil
}

func ghLoggedIn() bool {
	return exec.CommandContext(context.Background(), "gh", "auth", "status").Run() == nil // #nosec G204 -- fixed tool and arguments
}
