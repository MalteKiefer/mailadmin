// Command mailadmin is the multi-domain mail server administration CLI.
//
// It builds the root cobra command tree (internal/cli), which lazily loads
// configuration and dispatches to the backend packages. Exit codes follow
// ARCHITECTURE: 0 ok, 1 runtime error, 2 usage error, 3 not-found, 4 declined.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"mailadmin/internal/cli"
)

func main() {
	os.Exit(run())
}

// run executes the CLI and returns the process exit code. Splitting this out
// of main lets the signal-forwarding context's stop() defer run before the
// process exits (os.Exit in main itself would skip it).
func run() int {
	// Files and directories mailadmin creates for other services (apt keyrings,
	// Caddy includes, the MTA-STS web root, rspamd local.d) must be readable by
	// them. A hardened login umask such as 027 would make them root only, so the
	// process sets 022. Secrets and keys are always written with explicit modes.
	syscall.Umask(0o022)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := cli.NewRootCmd()
	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return cli.ExitCode(err)
	}
	return cli.ExitOK
}
