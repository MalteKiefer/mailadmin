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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := cli.NewRootCmd()
	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(cli.ExitCode(err))
	}
	os.Exit(cli.ExitOK)
}
