package cli

import (
	"context"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"mailadmin/internal/db"
	"mailadmin/internal/output"
)

// newAuditCmd builds the `audit` command group, which reads the append-only
// audit_log written by every mutation. It is read-only: no confirmation and no
// audit record of its own.
func newAuditCmd(app *App) *cobra.Command {
	var lines int
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show the audit log",
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List recent audit entries",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runAuditList(app, ctx(c), lines)
		},
	}
	list.Flags().IntVarP(&lines, "lines", "n", 200, "number of entries")

	cmd.AddCommand(list)
	return cmd
}

// runAuditList loads config, opens the database, fetches the most recent
// entries, and renders them through the shared renderer.
func runAuditList(app *App, ctx context.Context, lines int) error {
	if lines <= 0 {
		return fmt.Errorf("%w: --lines must be positive", ErrUsage)
	}

	r, err := app.Renderer()
	if err != nil {
		return err
	}

	database, err := app.db(ctx)
	if err != nil {
		return fmt.Errorf("audit list: open database: %w", err)
	}

	entries, err := database.ListAudit(ctx, lines)
	if err != nil {
		return fmt.Errorf("audit list: query: %w", err)
	}

	return r.Table(auditTable(entries))
}

// auditTable projects audit entries into the renderer's tabular form. Timestamps
// are rendered in RFC3339 (UTC) for stable, sortable output; before/after JSON
// snapshots are included as compact columns for full-fidelity json/plain output.
func auditTable(entries []db.AuditEntry) output.Table {
	t := output.Table{
		Columns: []string{"id", "timestamp", "actor", "action", "target", "before", "after"},
		Rows:    make([][]string, 0, len(entries)),
	}
	for _, e := range entries {
		t.Rows = append(t.Rows, []string{
			strconv.FormatInt(e.ID, 10),
			e.TS.UTC().Format("2006-01-02T15:04:05Z07:00"),
			e.Actor,
			e.Action,
			e.Target,
			rawJSON(e.Before),
			rawJSON(e.After),
		})
	}
	return t
}

// rawJSON renders an optional JSON snapshot column; an absent snapshot shows as
// an empty string rather than the literal "null".
func rawJSON(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return string(b)
}
