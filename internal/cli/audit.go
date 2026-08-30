package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"mailadmin/internal/db"
	"mailadmin/internal/output"
	"mailadmin/internal/valid"
)

// newAuditCmd builds the `audit` command group, which reads the append-only
// audit_log written by every mutation. It is read-only: no confirmation and no
// audit record of its own.
func newAuditCmd(app *App) *cobra.Command {
	var (
		lines  int
		actor  string
		action string
		target string
		since  string
		until  string
	)
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show the audit log",
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List recent audit entries",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runAuditList(app, ctx(c), auditListArgs{
				lines:  lines,
				actor:  actor,
				action: action,
				target: target,
				since:  since,
				until:  until,
			})
		},
	}
	list.Flags().IntVarP(&lines, "lines", "n", 200, "number of entries")
	list.Flags().StringVar(&actor, "actor", "", "only entries recorded by this actor (exact match)")
	list.Flags().StringVar(&action, "action", "", "only entries with this action (exact match, e.g. mailbox.add)")
	list.Flags().StringVar(&target, "target", "", "only entries targeting this address, or every address at this domain (exact match, or an address whose domain matches)")
	list.Flags().StringVar(&since, "since", "", "only entries at or after this long ago (e.g. 24h, 7d)")
	list.Flags().StringVar(&until, "until", "", "only entries at or before this long ago (e.g. 1d); combine with --since for a window, e.g. --since 7d --until 1d for \"between 7 and 1 days ago\"")

	cmd.AddCommand(list)
	return cmd
}

// auditListArgs holds `audit list`'s raw flag values before validation.
type auditListArgs struct {
	lines                 int
	actor, action, target string
	since, until          string
}

// auditFilter validates args and turns them into a db.AuditFilter plus the
// row-count limit to pass to ListAudit. It is a pure function (no I/O) so it
// can be unit-tested without a database, following the pattern of
// backupDir in backup.go.
func auditFilter(a auditListArgs, now time.Time) (db.AuditFilter, int, error) {
	if a.lines <= 0 {
		return db.AuditFilter{}, 0, fmt.Errorf("%w: --lines must be positive", ErrUsage)
	}

	f := db.AuditFilter{Actor: a.actor, Action: a.action, Target: a.target}

	if a.since != "" {
		d, err := parseDurationAgo(a.since)
		if err != nil {
			return db.AuditFilter{}, 0, fmt.Errorf("%w: --since: %w", ErrUsage, err)
		}
		f.Since = now.Add(-d)
	}
	if a.until != "" {
		d, err := parseDurationAgo(a.until)
		if err != nil {
			return db.AuditFilter{}, 0, fmt.Errorf("%w: --until: %w", ErrUsage, err)
		}
		f.Until = now.Add(-d)
	}
	if !f.Since.IsZero() && !f.Until.IsZero() && f.Since.After(f.Until) {
		return db.AuditFilter{}, 0, fmt.Errorf("%w: --since must be further in the past than --until", ErrUsage)
	}

	return f, a.lines, nil
}

// parseDurationAgo validates s with valid.Duration (the same "4h"/"30m"/"7d"
// format used by --since elsewhere, e.g. queue bounces/security quarantine
// list) and converts it to a time.Duration. valid.Duration only validates the
// format; time.ParseDuration doesn't understand the "d" (day) unit that
// format allows, so the day case is expanded to hours before parsing.
func parseDurationAgo(s string) (time.Duration, error) {
	v, err := valid.Duration(s)
	if err != nil {
		return 0, err
	}
	if strings.HasSuffix(v, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(v, "d"))
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(v)
}

// runAuditList loads config, opens the database, fetches the matching
// entries, and renders them through the shared renderer.
func runAuditList(app *App, ctx context.Context, a auditListArgs) error {
	filter, limit, err := auditFilter(a, time.Now())
	if err != nil {
		return err
	}

	r, err := app.Renderer()
	if err != nil {
		return err
	}

	database, err := app.db(ctx)
	if err != nil {
		return fmt.Errorf("audit list: open database: %w", err)
	}

	entries, err := database.ListAudit(ctx, limit, filter)
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
