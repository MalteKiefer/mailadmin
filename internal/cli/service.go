package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"mailadmin/internal/output"
	"mailadmin/internal/services"
	"mailadmin/internal/valid"
)

func newServiceCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "service", Short: "Manage allowlisted systemd units"}

	list := &cobra.Command{
		Use:   "list",
		Short: "List managed units and their status",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, _ []string) error { return runServiceList(app, c) },
	}

	status := &cobra.Command{
		Use:   "status <unit>",
		Short: "Show a unit's status",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return runServiceStatus(app, c, args[0]) },
	}

	start := &cobra.Command{
		Use:   "start <unit>",
		Short: "Start a unit",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return runServiceAction(app, c, "start", args[0]) },
	}

	stop := &cobra.Command{
		Use:   "stop <unit>",
		Short: "Stop a unit",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return runServiceAction(app, c, "stop", args[0]) },
	}

	restart := &cobra.Command{
		Use:   "restart <unit>",
		Short: "Restart a unit",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return runServiceAction(app, c, "restart", args[0]) },
	}

	reload := &cobra.Command{
		Use:   "reload <unit>",
		Short: "Reload a unit",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return runServiceAction(app, c, "reload", args[0]) },
	}

	cmd.AddCommand(list, status, start, stop, restart, reload)
	return cmd
}

// serviceRow flattens a services.Status for stable table/plain/json output.
type serviceRow struct {
	Unit    string `json:"unit"`
	Active  string `json:"active"`
	Sub     string `json:"sub"`
	Enabled string `json:"enabled"`
}

var serviceColumns = []string{"UNIT", "ACTIVE", "SUB", "ENABLED"}

func serviceStatusRow(s services.Status) []string {
	return []string{s.Unit, s.Active, s.Sub, s.Enabled}
}

// runServiceList prints the status of every allowlisted unit.
func runServiceList(app *App, cmd *cobra.Command) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	svc, err := app.services()
	if err != nil {
		return err
	}
	statuses, err := svc.List(ctx(cmd))
	if err != nil {
		return err
	}
	rows := make([][]string, 0, len(statuses))
	for _, s := range statuses {
		rows = append(rows, serviceStatusRow(s))
	}
	return r.Table(output.Table{Columns: serviceColumns, Rows: rows})
}

// runServiceStatus prints one allowlisted unit's status.
func runServiceStatus(app *App, cmd *cobra.Command, unit string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	svc, err := app.services()
	if err != nil {
		return err
	}
	st, err := svc.StatusOf(ctx(cmd), unit)
	if err != nil {
		return serviceError(err)
	}
	return r.Value(serviceRow{Unit: st.Unit, Active: st.Active, Sub: st.Sub, Enabled: st.Enabled})
}

// runServiceAction runs a mutating verb (start/stop/restart/reload) against an
// allowlisted unit: it confirms unless --yes, executes, records an audit entry,
// then prints the resulting status.
func runServiceAction(app *App, cmd *cobra.Command, verb, unit string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	svc, err := app.services()
	if err != nil {
		return err
	}

	// Validate and allowlist-gate the unit before confirming or acting, so an
	// invalid/forbidden unit fails fast without a misleading prompt.
	before, err := svc.StatusOf(ctx(cmd), unit)
	if err != nil {
		return serviceError(err)
	}

	if err := app.confirm(fmt.Sprintf("%s unit %q?", verb, before.Unit)); err != nil {
		return err
	}

	if err := serviceRun(svc, ctx(cmd), verb, before.Unit); err != nil {
		return err
	}

	after, err := svc.StatusOf(ctx(cmd), before.Unit)
	if err != nil {
		return serviceError(err)
	}

	if err := app.recordAudit(ctx(cmd), "service."+verb, before.Unit,
		serviceRow{Unit: before.Unit, Active: before.Active, Sub: before.Sub, Enabled: before.Enabled},
		serviceRow{Unit: after.Unit, Active: after.Active, Sub: after.Sub, Enabled: after.Enabled}); err != nil {
		return err
	}

	r.Message("%s %s", verb, after.Unit)
	return r.Value(serviceRow{Unit: after.Unit, Active: after.Active, Sub: after.Sub, Enabled: after.Enabled})
}

// serviceRun dispatches the validated verb to the backend. verb is a
// compile-time constant supplied by the command wiring, never user input.
func serviceRun(svc *services.Service, ctx context.Context, verb, unit string) error {
	switch verb {
	case "start":
		return svc.Start(ctx, unit)
	case "stop":
		return svc.Stop(ctx, unit)
	case "restart":
		return svc.Restart(ctx, unit)
	case "reload":
		return svc.Reload(ctx, unit)
	default:
		return fmt.Errorf("%w: unknown service verb %q", ErrUsage, verb)
	}
}

// services builds the allowlist-gated systemctl backend from the configured
// logs.units allowlist (the same set the CLI is permitted to inspect and act on).
func (a *App) services() (*services.Service, error) {
	cfg, _, err := a.Config()
	if err != nil {
		return nil, err
	}
	return services.New(a.runner(), cfg.Logs.Units), nil
}

// recordAudit writes one audit entry for a successful mutation. An audit failure
// surfaces to the caller: a mutation that cannot be recorded must not be
// reported as a clean success. The shared DB pool is released by closeBackends.
func (a *App) recordAudit(ctx context.Context, action, target string, before, after any) error {
	rec, err := a.auditor(ctx)
	if err != nil {
		return err
	}
	return rec.Record(ctx, action, target, before, after)
}

// serviceError maps backend sentinels to the CLI's exit-code sentinels: an
// invalid unit name is a usage error (exit 2); a unit outside the allowlist is
// reported as not-found (exit 3) so callers cannot probe which units exist.
func serviceError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, valid.ErrInvalid):
		return fmt.Errorf("%w: %v", ErrUsage, err)
	case errors.Is(err, services.ErrUnitNotAllowed):
		return fmt.Errorf("%w: unit not managed", ErrNotFound)
	default:
		return err
	}
}
