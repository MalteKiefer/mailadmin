package cli

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"mailadmin/internal/config"
	"mailadmin/internal/output"
	"mailadmin/internal/stats"
	"mailadmin/internal/sys"
	"mailadmin/internal/valid"
)

// newStatsCmd builds the read-only `stats` group: mail-flow and spam summaries
// parsed from journalctl by internal/stats. Every subcommand loads config,
// builds a Collector over the configured log units, and renders the resulting
// Summary through internal/output (respecting -o/-q).
func newStatsCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "stats", Short: "Mail flow and spam statistics"}

	inbound := &cobra.Command{
		Use:   "inbound",
		Short: "Inbound message statistics",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return runStats(app, func(col *stats.Collector) (stats.Summary, error) {
				return col.Inbound(ctx(c))
			})
		},
	}

	outbound := &cobra.Command{
		Use:   "outbound",
		Short: "Outbound message statistics",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return runStats(app, func(col *stats.Collector) (stats.Summary, error) {
				return col.Outbound(ctx(c))
			})
		},
	}

	spam := &cobra.Command{
		Use:   "spam",
		Short: "Spam / rspamd action statistics",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return runStats(app, func(col *stats.Collector) (stats.Summary, error) {
				return col.Spam(ctx(c))
			})
		},
	}

	domain := &cobra.Command{
		Use:   "domain <domain>",
		Short: "Per-domain statistics",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			d, err := valid.Domain(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrUsage, err)
			}
			return runStats(app, func(col *stats.Collector) (stats.Summary, error) {
				return col.Domain(ctx(c), d)
			})
		},
	}

	cmd.AddCommand(inbound, outbound, spam, domain)
	return cmd
}

// runStats is the shared body for every stats subcommand: it wires up the
// config, the audited exec runner and the Collector, invokes the given
// collection function, and renders the Summary. Collection failures surface as
// runtime errors; presentation is delegated to renderSummary.
func runStats(app *App, collect func(*stats.Collector) (stats.Summary, error)) error {
	cfg, err := app.statsConfig()
	if err != nil {
		return err
	}
	format, err := output.ParseFormat(app.flags.output)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	r := output.New(format, os.Stdout, app.flags.quiet)

	runner := sys.New(sys.DefaultTimeout, nil)
	col := stats.New(runner, cfg.Logs.Units)

	summary, err := collect(col)
	if err != nil {
		return err
	}
	return renderSummary(r, format, summary)
}

// statsConfig loads and validates the configuration for the stats commands
// using the resolved --config path.
func (a *App) statsConfig() (*config.Config, error) {
	cfg, _, err := config.Load(a.flags.configPath)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// renderSummary presents a stats.Summary. JSON output emits the whole Summary
// object in one shot so the nested series survive; table/plain output renders a
// headline totals table plus each named series as its own labelled table.
func renderSummary(r *output.Renderer, format output.Format, s stats.Summary) error {
	if format == output.FormatJSON {
		return r.JSON(s)
	}

	totals := output.Table{
		Columns: []string{"metric", "count"},
		Rows: [][]string{
			{"accepted", strconv.FormatInt(s.Accepted, 10)},
			{"rejected", strconv.FormatInt(s.Rejected, 10)},
			{"deferred", strconv.FormatInt(s.Deferred, 10)},
			{"spam", strconv.FormatInt(s.Spam, 10)},
		},
	}
	if err := r.Table(totals); err != nil {
		return err
	}

	for _, series := range s.Series {
		r.Message("")
		r.Message("%s", series.Name)
		t := output.Table{Columns: []string{"label", "value"}}
		for _, p := range series.Points {
			t.Rows = append(t.Rows, []string{p.Label, strconv.FormatInt(p.Value, 10)})
		}
		if err := r.Table(t); err != nil {
			return err
		}
	}
	return nil
}
