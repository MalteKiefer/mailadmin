package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"mailadmin/internal/logs"
	"mailadmin/internal/output"
)

// newLogCmd builds the `log` group: read-only access to allowlisted unit logs
// via journalctl (through internal/logs → internal/sys). No mutation, so no
// confirm/audit; the unit is always constrained to config's logs.units.
func newLogCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "log", Short: "Read unit logs"}

	var showLines int
	show := &cobra.Command{
		Use:   "show <unit>",
		Short: "Show recent log lines for a unit",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return app.runLogShow(c, args[0], showLines)
		},
	}
	show.Flags().IntVarP(&showLines, "lines", "n", 100, "number of lines")

	tail := &cobra.Command{
		Use:   "tail <unit>",
		Short: "Follow log lines for a unit",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return app.runLogTail(c, args[0])
		},
	}

	cmd.AddCommand(show, tail)
	return cmd
}

// logReader loads config and builds a logs.Reader gated to config's logs.units.
func (a *App) logReader() (*logs.Reader, error) {
	cfg, _, err := a.Config()
	if err != nil {
		return nil, err
	}
	return logs.New(a.runner(), cfg.Logs.Units), nil
}

// runLogShow renders the last n log lines for an allowlisted unit.
func (a *App) runLogShow(cmd *cobra.Command, unit string, lines int) error {
	reader, err := a.logReader()
	if err != nil {
		return err
	}
	if !reader.Allowed(unit) {
		return fmt.Errorf("%w: unit %q not in configured logs.units allowlist", ErrUsage, unit)
	}

	renderer, err := a.Renderer()
	if err != nil {
		return err
	}

	entries, err := reader.Show(ctx(cmd), unit, lines)
	if err != nil {
		return err
	}
	return renderer.Table(logTable(entries))
}

// runLogTail follows a unit's journal, rendering each line as it arrives until
// the context is cancelled (Ctrl-C / signal) or journalctl exits.
func (a *App) runLogTail(cmd *cobra.Command, unit string) error {
	reader, err := a.logReader()
	if err != nil {
		return err
	}
	if !reader.Allowed(unit) {
		return fmt.Errorf("%w: unit %q not in configured logs.units allowlist", ErrUsage, unit)
	}

	renderer, err := a.Renderer()
	if err != nil {
		return err
	}

	c := ctx(cmd)
	ch, err := reader.Tail(c, unit)
	if err != nil {
		return err
	}

	for {
		select {
		case <-c.Done():
			return nil
		case line, ok := <-ch:
			if !ok {
				return nil
			}
			if err := renderLogLine(renderer, line); err != nil {
				return err
			}
		}
	}
}

// logTable maps log lines onto the shared table shape.
func logTable(lines []logs.Line) output.Table {
	rows := make([][]string, 0, len(lines))
	for _, l := range lines {
		rows = append(rows, []string{l.Timestamp, l.Unit, l.Message})
	}
	return output.Table{
		Columns: []string{"TIMESTAMP", "UNIT", "MESSAGE"},
		Rows:    rows,
	}
}

// renderLogLine emits a single streamed line respecting the selected format:
// json/plain get one machine-readable record; table gets a compact aligned row.
func renderLogLine(r *output.Renderer, l logs.Line) error {
	switch r.Format() {
	case output.FormatJSON:
		return r.JSON(l)
	default:
		return r.Table(logTable([]logs.Line{l}))
	}
}
