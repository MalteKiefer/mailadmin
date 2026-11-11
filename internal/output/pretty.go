package output

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pterm/pterm"
)

// Nord palette as truecolour, used by the status tables and the notices.
var (
	ptGreen  = pterm.NewRGB(163, 190, 140)
	ptYellow = pterm.NewRGB(235, 203, 139)
	ptRed    = pterm.NewRGB(191, 97, 106)
	ptCyan   = pterm.NewRGB(136, 192, 208)
	ptBlue   = pterm.NewRGB(129, 161, 193)
	ptPurple = pterm.NewRGB(180, 142, 173)
	ptSnow   = pterm.NewRGB(236, 239, 244)
	ptGrey   = pterm.NewRGB(110, 118, 129)
)

// ptermColor maps a status colour code to the Nord truecolour. Unknown codes return nil.
func ptermColor(code string) *pterm.RGB {
	switch code {
	case ansiGreen:
		return &ptGreen
	case ansiYellow:
		return &ptYellow
	case ansiRed:
		return &ptRed
	case ansiCyan:
		return &ptCyan
	case ansiBlue:
		return &ptBlue
	case ansiMagenta:
		return &ptPurple
	}
	return nil
}

// stamp is the time prefix of every human-readable line.
func (r *Renderer) stamp() string {
	ts := time.Now().Format("15:04:05")
	if r.color {
		return ptGrey.Sprint(ts)
	}
	return ts
}

// notice prints one line: time, icon, text. Multi-line text is indented under the first line.
func (r *Renderer) notice(icon string, color *pterm.RGB, text string) {
	if r.quiet || r.format == FormatJSON {
		return
	}
	if r.format != FormatTable {
		_, _ = fmt.Fprintln(r.out, text)
		return
	}
	if color != nil && r.color {
		icon = color.Sprint(icon)
	}
	lines := strings.Split(text, "\n")
	pad := strings.Repeat(" ", 12)
	for i, l := range lines {
		if i == 0 {
			_, _ = fmt.Fprintf(r.out, "%s  %s %s\n", r.stamp(), icon, l)
			continue
		}
		_, _ = fmt.Fprintf(r.out, "%s%s\n", pad, l)
	}
}

// Info prints an informational line with a timestamp.
func (r *Renderer) Info(format string, args ...any) {
	r.notice("ℹ", &ptCyan, fmt.Sprintf(format, args...))
}

// OK prints a success line with a timestamp.
func (r *Renderer) OK(format string, args ...any) {
	r.notice("✔", &ptGreen, fmt.Sprintf(format, args...))
}

// Warn prints a warning line with a timestamp.
func (r *Renderer) Warn(format string, args ...any) {
	r.notice("⚠", &ptYellow, fmt.Sprintf(format, args...))
}

// Fail prints a failure line with a timestamp.
func (r *Renderer) Fail(format string, args ...any) {
	r.notice("✖", &ptRed, fmt.Sprintf(format, args...))
}

// PrintError writes an error the way every command reports it: failure icon,
// timestamp, message. It is used by the process entry point.
func PrintError(w io.Writer, color bool, err error) {
	r := &Renderer{format: FormatTable, out: w, color: color}
	r.Fail("error: %s", err.Error())
}

// ptermTable renders the table with pterm: bold header, rule under the header,
// no outer border, two spaces between columns.
func (r *Renderer) ptermTable(t Table, paint func(cells []string) string) error {
	var data pterm.TableData
	if len(t.Columns) > 0 {
		head := make([]string, len(t.Columns))
		for i, c := range sanitizeRow(t.Columns) {
			head[i] = c
			if r.color {
				head[i] = ptSnow.Sprint(pterm.Bold.Sprint(c))
			}
		}
		data = append(data, head)
	}
	for _, row := range t.Rows {
		cells := sanitizeRow(row)
		code := ""
		if paint != nil {
			code = paint(cells)
		}
		out := make([]string, len(cells))
		for i, c := range cells {
			out[i] = c
			if col := ptermColor(code); r.color && col != nil {
				out[i] = col.Sprint(c)
			}
		}
		data = append(data, out)
	}
	tp := pterm.DefaultTable.
		WithWriter(r.out).
		WithData(data).
		WithHasHeader(len(t.Columns) > 0).
		WithBoxed(false).
		WithSeparator("  ").
		WithLeftAlignment(true)
	// Without colour, the theme's styles must not leak escape codes into the table.
	plain := pterm.NewStyle()
	tp.Style = plain
	tp.HeaderStyle = plain
	tp.SeparatorStyle = plain
	tp.RowSeparatorStyle = plain
	tp.HeaderRowSeparatorStyle = plain
	if len(t.Columns) > 0 {
		tp.HeaderRowSeparator = "─"
	}
	s, err := tp.Srender()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(r.out, s)
	return err
}

// AutoColor reports whether human output to w should be coloured: a terminal, and
// NO_COLOR not set.
func AutoColor(w io.Writer) bool {
	return autoColor(FormatTable, w)
}
