// Package output is the one place mailadmin formats results. Handlers hand it
// structured data plus a chosen format (table|json|plain via -o); no command
// formats inline. This keeps presentation DRY and secret-free (callers pass
// already-redacted data).
package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jedib0t/go-pretty/v6/list"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"io"
	"os"
	"reflect"
	"strings"
	"text/tabwriter"

	"golang.org/x/term"
)

// ANSI SGR codes used for status colouring. Applied only on a colour-capable
// terminal (see Renderer.colorEnabled); never written into cell data (which is
// sanitized), so piped/JSON/plain output stays escape-free.
const (
	ansiReset   = "\x1b[0m"
	ansiBold    = "\x1b[1m"
	ansiRed     = "\x1b[31m"
	ansiGreen   = "\x1b[32m"
	ansiYellow  = "\x1b[33m"
	ansiBlue    = "\x1b[34m"
	ansiMagenta = "\x1b[35m"
	ansiCyan    = "\x1b[36m"
	ansiDim     = "\x1b[2m"
)

// recordTypeColor maps a DNS record type to a stable colour so a listing reads
// as grouped bands (all TXT one colour, all MX another, …).
func recordTypeColor(rtype string) string {
	switch strings.ToUpper(strings.TrimSpace(rtype)) {
	case "A", "AAAA":
		return ansiCyan
	case "CNAME":
		return ansiBlue
	case "MX":
		return ansiGreen
	case "TXT":
		return ansiYellow
	case "SRV":
		return ansiMagenta
	case "NS":
		return ansiBlue
	case "CAA":
		return ansiDim
	default:
		return ""
	}
}

// statusColor maps a status keyword to an SGR colour. Unknown keywords render
// uncoloured.
func statusColor(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "ok", "match", "active", "enabled", "unchanged", "yes", "present", "pass":
		return ansiGreen
	case "drift", "edit", "warn", "mismatch", "deferred", "hold", "skipped", "obsolete":
		return ansiYellow
	case "missing", "add", "error", "fail", "failed", "stale", "delete", "remove", "removed", "dkim-old", "no":
		return ansiRed
	case "info", "added", "created", "planned":
		return ansiCyan
	default:
		return ""
	}
}

// Format is the -o output mode.
type Format string

const (
	// FormatTable is the default aligned columnar output.
	FormatTable Format = "table"
	// FormatJSON emits machine-readable JSON.
	FormatJSON Format = "json"
	// FormatPlain emits tab-separated, header-less lines for scripting.
	FormatPlain Format = "plain"
)

// ErrUnknownFormat is returned for an unrecognised -o value.
var ErrUnknownFormat = errors.New("unknown output format")

// ParseFormat validates a -o flag value.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case FormatTable, FormatJSON, FormatPlain:
		return Format(s), nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnknownFormat, s)
	}
}

// Table is column-oriented data for tabular rendering. Rows must match Columns.
type Table struct {
	Columns []string
	Rows    [][]string
}

// Renderer writes results in the configured Format to a writer. It is the sole
// formatting authority; construct one per command invocation.
type Renderer struct {
	format Format
	out    io.Writer
	quiet  bool
	color  bool
}

// New builds a Renderer for the given format and writer. Colour is auto-enabled
// only for table output to a terminal with NO_COLOR unset.
func New(format Format, out io.Writer, quiet bool) *Renderer {
	return &Renderer{format: format, out: out, quiet: quiet, color: autoColor(format, out)}
}

// autoColor reports whether colour should be used: table format, a terminal
// writer, and NO_COLOR not set (https://no-color.org).
func autoColor(format Format, out io.Writer) bool {
	if format != FormatTable {
		return false
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	f, ok := out.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// SetColor overrides colour auto-detection (used by --color/--no-color).
func (r *Renderer) SetColor(on bool) { r.color = on && r.format == FormatTable }

// Format reports the renderer's configured output format so streaming callers
// (e.g. log tail) can pick a per-record rendering that suits the mode.
func (r *Renderer) Format() Format { return r.format }

// Table renders tabular data (table: aligned; json: array of objects keyed by
// column; plain: tab-separated rows).
func (r *Renderer) Table(t Table) error {
	switch r.format {
	case FormatJSON:
		return r.JSON(tableToObjects(t))
	case FormatPlain:
		return r.renderPlainTable(t)
	default:
		return r.renderAlignedTable(t)
	}
}

// StatusTable renders a table whose statusCol cell drives per-row colour
// (green=ok/match, yellow=drift, red=missing/stale, …). For json/plain it falls
// back to the plain Table rendering so scripting output is unaffected.
func (r *Renderer) StatusTable(t Table, statusCol int) error {
	if r.format != FormatTable || statusCol < 0 {
		return r.Table(t)
	}
	return r.writeTable(t, func(cells []string) text.Colors {
		if statusCol >= len(cells) {
			return nil
		}
		return ansiToText(statusColor(cells[statusCol]))
	})
}

// TypeTable renders a DNS record table whose typeCol cell (the record type)
// drives per-row colour, so the listing reads as colour-grouped bands. For
// json/plain it falls back to the plain Table rendering.
func (r *Renderer) TypeTable(t Table, typeCol int) error {
	if r.format != FormatTable || typeCol < 0 {
		return r.Table(t)
	}
	return r.writeTable(t, func(cells []string) text.Colors {
		if typeCol >= len(cells) {
			return nil
		}
		return ansiToText(recordTypeColor(cells[typeCol]))
	})
}

// writeTable renders t with go-pretty: aligned columns, bold header and per-row
// colour from paint when colour is on. Without colour no escape codes are written.
func (r *Renderer) writeTable(t Table, paint func(cells []string) text.Colors) error {
	tw := table.NewWriter()
	tw.SetOutputMirror(r.out)
	st := table.Style{
		Name: "mailadmin",
		Box: table.BoxStyle{
			PaddingLeft:   "",
			PaddingRight:  "  ",
			PageSeparator: "\n",
		},
		Options: table.Options{
			DrawBorder:      false,
			SeparateColumns: false,
			SeparateHeader:  false,
			SeparateRows:    false,
			SeparateFooter:  false,
		},
	}
	if r.color {
		st.Color = table.ColorOptions{Header: text.Colors{text.Bold}}
	}
	tw.SetStyle(st)
	if len(t.Columns) > 0 {
		tw.AppendHeader(toRow(sanitizeRow(t.Columns)))
	}
	for _, row := range t.Rows {
		tw.AppendRow(toRow(sanitizeRow(row)))
	}
	if r.color && paint != nil {
		tw.SetRowPainter(func(row table.Row) text.Colors {
			cells := make([]string, len(row))
			for i, v := range row {
				cells[i] = fmt.Sprint(v)
			}
			return paint(cells)
		})
	}
	tw.Render()
	return nil
}

func toRow(cells []string) table.Row {
	row := make(table.Row, len(cells))
	for i, c := range cells {
		row[i] = c
	}
	return row
}

// ansiToText maps the SGR codes used by statusColor and recordTypeColor to go-pretty colours.
func ansiToText(code string) text.Colors {
	switch code {
	case ansiGreen:
		return text.Colors{text.FgGreen}
	case ansiYellow:
		return text.Colors{text.FgYellow}
	case ansiRed:
		return text.Colors{text.FgRed}
	case ansiCyan:
		return text.Colors{text.FgCyan}
	case ansiMagenta:
		return text.Colors{text.FgMagenta}
	case ansiBlue:
		return text.Colors{text.FgBlue}
	}
	return nil
}

// JSON renders an arbitrary value as JSON. Used for single-object results and
// as the JSON path for Table/Value.
func (r *Renderer) JSON(v any) error {
	enc := json.NewEncoder(r.out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("output: encode json: %w", err)
	}
	return nil
}

// Value renders a single record: table/plain print key/value lines, json emits
// the object.
func (r *Renderer) Value(v any) error {
	if r.format == FormatJSON {
		return r.JSON(v)
	}
	return r.renderKV(v)
}

// Quiet reports whether status messages are suppressed (-q).
func (r *Renderer) Quiet() bool { return r.quiet }

// Message prints a human status line (suppressed when quiet, omitted for json).
func (r *Renderer) Message(format string, args ...any) {
	if r.quiet || r.format == FormatJSON {
		return
	}
	_, _ = fmt.Fprintf(r.out, format+"\n", args...)
}

// renderAlignedTable prints a header plus tab-aligned rows.
func (r *Renderer) renderAlignedTable(t Table) error {
	return r.writeTable(t, nil)
}

// renderPlainTable prints tab-separated rows with no header, for scripting.
func (r *Renderer) renderPlainTable(t Table) error {
	for _, row := range t.Rows {
		if _, err := fmt.Fprintln(r.out, strings.Join(sanitizeRow(row), "\t")); err != nil {
			return err
		}
	}
	return nil
}

// renderKV renders a struct/map as aligned "key  value" lines.
func (r *Renderer) renderKV(v any) error {
	fields := kvFields(v)
	tw := tabwriter.NewWriter(r.out, 0, 2, 2, ' ', 0)
	for _, f := range fields {
		if _, err := fmt.Fprintf(tw, "%s\t%s\n", f.key, sanitizeCell(f.val)); err != nil {
			return err
		}
	}
	return tw.Flush()
}

type kvField struct {
	key string
	val string
}

// kvFields flattens a struct or map into ordered key/value string pairs for the
// key/value renderer. Non-struct/map values render as a single value line.
func kvFields(v any) []kvField {
	rv := reflect.Indirect(reflect.ValueOf(v))
	if !rv.IsValid() {
		return []kvField{{key: "value", val: "<nil>"}}
	}
	switch rv.Kind() {
	case reflect.Struct:
		return structFields(rv)
	case reflect.Map:
		return mapFields(rv)
	default:
		return []kvField{{key: "value", val: fmt.Sprintf("%v", rv.Interface())}}
	}
}

func structFields(rv reflect.Value) []kvField {
	rt := rv.Type()
	out := make([]kvField, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		ft := rt.Field(i)
		if ft.PkgPath != "" { // unexported
			continue
		}
		out = append(out, kvField{key: fieldName(ft), val: fmt.Sprintf("%v", rv.Field(i).Interface())})
	}
	return out
}

func mapFields(rv reflect.Value) []kvField {
	keys := rv.MapKeys()
	out := make([]kvField, 0, len(keys))
	for _, k := range keys {
		out = append(out, kvField{key: fmt.Sprintf("%v", k.Interface()), val: fmt.Sprintf("%v", rv.MapIndex(k).Interface())})
	}
	return out
}

// fieldName prefers the json tag name so key/value output matches JSON output.
func fieldName(ft reflect.StructField) string {
	tag := ft.Tag.Get("json")
	if tag == "" || tag == "-" {
		return ft.Name
	}
	if comma := strings.IndexByte(tag, ','); comma >= 0 {
		tag = tag[:comma]
	}
	if tag == "" {
		return ft.Name
	}
	return tag
}

// tableToObjects converts a Table into []map for JSON so column names become
// keys. Cells beyond the column count are dropped; short rows get empty cells.
func tableToObjects(t Table) []map[string]string {
	out := make([]map[string]string, 0, len(t.Rows))
	for _, row := range t.Rows {
		obj := make(map[string]string, len(t.Columns))
		for i, col := range t.Columns {
			if i < len(row) {
				obj[col] = row[i]
			} else {
				obj[col] = ""
			}
		}
		out = append(out, obj)
	}
	return out
}

// sanitizeRow strips control characters from every cell so rendered output
// cannot smuggle terminal escapes or break tab/newline alignment.
func sanitizeRow(row []string) []string {
	out := make([]string, len(row))
	for i, c := range row {
		out[i] = sanitizeCell(c)
	}
	return out
}

func sanitizeCell(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' || (r < 0x20) || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// Heading prints a bold section line when colour is on, plain text otherwise.
func (r *Renderer) Heading(s string) {
	if r.quiet || r.format == FormatJSON {
		return
	}
	if r.color {
		s = ansiBold + s + ansiReset
	}
	_, _ = fmt.Fprintln(r.out, s)
}

// List renders items as a bulleted list (go-pretty). json and plain print one item
// per line, so scripts get the same values.
func (r *Renderer) List(items []string) error {
	if r.format != FormatTable {
		for _, it := range items {
			if _, err := fmt.Fprintln(r.out, sanitizeCell(it)); err != nil {
				return err
			}
		}
		return nil
	}
	lw := list.NewWriter()
	lw.SetOutputMirror(r.out)
	lw.SetStyle(list.StyleBulletCircle)
	for _, it := range items {
		lw.AppendItem(sanitizeCell(it))
	}
	lw.Render()
	return nil
}
