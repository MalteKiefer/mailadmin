// Package output is the one place mailadmin formats results. Handlers hand it
// structured data plus a chosen format (table|json|plain via -o); no command
// formats inline. This keeps presentation DRY and secret-free (callers pass
// already-redacted data).
package output

import (
	"encoding/json"
	"errors"
	"fmt"
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
	case "drift", "edit", "warn", "mismatch", "deferred", "hold":
		return ansiYellow
	case "missing", "add", "error", "fail", "failed", "stale", "delete", "remove", "removed", "dkim-old", "no":
		return ansiRed
	case "info", "added", "created":
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
	if r.format != FormatTable || !r.color || statusCol < 0 {
		return r.Table(t)
	}
	// Column widths are measured over the plain (uncoloured) text; colour is
	// applied only after padding, so ANSI codes never affect alignment. This
	// avoids tabwriter's brittle escape handling entirely for the coloured path.
	widths := columnWidths(t)
	if len(t.Columns) > 0 {
		if _, err := fmt.Fprintln(r.out, colorize(padCells(sanitizeRow(t.Columns), widths), ansiBold)); err != nil {
			return err
		}
	}
	for _, row := range t.Rows {
		cells := sanitizeRow(row)
		code := ""
		if statusCol < len(cells) {
			code = statusColor(cells[statusCol])
		}
		if _, err := fmt.Fprintln(r.out, colorize(padCells(cells, widths), code)); err != nil {
			return err
		}
	}
	return nil
}

// TypeTable renders a DNS record table whose typeCol cell (the record type)
// drives per-row colour, so the listing reads as colour-grouped bands. For
// json/plain it falls back to the plain Table rendering.
func (r *Renderer) TypeTable(t Table, typeCol int) error {
	if r.format != FormatTable || !r.color || typeCol < 0 {
		return r.Table(t)
	}
	widths := columnWidths(t)
	if len(t.Columns) > 0 {
		if _, err := fmt.Fprintln(r.out, colorize(padCells(sanitizeRow(t.Columns), widths), ansiBold)); err != nil {
			return err
		}
	}
	for _, row := range t.Rows {
		cells := sanitizeRow(row)
		code := ""
		if typeCol < len(cells) {
			code = recordTypeColor(cells[typeCol])
		}
		if _, err := fmt.Fprintln(r.out, colorize(padCells(cells, widths), code)); err != nil {
			return err
		}
	}
	return nil
}

// columnWidths returns the max plain-text width of each column across the header
// and all rows.
func columnWidths(t Table) []int {
	n := len(t.Columns)
	for _, row := range t.Rows {
		if len(row) > n {
			n = len(row)
		}
	}
	w := make([]int, n)
	measure := func(cells []string) {
		for i, c := range cells {
			if l := len([]rune(sanitizeCell(c))); l > w[i] {
				w[i] = l
			}
		}
	}
	measure(t.Columns)
	for _, row := range t.Rows {
		measure(row)
	}
	return w
}

// padCells right-pads each cell to its column width and joins with two spaces.
// The trailing column is not padded.
func padCells(cells []string, widths []int) string {
	var b strings.Builder
	for i, c := range cells {
		if i > 0 {
			b.WriteString("  ")
		}
		b.WriteString(c)
		if i < len(cells)-1 && i < len(widths) {
			if pad := widths[i] - len([]rune(c)); pad > 0 {
				b.WriteString(strings.Repeat(" ", pad))
			}
		}
	}
	return b.String()
}

// colorize wraps a fully-laid-out line in an SGR code (no-op when empty).
func colorize(line, code string) string {
	if code == "" {
		return line
	}
	return code + line + ansiReset
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

// Message prints a human status line (suppressed when quiet, omitted for json).
func (r *Renderer) Message(format string, args ...any) {
	if r.quiet || r.format == FormatJSON {
		return
	}
	_, _ = fmt.Fprintf(r.out, format+"\n", args...)
}

// renderAlignedTable prints a header plus tab-aligned rows.
func (r *Renderer) renderAlignedTable(t Table) error {
	// The bold header would upset tabwriter's width counting, so when colour is
	// on render the whole table through the manual layout (no per-row colour,
	// just a bold header). Otherwise use tabwriter for plain aligned output.
	if r.color && len(t.Columns) > 0 {
		widths := columnWidths(t)
		if _, err := fmt.Fprintln(r.out, colorize(padCells(sanitizeRow(t.Columns), widths), ansiBold)); err != nil {
			return err
		}
		for _, row := range t.Rows {
			if _, err := fmt.Fprintln(r.out, padCells(sanitizeRow(row), widths)); err != nil {
				return err
			}
		}
		return nil
	}
	tw := tabwriter.NewWriter(r.out, 0, 2, 2, ' ', 0)
	if len(t.Columns) > 0 {
		if _, err := fmt.Fprintln(tw, strings.Join(t.Columns, "\t")); err != nil {
			return err
		}
	}
	for _, row := range t.Rows {
		if _, err := fmt.Fprintln(tw, strings.Join(sanitizeRow(row), "\t")); err != nil {
			return err
		}
	}
	return tw.Flush()
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
