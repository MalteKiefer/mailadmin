package output

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

// TestStatusTableAlignment renders a coloured status table and confirms that,
// once ANSI codes are stripped, every column starts at the same offset, i.e.
// the escape bytes are not counted toward tabwriter width.
func TestStatusTableAlignment(t *testing.T) {
	var buf bytes.Buffer
	r := New(FormatTable, &buf, false)
	r.SetColor(true) // force colour even though buf is not a terminal
	tbl := Table{
		Columns: []string{"STATUS", "TYPE", "NAME"},
		Rows: [][]string{
			{"drift", "MX", "@"},
			{"missing", "TXT", "mail2026._domainkey"},
			{"remove", "MX", "@"},
		},
	}
	if err := r.StatusTable(tbl, 0); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	// header, rule under the header, three rows
	if len(lines) != 5 {
		t.Fatalf("want 5 lines, got %d", len(lines))
	}
	// Verify ANSI is actually present (colour on) but stripped for measuring.
	if !strings.Contains(buf.String(), "\x1b[") {
		t.Fatal("expected ANSI colour codes in output")
	}
	col2 := -1
	for _, ln := range lines {
		plain := ansiRE.ReplaceAllString(ln, "")
		if strings.HasPrefix(plain, "─") {
			continue // the rule under the header has no columns
		}
		if strings.ContainsRune(plain, '\xff') {
			t.Fatalf("tabwriter escape byte leaked into output: %q", plain)
		}
		// Offset of the TYPE column: the status cell may carry an icon, so the
		// first space is not a reliable anchor.
		idx := typeColStart(plain)
		if col2 == -1 {
			col2 = idx
		} else if idx != col2 {
			t.Fatalf("column 2 misaligned: got offset %d, want %d in line %q", idx, col2, plain)
		}
	}
}


// typeColStart returns the offset of the TYPE column value in a rendered line.
func typeColStart(s string) int {
	for _, w := range []string{"TYPE", "MX", "TXT"} {
		if i := strings.Index(s, w); i >= 0 {
			return utf8.RuneCountInString(s[:i]) // columns are measured in runes
		}
	}
	return -1
}
