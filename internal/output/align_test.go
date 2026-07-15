package output

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

// TestStatusTableAlignment renders a coloured status table and confirms that,
// once ANSI codes are stripped, every column starts at the same offset — i.e.
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
	if len(lines) != 4 {
		t.Fatalf("want 4 lines, got %d", len(lines))
	}
	// Verify ANSI is actually present (colour on) but stripped for measuring.
	if !strings.Contains(buf.String(), "\x1b[") {
		t.Fatal("expected ANSI colour codes in output")
	}
	col2 := -1
	for _, ln := range lines {
		plain := ansiRE.ReplaceAllString(ln, "")
		if strings.ContainsRune(plain, '\xff') {
			t.Fatalf("tabwriter escape byte leaked into output: %q", plain)
		}
		idx := firstColStart(plain) // offset of the 2nd column, measured uniformly
		if col2 == -1 {
			col2 = idx
		} else if idx != col2 {
			t.Fatalf("column 2 misaligned: got offset %d, want %d in line %q", idx, col2, plain)
		}
	}
}

// firstColStart returns the offset where the second whitespace-separated column
// begins (i.e. end of first field + following spaces).
func firstColStart(s string) int {
	i := strings.IndexByte(s, ' ')
	if i < 0 {
		return 0
	}
	for i < len(s) && s[i] == ' ' {
		i++
	}
	return i
}
