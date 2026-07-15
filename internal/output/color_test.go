package output

import "testing"

func TestStatusColor(t *testing.T) {
	cases := map[string]string{
		"match": ansiGreen, "ok": ansiGreen,
		"drift": ansiYellow, "edit": ansiYellow,
		"missing": ansiRed, "stale": ansiRed, "failed": ansiRed,
		"weird": "",
	}
	for in, want := range cases {
		if got := statusColor(in); got != want {
			t.Errorf("statusColor(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAutoColorNonTerminal(t *testing.T) {
	// A bytes.Buffer is not an *os.File terminal → colour must stay off even for
	// table format, so piped/redirected output never gets ANSI escapes.
	if autoColor(FormatTable, &nopWriter{}) {
		t.Fatal("autoColor must be false for a non-terminal writer")
	}
	if autoColor(FormatJSON, &nopWriter{}) {
		t.Fatal("autoColor must be false for json")
	}
}

type nopWriter struct{}

func (*nopWriter) Write(p []byte) (int, error) { return len(p), nil }
