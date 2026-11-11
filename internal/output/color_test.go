package output

import (
	"strings"
	"testing"

	"github.com/pterm/pterm"
)

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

func TestStatusIcon(t *testing.T) {
	cases := map[string]string{"ok": "✔", "drift": "⚠", "missing": "✖", "info": "ℹ", "weird": ""}
	for in, want := range cases {
		if got := statusIcon(in); got != want {
			t.Errorf("statusIcon(%q)=%q want %q", in, got, want)
		}
	}
}

func TestHighlightCodeKeepsText(t *testing.T) {
	// pterm turns colour off without a terminal; the test forces it on.
	pterm.EnableColor()
	defer pterm.DisableColor()
	line := `    MX("@", 10, "mxext1.mailbox.org."),`
	plain := ansiRE.ReplaceAllString(highlightCode(line), "")
	if plain != line {
		t.Fatalf("highlight changed the text:\n got %q\nwant %q", plain, line)
	}
	if !strings.Contains(highlightCode(line), "\x1b[") {
		t.Fatal("expected colour codes on a DNSControl statement")
	}
	if highlightCode("plain text") != "plain text" {
		t.Fatal("non-statement lines must stay unchanged")
	}
}

func TestPromptTextYellow(t *testing.T) {
	pterm.EnableColor()
	defer pterm.DisableColor()
	if PromptText("Proceed? [y/N]: ", false) != "Proceed? [y/N]: " {
		t.Fatal("no colour when color is off")
	}
	if !strings.Contains(PromptText("Proceed?", true), "\x1b[") {
		t.Fatal("prompt must be coloured when color is on")
	}
}
