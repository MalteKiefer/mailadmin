package rspamdconf

import (
	"errors"
	"strings"
	"testing"
)

func TestParseBytesRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"single newline only", "\n"},
		{"no trailing newline", "timeout = 300s;"},
		{"trailing newline", "timeout = 300s;\n"},
		{"comments and blank lines", "# header comment\n\ntimeout = 300s; # inline\n\n# footer\n"},
		{"block with nested keys", "rates {\n  to = \"20 / 1min\";\n  to_ip = \"20 / 1min\";\n}\n"},
		{"mixed top-level and block", "# greylist tuning\ntimeout = 300s;\nexpire = 1d;\n\nrates {\n  to = \"20 / 1min\";\n}\n"},
		{"crlf line endings", "timeout = 300s;\r\nexpire = 1d;\r\n"},
		{"weird but harmless lines pass through", "include \"other.conf\";\nsome garbage that is not key=value\n"},
		{"block without semicolon close", "rates {\n  to = \"20 / 1min\";\n}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			doc := Parse([]byte(tt.in))
			got := string(doc.Bytes())
			if got != tt.in {
				t.Fatalf("round trip mismatch:\n got: %q\nwant: %q", got, tt.in)
			}
		})
	}
}

func TestDocumentGet(t *testing.T) {
	t.Parallel()
	content := []byte("# header\ntimeout = 300s;\nexpire = 1d;\n\nrates {\n  to = \"20 / 1min\";\n  to_ip = \"20 / 1min\";\n}\n")
	doc := Parse(content)

	tests := []struct {
		key       string
		wantValue string
		wantFound bool
	}{
		{"timeout", "300s", true},
		{"expire", "1d", true},
		{"rates.to", `"20 / 1min"`, true},
		{"rates.to_ip", `"20 / 1min"`, true},
		{"rates.bounce_to", "", false},
		{"nonexistent", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			t.Parallel()
			v, ok := doc.Get(tt.key)
			if ok != tt.wantFound || v != tt.wantValue {
				t.Fatalf("Get(%q) = (%q, %v), want (%q, %v)", tt.key, v, ok, tt.wantValue, tt.wantFound)
			}
		})
	}
}

func TestDocumentSetExistingKeyPreservesEverythingElse(t *testing.T) {
	t.Parallel()
	content := "# rate limits\nrates {\n  to = \"20 / 1min\"; # default\n  to_ip = \"20 / 1min\";\n}\n# footer comment\n"
	doc := Parse([]byte(content))

	old, err := doc.Set("rates.to", `"50 / 1min"`)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if old != `"20 / 1min"` {
		t.Fatalf("old value = %q, want %q", old, `"20 / 1min"`)
	}

	want := "# rate limits\nrates {\n  to = \"50 / 1min\"; # default\n  to_ip = \"20 / 1min\";\n}\n# footer comment\n"
	got := string(doc.Bytes())
	if got != want {
		t.Fatalf("Bytes() =\n%q\nwant\n%q", got, want)
	}
}

func TestDocumentSetTopLevelExistingKey(t *testing.T) {
	t.Parallel()
	content := "timeout = 300s;\nexpire = 1d;\n"
	doc := Parse([]byte(content))

	old, err := doc.Set("timeout", "10m")
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if old != "300s" {
		t.Fatalf("old = %q, want 300s", old)
	}
	want := "timeout = 10m;\nexpire = 1d;\n"
	if got := string(doc.Bytes()); got != want {
		t.Fatalf("Bytes() = %q, want %q", got, want)
	}

	// expire must be untouched.
	if v, ok := doc.Get("expire"); !ok || v != "1d" {
		t.Fatalf("expire = (%q, %v), want (1d, true)", v, ok)
	}
}

func TestDocumentSetMissingKeyInExistingBlockAppendsBeforeClose(t *testing.T) {
	t.Parallel()
	content := "rates {\n  to = \"20 / 1min\";\n}\n"
	doc := Parse([]byte(content))

	old, err := doc.Set("rates.bounce_to", `"5 / 1h"`)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if old != "" {
		t.Fatalf("old = %q, want empty (key was absent)", old)
	}

	want := "rates {\n  to = \"20 / 1min\";\n  bounce_to = \"5 / 1h\";\n}\n"
	if got := string(doc.Bytes()); got != want {
		t.Fatalf("Bytes() = %q, want %q", got, want)
	}

	// Now settable/gettable in place.
	if v, ok := doc.Get("rates.bounce_to"); !ok || v != `"5 / 1h"` {
		t.Fatalf("rates.bounce_to = (%q, %v)", v, ok)
	}
}

func TestDocumentSetMissingKeyNoBlockCreatesBlock(t *testing.T) {
	t.Parallel()
	content := "# no rates block yet\n"
	doc := Parse([]byte(content))

	old, err := doc.Set("rates.to", `"20 / 1min"`)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if old != "" {
		t.Fatalf("old = %q, want empty", old)
	}

	want := "# no rates block yet\nrates {\n  to = \"20 / 1min\";\n}\n"
	if got := string(doc.Bytes()); got != want {
		t.Fatalf("Bytes() = %q, want %q", got, want)
	}
}

func TestDocumentSetMissingTopLevelKeyAppends(t *testing.T) {
	t.Parallel()
	content := "# greylist\nexpire = 1d;\n"
	doc := Parse([]byte(content))

	old, err := doc.Set("timeout", "300s")
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if old != "" {
		t.Fatalf("old = %q, want empty", old)
	}
	want := "# greylist\nexpire = 1d;\ntimeout = 300s;\n"
	if got := string(doc.Bytes()); got != want {
		t.Fatalf("Bytes() = %q, want %q", got, want)
	}
}

func TestDocumentSetUnsupportedNestedKey(t *testing.T) {
	t.Parallel()
	doc := Parse([]byte("a { b { c = 1; } }\n"))
	if _, err := doc.Set("a.b.c", "2"); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("err = %v, want ErrUnsupportedKey", err)
	}
}

func TestDocumentSetOnEmptyFile(t *testing.T) {
	t.Parallel()
	doc := Parse([]byte(""))
	if _, err := doc.Set("timeout", "300s"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	want := "timeout = 300s;\n"
	if got := string(doc.Bytes()); got != want {
		t.Fatalf("Bytes() = %q, want %q", got, want)
	}
}

func TestDocumentSetDoesNotAffectUnrelatedSimilarKeyNames(t *testing.T) {
	t.Parallel()
	// "to" and "to_ip" must not collide via prefix matching.
	content := "rates {\n  to = \"1 / 1m\";\n  to_ip = \"2 / 1m\";\n}\n"
	doc := Parse([]byte(content))
	if _, err := doc.Set("rates.to", `"9 / 1m"`); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if v, _ := doc.Get("rates.to_ip"); v != `"2 / 1m"` {
		t.Fatalf("rates.to_ip = %q, want unchanged", v)
	}
}

func TestNestedObjectInBlock(t *testing.T) {
	doc := Parse([]byte("rates {\n  to = {\n    burst = 100;\n  }\n  to_ip = \"100 / 1s\";\n}\n"))
	if v, ok := doc.Get("rates.to_ip"); !ok || v != `"100 / 1s"` {
		t.Fatalf("rates.to_ip = %q, %v", v, ok)
	}
	if _, err := doc.Set("rates.to_ip", `"50 / 1m"`); err != nil {
		t.Fatal(err)
	}
	if got := string(doc.Bytes()); !strings.Contains(got, "  to_ip = \"50 / 1m\";\n}") {
		t.Fatalf("set landed in the wrong block:\n%s", got)
	}
}
