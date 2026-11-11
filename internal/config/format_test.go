package config

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestFormatTOMLNormalisesLayout(t *testing.T) {
	in := "# head\n\n\n[mail]\n   hostname   =   \"mx.example.com\"   \n\n\n\n# keep this\ndns_ttl=3600\n[server]\n\tipv4 = \"192.0.2.1\"\n"
	got := FormatTOML(in)
	want := "# head\n\n[mail]\nhostname = \"mx.example.com\"\n\n# keep this\ndns_ttl = 3600\n\n[server]\nipv4 = \"192.0.2.1\"\n"
	if got != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
	if FormatTOML(got) != got {
		t.Fatal("formatter is not idempotent")
	}
	var m map[string]any
	if _, err := toml.Decode(got, &m); err != nil {
		t.Fatalf("formatted output does not parse: %v", err)
	}
}

func TestFormatTOMLKeepsMultiLineArrays(t *testing.T) {
	in := "[logs]\nunits = [\n    \"postfix\",\n      \"dovecot\",\n]\n"
	got := FormatTOML(in)
	if !strings.Contains(got, "    \"postfix\",\n      \"dovecot\",\n]") {
		t.Fatalf("multi-line array changed:\n%s", got)
	}
}
