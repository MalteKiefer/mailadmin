package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetMailKeyAddsOnceAndKeepsRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	src := "[postgres]\nservice = \"mail\"\n\n[mail]\nhostname = \"mx.example.com\"\n\n[server]\nipv4 = \"192.0.2.1\"\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetMailKey(path, "primary_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	if err := SetMailKey(path, "primary_domain", "other.example"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if strings.Count(s, "primary_domain") != 1 || !strings.Contains(s, "[mail]\nprimary_domain = \"example.com\"\nhostname") {
		t.Fatalf("unexpected config:\n%s", s)
	}
	if !strings.Contains(s, "[server]\nipv4 = \"192.0.2.1\"") {
		t.Fatalf("other tables changed:\n%s", s)
	}
}

func TestSetMailKeyRefusesConfigWithoutMailTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[server]\nipv4 = \"192.0.2.1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetMailKey(path, "primary_domain", "example.com"); err == nil {
		t.Fatal("config without [mail] must be refused")
	}
}
