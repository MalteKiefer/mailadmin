package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const testDefault = `
[mail]
hostname = "mx.example.com"
new_key = 1

[hardening]
system = true
new_flag = false

[secrets]
DESEC_TOKEN = ""
`

func writeHost(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNewDefaultKeysFindsMissingKeys(t *testing.T) {
	host := writeHost(t, "config.toml", "[mail]\nhostname = \"mx.example.com\"\n\n[hardening]\nsystem = true\n")
	got, err := NewDefaultKeys(host, []byte(testDefault))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"hardening.new_flag", "mail.new_key"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("missing = %v, want %v", got, want)
	}
}

func TestNewDefaultKeysSkipsSecrets(t *testing.T) {
	host := writeHost(t, "config.toml", "[mail]\nhostname = \"x\"\nnew_key = 1\n\n[hardening]\nsystem = true\nnew_flag = true\n")
	got, err := NewDefaultKeys(host, []byte(testDefault))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("nothing missing expected, got %v", got)
	}
}

func TestNewDefaultKeysReadsYAMLHost(t *testing.T) {
	host := writeHost(t, "config.yaml", "mail:\n  hostname: mx.example.com\nhardening:\n  system: true\n")
	got, err := NewDefaultKeys(host, []byte(testDefault))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"hardening.new_flag", "mail.new_key"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("missing = %v, want %v", got, want)
	}
}

func TestNewDefaultKeysRejectsBrokenDefault(t *testing.T) {
	host := writeHost(t, "config.toml", "[mail]\n")
	if _, err := NewDefaultKeys(host, []byte("[mail\n")); err == nil {
		t.Fatal("broken default config must be an error")
	}
}
