package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

const mergeDefaults = `[mail]
# Required. Public FQDN.
hostname = "mail.example.com"
dns_ttl = 3600

[backup]
dir = "/var/lib/mailadmin/backups"

[backup.borg]
enabled = false
[backup.borg.retention]
daily = 7

[timeouts]
command = "30s"

[secrets]
DESEC_TOKEN = ""
`

func TestMergeNewKeysAddsMissingAndKeepsOperatorValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	host := "# operator note\n[mail]\n# keep me\nhostname = \"mx.kiefer.example\"\n\n[backup]\ndir = \"/srv/backups\"\n\n[secrets]\nRSPAMD_CONTROLLER_PW = \"pw\"\n"
	if err := os.WriteFile(path, []byte(host), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := MergeNewKeys(path, []byte(mergeDefaults), "v1.33.0")
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	want := []string{"backup.borg.enabled", "backup.borg.retention.daily", "mail.dns_ttl", "timeouts.command"}
	if strings.Join(res.Added, ",") != strings.Join(want, ",") {
		t.Fatalf("added = %v, want %v", res.Added, want)
	}
	got, _ := os.ReadFile(path)
	s := string(got)
	for _, must := range []string{"# operator note", "# keep me", `hostname = "mx.kiefer.example"`, `dir = "/srv/backups"`, `RSPAMD_CONTROLLER_PW = "pw"`} {
		if !strings.Contains(s, must) {
			t.Fatalf("operator content %q lost:\n%s", must, s)
		}
	}
	if strings.Contains(s, "DESEC_TOKEN") {
		t.Fatalf("[secrets] defaults must not be added:\n%s", s)
	}
	var check map[string]any
	if _, err := toml.Decode(s, &check); err != nil {
		t.Fatalf("merged file does not parse: %v\n%s", err, s)
	}
	if mail := check["mail"].(map[string]any); mail["dns_ttl"] != int64(3600) {
		t.Fatalf("dns_ttl not placed under [mail]: %v", mail)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 600", fi.Mode().Perm())
	}
	again, err := MergeNewKeys(path, []byte(mergeDefaults), "v1.33.0")
	if err != nil || len(again.Added) != 0 || len(again.Obsolete) != 0 {
		t.Fatalf("second merge = %+v, %v; want no change", again, err)
	}
}

func TestMergeNewKeysRefusesYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("mail:\n  hostname: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MergeNewKeys(path, []byte(mergeDefaults), "v1.33.0"); err == nil {
		t.Fatal("YAML config must not be merged")
	}
}

// A key the release dropped stays in place, with a marker line above it.
func TestMergeNewKeysMarksObsoleteKeepsValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	host := "[mail]\nhostname = \"mx.example.com\"\nold_knob = 7\ndns_ttl = 300\n\n[mail.legacy]\nflag = true\n"
	if err := os.WriteFile(path, []byte(host), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := MergeNewKeys(path, []byte(mergeDefaults), "v1.33.0")
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if strings.Join(res.Obsolete, ",") != "mail.legacy.flag,mail.old_knob" {
		t.Fatalf("obsolete = %v", res.Obsolete)
	}
	got, _ := os.ReadFile(path)
	s := string(got)
	if !strings.Contains(s, "# obsolete since v1.33.0: no longer read, safe to remove\nold_knob = 7") {
		t.Fatalf("marker missing:\n%s", s)
	}
	if !strings.Contains(s, `dns_ttl = 300`) {
		t.Fatalf("operator value changed:\n%s", s)
	}
	again, _ := MergeNewKeys(path, []byte(mergeDefaults), "v1.33.0")
	if len(again.Obsolete) != 0 {
		t.Fatalf("marker added twice: %+v", again)
	}
	raw, _ := os.ReadFile(path)
	if strings.Count(string(raw), "# obsolete since") != 2 {
		t.Fatalf("expected two markers:\n%s", raw)
	}
}

// A config with odd layout is rewritten in the canonical layout even when no key
// is missing, and a second run changes nothing.
func TestMergeNewKeysFormatsEveryRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	host := "[mail]\nhostname   =   \"mx.example.com\"\ndns_ttl = 3600\nquota_default = 5368709120\ndefault_selector = \"mail2026\"\ndkim_dir = \"/var/lib/rspamd/dkim\"\ntls_mode = \"acme\"\n\n\n\n[notify]\n  url = \"\"\n\n[backup]\ndir = \"/var/lib/mailadmin/backups\"\n\n[backup.borg]\nenabled = false\n[backup.borg.retention]\ndaily = 7\n\n[timeouts]\ncommand = \"30s\"\n"
	if err := os.WriteFile(path, []byte(host), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MergeNewKeys(path, []byte(mergeDefaults), "v1.34.0"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if strings.Contains(string(got), "   =") || strings.Contains(string(got), "\n\n\n") || strings.Contains(string(got), "  url") {
		t.Fatalf("layout not normalised:\n%s", got)
	}
	again, _ := os.ReadFile(path)
	if _, err := MergeNewKeys(path, []byte(mergeDefaults), "v1.34.0"); err != nil {
		t.Fatal(err)
	}
	final, _ := os.ReadFile(path)
	if string(again) != string(final) {
		t.Fatalf("second run changed the file:\n%s", final)
	}
}
