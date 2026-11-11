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
	added, err := MergeNewKeys(path, []byte(mergeDefaults))
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	want := []string{"backup.borg.enabled", "backup.borg.retention.daily", "mail.dns_ttl", "timeouts.command"}
	if strings.Join(added, ",") != strings.Join(want, ",") {
		t.Fatalf("added = %v, want %v", added, want)
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
	again, err := MergeNewKeys(path, []byte(mergeDefaults))
	if err != nil || len(again) != 0 {
		t.Fatalf("second merge = %v, %v; want nothing to add", again, err)
	}
}

func TestMergeNewKeysRefusesYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("mail:\n  hostname: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MergeNewKeys(path, []byte(mergeDefaults)); err == nil {
		t.Fatal("YAML config must not be merged")
	}
}
