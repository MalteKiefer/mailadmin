package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mailadmin/defaults"
)

const testTOML = `[postgres]
service = "mail-admin"
[mail]
hostname = "mx.example.com"
dkim_dir = "/var/lib/rspamd/dkim"
default_selector = "mail2026"
[server]
ipv4 = "203.0.113.10"
[dns]
resolver = "1.1.1.1:53"
[backup]
dns_backup_dir = "/var/lib/mailadmin/dns-backups"
[logs]
units = ["postfix", "dovecot"]
`

const testYAML = `postgres:
  service: mail-admin
mail:
  hostname: mx.example.com
  dkim_dir: /var/lib/rspamd/dkim
  default_selector: mail2026
server:
  ipv4: 203.0.113.10
dns:
  resolver: 1.1.1.1:53
backup:
  dns_backup_dir: /var/lib/mailadmin/dns-backups
logs:
  units: [postfix, dovecot]
`

const testJSON = `{"postgres":{"service":"mail-admin"},
"mail":{"hostname":"mx.example.com","dkim_dir":"/var/lib/rspamd/dkim","default_selector":"mail2026"},
"server":{"ipv4":"203.0.113.10"},"dns":{"resolver":"1.1.1.1:53"},"backup":{"dns_backup_dir":"/var/lib/mailadmin/dns-backups"},
"logs":{"units":["postfix","dovecot"]}}`

func writeFile(t *testing.T, dir, name, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAllFormatsGiveSameConfig(t *testing.T) {
	for name, body := range map[string]string{"config.toml": testTOML, "config.yaml": testYAML, "config.json": testJSON} {
		dir := t.TempDir()
		p := writeFile(t, dir, name, body, 0o644)
		c, _, err := Load(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.Mail.Hostname != "mx.example.com" || c.Server.IPv4 != "203.0.113.10" || len(c.Logs.Units) != 2 {
			t.Fatalf("%s: got %+v", name, c)
		}
	}
}

func TestDiscoverRefusesSeveralFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.toml", testTOML, 0o644)
	writeFile(t, dir, "config.yaml", testYAML, 0o644)
	if _, err := Discover(dir); err == nil || !strings.Contains(err.Error(), "keep exactly one") {
		t.Fatalf("two config files must be refused, got %v", err)
	}
}

func TestDiscoverFindsOneFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := Discover(dir); err == nil {
		t.Fatal("empty directory must fail")
	}
	want := writeFile(t, dir, "config.yml", testYAML, 0o644)
	got, err := Discover(dir)
	if err != nil || got != want {
		t.Fatalf("Discover = %q, %v", got, err)
	}
}

func TestSecretsInConfigNeedOwnerOnlyMode(t *testing.T) {
	dir := t.TempDir()
	withSecrets := testTOML + "[secrets]\nRSPAMD_CONTROLLER_PW = \"pw\"\n"
	loose := writeFile(t, dir, "config.toml", withSecrets, 0o644)
	if _, _, err := Load(loose); err == nil {
		t.Fatal("a config with secrets must not be world readable")
	}
	if err := os.Chmod(loose, 0o600); err != nil {
		t.Fatal(err)
	}
	_, s, err := Load(loose)
	if err != nil {
		t.Fatalf("owner-only config: %v", err)
	}
	if s.RspamdControllerPW() != "pw" {
		t.Fatalf("secret = %q", s.RspamdControllerPW())
	}
}

func TestConfigSecretsWinOverLegacyFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "secrets.env", "DESEC_TOKEN=old\n", 0o600)
	p := writeFile(t, dir, "config.toml", testTOML+"[secrets]\nDESEC_TOKEN = \"new\"\n", 0o600)
	_, s, err := Load(p)
	if err != nil || s.DeSECToken() != "new" {
		t.Fatalf("token = %q, %v", s.DeSECToken(), err)
	}
}

func TestEmbeddedDefaultLoads(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, defaults.ConfigTOML, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(p); err != nil {
		t.Fatalf("the shipped default must load and validate after the example values are filled: %v", err)
	}
}
