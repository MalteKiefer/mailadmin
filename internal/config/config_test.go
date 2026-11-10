package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validConfig returns a Config that passes Validate, for mutation in tests.
func validConfig() Config {
	return Config{
		Postgres: Postgres{Service: "mail-admin", ServiceFile: "/var/lib/mailadmin/.pg_service.conf"},
		Mail:     Mail{Hostname: "mail.example.com", DKIMDir: "/var/lib/rspamd/dkim", DefaultSelector: "mail2026"},
		Server:   Server{IPv4: "203.0.113.10", IPv6: "2001:db8::10"},
		DNS:      DNS{Resolver: "1.1.1.1:53"},
		Backup:   Backup{DNSBackupDir: "/var/lib/mailadmin/dns-backups"},
		Logs:     Logs{Units: []string{"postfix", "dovecot"}},
		Path:     "/etc/mailadmin/config.toml",
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"valid", func(*Config) {}, false},
		{"valid no ipv6", func(c *Config) { c.Server.IPv6 = "" }, false},
		{"missing postgres service", func(c *Config) { c.Postgres.Service = "" }, true},
		{"relative service file", func(c *Config) { c.Postgres.ServiceFile = "rel/path" }, true},
		{"missing hostname", func(c *Config) { c.Mail.Hostname = "" }, true},
		{"bad hostname", func(c *Config) { c.Mail.Hostname = "not a host" }, true},
		{"relative dkim dir", func(c *Config) { c.Mail.DKIMDir = "dkim" }, true},
		{"missing selector", func(c *Config) { c.Mail.DefaultSelector = "" }, true},
		{"bad selector", func(c *Config) { c.Mail.DefaultSelector = "BAD SEL" }, true},
		{"missing ipv4", func(c *Config) { c.Server.IPv4 = "" }, true},
		{"ipv6 in ipv4 field", func(c *Config) { c.Server.IPv4 = "2001:db8::1" }, true},
		{"bad ipv4", func(c *Config) { c.Server.IPv4 = "999.1.1.1" }, true},
		{"ipv4 in ipv6 field", func(c *Config) { c.Server.IPv6 = "203.0.113.10" }, true},
		{"bad ipv6", func(c *Config) { c.Server.IPv6 = "nope" }, true},
		{"missing resolver", func(c *Config) { c.DNS.Resolver = "" }, true},
		{"resolver no port", func(c *Config) { c.DNS.Resolver = "1.1.1.1" }, true},
		{"resolver bad port", func(c *Config) { c.DNS.Resolver = "1.1.1.1:70000" }, true},
		{"resolver non-numeric port", func(c *Config) { c.DNS.Resolver = "1.1.1.1:dns" }, true},
		{"relative backup dir", func(c *Config) { c.Backup.DNSBackupDir = "backups" }, true},
		{"no log units", func(c *Config) { c.Logs.Units = nil }, true},
		{"bad log unit", func(c *Config) { c.Logs.Units = []string{"ok", "bad unit!"} }, true},
		{"notify url unset is fine", func(c *Config) { c.Notify.URL = "" }, false},
		{"notify url https ok", func(c *Config) { c.Notify.URL = "https://notify.example.com/mailadmin" }, false},
		{"notify url http ok", func(c *Config) { c.Notify.URL = "http://notify.internal/mailadmin" }, false},
		{"notify url missing scheme", func(c *Config) { c.Notify.URL = "notify.example.com/mailadmin" }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mutate(&c)
			err := c.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error not wrapped with ErrInvalidConfig: %v", err)
			}
		})
	}
}

func TestDSN(t *testing.T) {
	c := validConfig()
	if got, want := c.DSN(), "service=mail-admin"; got != want {
		t.Fatalf("DSN() = %q, want %q", got, want)
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	env := map[string]string{
		"MAILADMIN_POSTGRES_SERVICE": "other-svc",
		"MAILADMIN_MAIL_HOSTNAME":    "mx.override.test",
		"MAILADMIN_SERVER_IPV4":      "198.51.100.5",
		"MAILADMIN_DNS_RESOLVER":     "9.9.9.9:53",
		"MAILADMIN_LOGS_UNITS":       "postfix, rspamd ,, caddy",
		"MAILADMIN_NOTIFY_URL":       "https://notify.override.test/mailadmin",
	}
	getenv := func(k string) string { return env[k] }

	c := validConfig()
	c.applyEnvOverrides(getenv)
	if c.Postgres.Service != "other-svc" {
		t.Errorf("postgres service not overridden: %q", c.Postgres.Service)
	}
	if c.Mail.Hostname != "mx.override.test" {
		t.Errorf("hostname not overridden: %q", c.Mail.Hostname)
	}
	if c.Server.IPv4 != "198.51.100.5" {
		t.Errorf("ipv4 not overridden: %q", c.Server.IPv4)
	}
	if c.DNS.Resolver != "9.9.9.9:53" {
		t.Errorf("resolver not overridden: %q", c.DNS.Resolver)
	}
	want := []string{"postfix", "rspamd", "caddy"}
	if strings.Join(c.Logs.Units, ",") != strings.Join(want, ",") {
		t.Errorf("units = %v, want %v", c.Logs.Units, want)
	}
	if c.Notify.URL != "https://notify.override.test/mailadmin" {
		t.Errorf("notify url not overridden: %q", c.Notify.URL)
	}
}

func TestApplyEnvOverridesEmptyKeepsExisting(t *testing.T) {
	c := validConfig()
	orig := c.Mail.Hostname
	c.applyEnvOverrides(func(string) string { return "" })
	if c.Mail.Hostname != orig {
		t.Fatalf("empty env should not change hostname: %q", c.Mail.Hostname)
	}
}

func TestParseEnvLine(t *testing.T) {
	tests := []struct {
		in       string
		key, val string
		ok       bool
	}{
		{"NJALLA_TOKEN=abc123", "NJALLA_TOKEN", "abc123", true},
		{"  RSPAMD_CONTROLLER_PW = s3cr et ", "RSPAMD_CONTROLLER_PW", "s3cr et", true},
		{`KEY="quoted value"`, "KEY", "quoted value", true},
		{"KEY='single'", "KEY", "single", true},
		{"export NJALLA_TOKEN=xyz", "NJALLA_TOKEN", "xyz", true},
		{"# a comment", "", "", false},
		{"", "", "", false},
		{"   ", "", "", false},
		{"noequals", "", "", false},
		{"=noKey", "", "", false},
		{`KEY="only-leading-quote`, "KEY", `"only-leading-quote`, true},
		{"KEY=", "KEY", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			key, val, ok := parseEnvLine(tt.in)
			if ok != tt.ok || key != tt.key || val != tt.val {
				t.Fatalf("parseEnvLine(%q) = (%q,%q,%v), want (%q,%q,%v)",
					tt.in, key, val, ok, tt.key, tt.val, tt.ok)
			}
		})
	}
}

func TestLoadSecretsMissingFile(t *testing.T) {
	s, err := LoadSecrets(filepath.Join(t.TempDir(), "absent.env"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if s.HasNjalla() || s.RspamdControllerPW() != "" {
		t.Fatalf("expected empty secrets, got njalla=%v rspamd=%v", s.HasNjalla(), s.RspamdControllerPW() != "")
	}
}

func TestLoadSecretsParsesAndEnforcesMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	content := "# secrets\nNJALLA_TOKEN=tok-123\nRSPAMD_CONTROLLER_PW=\"pw with space\"\nNTFY_TOKEN=tok-ntfy\nUNKNOWN=ignored\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadSecrets(path)
	if err != nil {
		t.Fatalf("LoadSecrets: %v", err)
	}
	if s.NjallaToken() != "tok-123" {
		t.Errorf("njalla token = %q", s.NjallaToken())
	}
	if s.RspamdControllerPW() != "pw with space" {
		t.Errorf("rspamd pw = %q", s.RspamdControllerPW())
	}
	if !s.HasNjalla() {
		t.Error("HasNjalla() = false, want true")
	}
	if s.NtfyToken() != "tok-ntfy" {
		t.Errorf("ntfy token = %q", s.NtfyToken())
	}
	if !s.HasNtfy() {
		t.Error("HasNtfy() = false, want true")
	}
}

func TestLoadSecretsRejectsLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	if err := os.WriteFile(path, []byte("NJALLA_TOKEN=x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadSecrets(path)
	if err == nil || !errors.Is(err, ErrInsecureSecrets) {
		t.Fatalf("expected ErrInsecureSecrets, got %v", err)
	}
}

func TestLoadSecretsRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.env")
	if err := os.WriteFile(target, []byte("NJALLA_TOKEN=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "secrets.env")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	_, err := LoadSecrets(link)
	if err == nil || !errors.Is(err, ErrInsecureSecrets) {
		t.Fatalf("expected ErrInsecureSecrets for symlink, got %v", err)
	}
}

func TestSecretsNeverLeak(t *testing.T) {
	s := &Secrets{njallaToken: "SUPER-SECRET-TOKEN", rspamdControllPW: "PW-VALUE"}
	for _, format := range []string{"%v", "%s", "%+v", "%#v"} {
		out := fmt.Sprintf(format, s)
		if strings.Contains(out, "SUPER-SECRET-TOKEN") || strings.Contains(out, "PW-VALUE") {
			t.Fatalf("secret leaked via %s: %q", format, out)
		}
		if !strings.Contains(out, "REDACTED") {
			t.Fatalf("expected REDACTED marker via %s: %q", format, out)
		}
	}
}

func TestViewRedactsSecrets(t *testing.T) {
	c := validConfig()
	s := &Secrets{njallaToken: "tok", rspamdControllPW: ""}
	v := View(&c, s)
	if !v.NjallaConfigured {
		t.Error("NjallaConfigured should be true")
	}
	if v.RspamdConfigured {
		t.Error("RspamdConfigured should be false")
	}
	if v.PostgresService != c.Postgres.Service || v.MailHostname != c.Mail.Hostname {
		t.Error("view did not copy config fields")
	}
}

func TestInitWritesAndRefusesOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mailadmin")
	body := []byte("[postgres]\nservice = \"mail-admin\"\n")
	cfgPath, err := Init(dir, body, false)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	fi, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %#o, want 0600 (it can hold secrets)", fi.Mode().Perm())
	}
	if _, err := Init(dir, body, false); err == nil {
		t.Fatal("expected Init to refuse overwrite without force")
	}
	if _, err := Init(dir, body, true); err != nil {
		t.Fatalf("force must replace: %v", err)
	}
}

func TestCheckReportsState(t *testing.T) {
	dir := t.TempDir()
	// Write a valid on-disk config + secrets so Check finds real paths.
	dkim := filepath.Join(dir, "dkim")
	backups := filepath.Join(dir, "dns-backups")
	if err := os.MkdirAll(dkim, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(backups, 0o755); err != nil {
		t.Fatal(err)
	}
	secPath := filepath.Join(dir, "secrets.env")
	if err := os.WriteFile(secPath, []byte("NJALLA_TOKEN=t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The config file holds the secrets since v1.28: the check reads its mode.
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[mail]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := validConfig()
	c.Path = filepath.Join(dir, "config.toml")
	c.Mail.DKIMDir = dkim
	c.Backup.DNSBackupDir = backups
	c.Postgres.ServiceFile = "" // exercise the "not set" branch

	s := &Secrets{njallaToken: "t"}
	results, err := Check(&c, s)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	byName := map[string]CheckResult{}
	for _, r := range results {
		byName[r.Name] = r
	}
	for _, name := range []string{"config", "dkim_dir", "dns_backup_dir", "secrets_file", "njalla_token", "notify_url"} {
		r, ok := byName[name]
		if !ok {
			t.Fatalf("missing check %q", name)
		}
		if !r.OK {
			t.Errorf("check %q not OK: %s", name, r.Detail)
		}
	}
	if byName["rspamd_controller_pw"].OK {
		t.Error("rspamd_controller_pw should be not-configured")
	}
	// Optional settings pass when unset, but still say they are not configured.
	for _, name := range []string{"ntfy_token", "desec_token", "cloudflare_api_token"} {
		if r := byName[name]; !r.OK || !strings.Contains(r.Detail, "not configured") {
			t.Errorf("%s: optional and unset should pass as not configured, got ok=%v %q", name, r.OK, r.Detail)
		}
	}
	// No secret value must appear in any detail string.
	for _, r := range results {
		if strings.Contains(r.Detail, "t") && r.Name == "njalla_token" && strings.Contains(r.Detail, "\"t\"") {
			t.Errorf("secret value leaked in detail: %q", r.Detail)
		}
	}
}
