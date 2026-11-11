package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// With dns.config_repo set, direct DNS writes are refused before anything is sent.
func TestRefuseRepoManagedDNS(t *testing.T) {
	raw, err := os.ReadFile("../../defaults/config.default.toml")
	if err != nil {
		t.Fatal(err)
	}
	base := strings.Replace(string(raw), "hostname = \"mail.example.com\"", "hostname = \"mx.example.com\"", 1)
	base = strings.Replace(base, "ipv4 = \"203.0.113.10\"", "ipv4 = \"192.0.2.1\"", 1)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")

	write := func(text string) *App {
		if err := os.WriteFile(cfgPath, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return &App{flags: globalFlags{configPath: cfgPath}}
	}
	withRepo := strings.Replace(base, `config_repo = ""`, `config_repo = "/srv/dns"`, 1)
	if err := write(withRepo).refuseRepoManagedDNS(nil); err == nil {
		t.Fatal("direct DNS write must be refused when dns.config_repo is set")
	}
	if err := write(base).refuseRepoManagedDNS(nil); err != nil {
		t.Fatalf("without config_repo writes stay allowed: %v", err)
	}
}
