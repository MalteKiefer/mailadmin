package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mailadmin/internal/backup"
	"mailadmin/internal/config"
)

// newBundle returns a bundle directory holding a config.toml.
func newBundle(t *testing.T) string {
	t.Helper()
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := os.MkdirAll(bundle, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, backup.ConfigFile), []byte("[mail]\nhostname = \"mx.example.com\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return bundle
}

// A refused config must stop the restore before the database or sieve step runs.
func TestRestorePreflightRefusesBeforeAnyChange(t *testing.T) {
	bundle := newBundle(t)
	live := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(live, []byte("mail:\n  hostname: old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The dump exists, so the database check passes and only the config can refuse.
	if err := os.WriteFile(filepath.Join(bundle, backup.DBDumpFile), []byte("dump"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Path: live}
	_, err := restorePreflight(cfg, bundle, backup.Manifest{}, []string{backup.ComponentDB, backup.ComponentConfig})
	if err == nil || !strings.Contains(err.Error(), "restore writes config.toml only") {
		t.Fatalf("preflight must refuse a YAML live config, got %v", err)
	}
}

// The database dump must exist before anything is restored.
func TestRestorePreflightNeedsDBDump(t *testing.T) {
	bundle := newBundle(t)
	if _, err := restorePreflight(&config.Config{Path: filepath.Join(bundle, "missing.toml")}, bundle, backup.Manifest{}, []string{backup.ComponentDB}); err == nil {
		t.Fatal("preflight must fail without db.dump")
	}
}

// Every sieve script the manifest names must be present before the restore starts.
func TestRestorePreflightNeedsSieveScripts(t *testing.T) {
	bundle := newBundle(t)
	man := backup.Manifest{SieveScripts: []string{"malte.kiefer@kiefer-networks.de"}}
	if _, err := restorePreflight(&config.Config{}, bundle, man, []string{backup.ComponentSieve}); err == nil {
		t.Fatal("preflight must fail when a sieve script is missing")
	}
	dir := filepath.Join(bundle, backup.SieveDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, backup.SieveFileName(man.SieveScripts[0])), []byte("keep;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := restorePreflight(&config.Config{}, bundle, man, []string{backup.ComponentSieve}); err != nil {
		t.Fatalf("preflight with all scripts present: %v", err)
	}
}

// A component that does not touch the config returns no merged config.
func TestRestorePreflightWithoutConfigComponent(t *testing.T) {
	bundle := newBundle(t)
	merged, err := restorePreflight(&config.Config{Path: filepath.Join(bundle, "config.toml")}, bundle, backup.Manifest{}, []string{backup.ComponentDKIM})
	if err != nil || merged != nil {
		t.Fatalf("merged = %q, err = %v; want nil, nil", merged, err)
	}
}
