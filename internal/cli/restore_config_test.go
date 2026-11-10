package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mailadmin/internal/backup"
	"mailadmin/internal/config"
)

// The restore of config.toml is the one step that can drop live secrets. It must
// keep the live [secrets] table when the bundle copy has none.
func TestRestoreConfigKeepsLiveSecrets(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(live, []byte("[mail]\nhostname = \"old.example.com\"\n\n[secrets]\nDESEC_TOKEN = \"live-tok\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "bundle")
	if err := os.MkdirAll(bundle, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, backup.ConfigFile), []byte("[mail]\nhostname = \"mx.example.com\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	a := &App{}
	if err := a.restoreConfig(nil, &config.Config{Path: live}, bundle); err != nil {
		t.Fatalf("restoreConfig: %v", err)
	}
	got, err := os.ReadFile(live)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "live-tok") || !strings.Contains(string(got), "mx.example.com") {
		t.Fatalf("restored config wrong:\n%s", got)
	}
	fi, err := os.Stat(live)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 600", fi.Mode().Perm())
	}
}
