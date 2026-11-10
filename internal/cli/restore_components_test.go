package cli

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"mailadmin/internal/backup"
	"mailadmin/internal/config"
	"mailadmin/internal/output"
)

// A failed component stops the restore, and the completed ones are reported so the
// audit record and the domain sync cover what already changed.
func TestRestoreComponentsReportsCompletedBeforeFailure(t *testing.T) {
	bundle := newBundle(t)
	live := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(live, []byte("[mail]\nhostname = \"old\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Path: live}
	merged := []byte("[mail]\nhostname = \"mx.example.com\"\n\n[secrets]\nDESEC_TOKEN = \"tok\"\n")
	// The sieve script named by the manifest is not in the bundle: the step fails
	// after the config has been written.
	man := backup.Manifest{SieveScripts: []string{"malte.kiefer@kiefer-networks.de"}}
	a := &App{}
	r := output.New(output.FormatTable, io.Discard, true)
	done, err := a.restoreComponents(&cobra.Command{}, cfg, bundle, man,
		[]string{backup.ComponentConfig, backup.ComponentSieve}, merged, r)
	if err == nil {
		t.Fatal("sieve step must fail on the missing script")
	}
	if !reflect.DeepEqual(done, []string{backup.ComponentConfig}) {
		t.Fatalf("completed = %v, want [config]", done)
	}
	got, _ := os.ReadFile(live)
	if !strings.Contains(string(got), "mx.example.com") {
		t.Fatalf("config step did not write:\n%s", got)
	}
}
