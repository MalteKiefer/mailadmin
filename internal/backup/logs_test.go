package backup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectLogsCopiesOnlyExistingFiles(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(src, []byte("login ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "bundle")
	got, err := CollectLogs(bundle, []string{src, filepath.Join(dir, "missing.log")})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "auth.log" {
		t.Fatalf("copied = %v", got)
	}
	data, err := os.ReadFile(filepath.Join(bundle, LogsDir, "auth.log"))
	if err != nil || string(data) != "login ok\n" {
		t.Fatalf("copy = %q, %v", data, err)
	}
}

func TestLogsComponentIsValid(t *testing.T) {
	if !ValidComponent(ComponentLogs) {
		t.Fatal("logs must be a valid component")
	}
}
