package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withStateDir(t *testing.T) string {
	t.Helper()
	old := StateDir
	StateDir = t.TempDir()
	t.Cleanup(func() { StateDir = old; EndJournal() })
	return StateDir
}

func TestJournalRestoresOriginalAndRemovesCreated(t *testing.T) {
	withStateDir(t)
	root := t.TempDir()
	existing := filepath.Join(root, "login.defs")
	created := filepath.Join(root, "new.conf")
	if err := os.WriteFile(existing, []byte("UMASK 022\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := BeginJournal("test"); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(existing, []byte("UMASK 027\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(created, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	EndJournal()

	m, err := LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 2 {
		t.Fatalf("files = %+v", m.Files)
	}
	for i := len(m.Files) - 1; i >= 0; i-- {
		if err := restoreFile(m.Files[i]); err != nil {
			t.Fatalf("restore %s: %v", m.Files[i].Path, err)
		}
	}
	got, _ := os.ReadFile(existing)
	if string(got) != "UMASK 022\n" {
		t.Fatalf("original content = %q", got)
	}
	if fi, _ := os.Stat(existing); fi.Mode().Perm() != 0o640 {
		t.Fatalf("original mode = %o", fi.Mode().Perm())
	}
	if _, err := os.Stat(created); !os.IsNotExist(err) {
		t.Fatal("a file install created must be removed")
	}
}

// A rerun of install must not replace the saved original with the file that the
// earlier run wrote.
func TestJournalRerunKeepsOriginal(t *testing.T) {
	withStateDir(t)
	root := t.TempDir()
	file := filepath.Join(root, "sysctl.conf")
	if err := os.WriteFile(file, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"first run\n", "second run\n"} {
		if err := BeginJournal("test"); err != nil {
			t.Fatal(err)
		}
		if err := writeAtomic(file, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		EndJournal()
	}
	m, err := LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 1 {
		t.Fatalf("a rerun must not duplicate records: %+v", m.Files)
	}
	if err := restoreFile(m.Files[0]); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(file); string(got) != "original\n" {
		t.Fatalf("restored %q, want the original from before the first run", got)
	}
}

func TestSummaryNamesWhatGoes(t *testing.T) {
	m := &Manifest{Version: "1.28.0", Packages: []string{"postfix"}, Users: []string{"vmail"},
		Database: "mail", Roles: []string{"postfix"}, NftTable: true}
	text := ""
	for _, l := range Summary(m) {
		text += l + "\n"
	}
	for _, want := range []string{"postfix", "vmail", "database mail", "nftables table inet mailadmin", "/var/vmail"} {
		if !strings.Contains(text, want) {
			t.Errorf("summary misses %q:\n%s", want, text)
		}
	}
}
