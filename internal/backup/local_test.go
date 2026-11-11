package backup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPruneLocalBundlesKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"mailadmin-20261110T010000Z", "mailadmin-20261111T010000Z", "mailadmin-20261111T020000Z", "notes", "mailadmin-bogus"} {
		if err := os.MkdirAll(filepath.Join(dir, n), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := PruneLocalBundles(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != "mailadmin-20261110T010000Z" {
		t.Fatalf("removed = %v", removed)
	}
	for _, keep := range []string{"mailadmin-20261111T010000Z", "mailadmin-20261111T020000Z", "notes", "mailadmin-bogus"} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Fatalf("%s must stay: %v", keep, err)
		}
	}
}

func TestPruneLocalBundlesRefusesZero(t *testing.T) {
	if _, err := PruneLocalBundles(t.TempDir(), 0); err == nil {
		t.Fatal("keep 0 must be refused")
	}
}
