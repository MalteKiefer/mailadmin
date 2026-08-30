package backup

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeBundle(t *testing.T, root, name string, tm time.Time) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	m := NewManifest("dev", []string{ComponentDB})
	m.CreatedAt = tm.UTC()
	if err := WriteManifest(dir, m); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, DBDumpFile), "not-a-real-dump-but-has-bytes")
	return dir
}

func TestListBundlesNewestFirst(t *testing.T) {
	root := t.TempDir()
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)

	makeBundle(t, root, BundleName(t1), t1)
	makeBundle(t, root, BundleName(t3), t3)
	makeBundle(t, root, BundleName(t2), t2)

	// A non-bundle directory (no manifest.json) must be ignored.
	if err := os.MkdirAll(filepath.Join(root, "not-a-bundle"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A stray file at the top level must also be ignored.
	writeFile(t, filepath.Join(root, "stray.txt"), "x")

	got, err := ListBundles(root)
	if err != nil {
		t.Fatalf("ListBundles: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len(got) = %d, want 3", len(got))
	}
	if got[0].Name != BundleName(t3) || got[1].Name != BundleName(t2) || got[2].Name != BundleName(t1) {
		t.Fatalf("order = %v, want newest-first", []string{got[0].Name, got[1].Name, got[2].Name})
	}
	for _, b := range got {
		if b.ManifestErr != nil {
			t.Errorf("bundle %s: unexpected ManifestErr: %v", b.Name, b.ManifestErr)
		}
		if b.Bytes <= 0 {
			t.Errorf("bundle %s: Bytes = %d, want > 0", b.Name, b.Bytes)
		}
	}
}

func TestListBundlesMissingDir(t *testing.T) {
	got, err := ListBundles(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatalf("ListBundles on missing dir: %v", err)
	}
	if got != nil {
		t.Fatalf("got = %v, want nil", got)
	}
}

func TestListBundlesBrokenManifestStillListed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "mailadmin-broken")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, ManifestFile), "{not valid json")

	got, err := ListBundles(root)
	if err != nil {
		t.Fatalf("ListBundles: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	if got[0].ManifestErr == nil {
		t.Fatal("expected ManifestErr for a broken manifest.json")
	}
}
