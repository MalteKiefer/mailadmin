package backup

import (
	"os"
	"path/filepath"
	"testing"
)

// A symlinked subdirectory inside the destination must not redirect CopyTree's
// writes outside the destination tree.
func TestCopyTreeRefusesSymlinkedDestinationDir(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "src")
	dst := filepath.Join(base, "dst")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(src, "sub"), outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "x"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dst, "sub")); err != nil {
		t.Fatal(err)
	}

	if _, err := CopyTree(src, dst); err == nil {
		t.Fatal("CopyTree followed a symlinked destination directory")
	}
	if _, err := os.Stat(filepath.Join(outside, "x")); err == nil {
		t.Fatal("file was written outside the destination tree")
	}
}

// CopyFile refuses a symlink at the destination, CopyFileFollow writes through
// it. The restore of an operator-managed config.toml relies on the latter.
func TestCopyFileFollowWritesThroughSymlink(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "bundle-config.toml")
	realTarget := filepath.Join(base, "managed.toml")
	link := filepath.Join(base, "config.toml")
	if err := os.WriteFile(src, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(realTarget, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realTarget, link); err != nil {
		t.Fatal(err)
	}

	if _, err := CopyFile(src, link); err == nil {
		t.Fatal("CopyFile wrote through a symlink")
	}
	if _, err := CopyFileFollow(src, link); err != nil {
		t.Fatalf("CopyFileFollow: %v", err)
	}
	got, err := os.ReadFile(realTarget)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("link target = %q, want %q", got, "new")
	}
}
