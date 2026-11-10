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
