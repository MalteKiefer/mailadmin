package backup

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCopyTreeCopiesNestedFiles(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	dst := filepath.Join(t.TempDir(), "dst")

	writeFile(t, filepath.Join(src, "a.key"), "AAAA")
	writeFile(t, filepath.Join(src, "sub", "b.key.pub"), "BBBBBB")

	res, err := CopyTree(src, dst)
	if err != nil {
		t.Fatalf("CopyTree: %v", err)
	}
	if res.Files != 2 {
		t.Fatalf("Files = %d, want 2", res.Files)
	}
	if res.Bytes != int64(len("AAAA")+len("BBBBBB")) {
		t.Fatalf("Bytes = %d, want %d", res.Bytes, len("AAAA")+len("BBBBBB"))
	}

	got, err := os.ReadFile(filepath.Join(dst, "sub", "b.key.pub"))
	if err != nil {
		t.Fatalf("read copied file: %v", err)
	}
	if string(got) != "BBBBBB" {
		t.Fatalf("copied content = %q, want %q", got, "BBBBBB")
	}
}

func TestCopyTreeMissingSrcIsNotError(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "dst")
	res, err := CopyTree(filepath.Join(t.TempDir(), "does-not-exist"), dst)
	if err != nil {
		t.Fatalf("CopyTree on missing src: %v", err)
	}
	if res.Files != 0 {
		t.Fatalf("Files = %d, want 0", res.Files)
	}
}

func TestCopyTreeSrcNotADirectory(t *testing.T) {
	src := filepath.Join(t.TempDir(), "file.txt")
	writeFile(t, src, "x")
	if _, err := CopyTree(src, filepath.Join(t.TempDir(), "dst")); err == nil {
		t.Fatal("expected error when src is a regular file, not a directory")
	}
}

func TestCopyFilePreservesContent(t *testing.T) {
	src := filepath.Join(t.TempDir(), "config.toml")
	writeFile(t, src, "[mail]\nhostname = \"mail.example.com\"\n")
	dst := filepath.Join(t.TempDir(), "nested", "out.toml")

	n, err := CopyFile(src, dst)
	if err != nil {
		t.Fatalf("CopyFile: %v", err)
	}
	body, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if int64(len(body)) != n {
		t.Fatalf("returned n=%d, actual file len=%d", n, len(body))
	}
}

func TestCopyFileRejectsNonRegular(t *testing.T) {
	dir := t.TempDir()
	if _, err := CopyFile(dir, filepath.Join(t.TempDir(), "out")); err == nil {
		t.Fatal("expected error copying a directory as if it were a file")
	}
}

func TestDirSize(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	writeFile(t, filepath.Join(dir, "a"), "12345")
	writeFile(t, filepath.Join(dir, "sub", "b"), "12")

	n, err := DirSize(dir)
	if err != nil {
		t.Fatalf("DirSize: %v", err)
	}
	if n != 7 {
		t.Fatalf("DirSize = %d, want 7", n)
	}
}

func TestDirSizeMissingIsZero(t *testing.T) {
	n, err := DirSize(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatalf("DirSize on missing dir: %v", err)
	}
	if n != 0 {
		t.Fatalf("DirSize = %d, want 0", n)
	}
}
