package valid

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathUnder(t *testing.T) {
	root := t.TempDir()

	// A real file directly under root.
	inFile := filepath.Join(root, "example.com", "user")
	if err := os.MkdirAll(inFile, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	msgPath := filepath.Join(inFile, "message")
	if err := os.WriteFile(msgPath, []byte("hi"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// A file outside root, used as a traversal/symlink target.
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	t.Run("absolute path under root resolves", func(t *testing.T) {
		got, err := PathUnder(root, msgPath)
		if err != nil {
			t.Fatalf("PathUnder: %v", err)
		}
		want, _ := filepath.EvalSymlinks(msgPath)
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("relative path resolves under root", func(t *testing.T) {
		got, err := PathUnder(root, filepath.Join("example.com", "user", "message"))
		if err != nil {
			t.Fatalf("PathUnder: %v", err)
		}
		want, _ := filepath.EvalSymlinks(msgPath)
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("dot-dot traversal rejected", func(t *testing.T) {
		traversal := filepath.Join(root, "example.com", "user", "..", "..", "..", filepath.Base(outsideDir), "secret")
		if _, err := PathUnder(root, traversal); err == nil {
			t.Fatalf("expected error for traversal path")
		}
	})

	t.Run("absolute path outside root rejected", func(t *testing.T) {
		if _, err := PathUnder(root, outsideFile); err == nil {
			t.Fatalf("expected error for path outside root")
		}
	})

	t.Run("nonexistent path rejected", func(t *testing.T) {
		if _, err := PathUnder(root, filepath.Join(root, "nope", "nothing")); err == nil {
			t.Fatalf("expected error for nonexistent path")
		}
	})

	t.Run("empty path rejected", func(t *testing.T) {
		if _, err := PathUnder(root, ""); err == nil {
			t.Fatalf("expected error for empty path")
		}
	})

	t.Run("symlink escape rejected", func(t *testing.T) {
		link := filepath.Join(root, "escape")
		if err := os.Symlink(outsideFile, link); err != nil {
			t.Skipf("symlink not supported in this environment: %v", err)
		}
		if _, err := PathUnder(root, link); err == nil {
			t.Fatalf("expected error for symlink escaping root")
		}
	})

	t.Run("root itself resolves", func(t *testing.T) {
		if _, err := PathUnder(root, root); err != nil {
			t.Fatalf("PathUnder(root): %v", err)
		}
	})
}
