package rspamd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"mailadmin/internal/valid"
)

func TestServiceResolvePath(t *testing.T) {
	root := t.TempDir()
	mailboxDir := filepath.Join(root, "example.com", "user", "Maildir", "cur")
	if err := os.MkdirAll(mailboxDir, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	msgPath := filepath.Join(mailboxDir, "1700000000.M123P456.mail")
	if err := os.WriteFile(msgPath, []byte("From: a@b\n\nhi"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	dirPath := filepath.Join(root, "example.com", "user")

	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "secret")
	if err := os.WriteFile(outsideFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	svc := New(nil, root)

	t.Run("file under root resolves", func(t *testing.T) {
		got, err := svc.resolvePath(msgPath)
		if err != nil {
			t.Fatalf("resolvePath: %v", err)
		}
		want, _ := filepath.EvalSymlinks(msgPath)
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("relative path under root resolves", func(t *testing.T) {
		rel := filepath.Join("example.com", "user", "Maildir", "cur", filepath.Base(msgPath))
		if _, err := svc.resolvePath(rel); err != nil {
			t.Fatalf("resolvePath(%q): %v", rel, err)
		}
	})

	t.Run("directory is rejected (not a regular file)", func(t *testing.T) {
		if _, err := svc.resolvePath(dirPath); err == nil {
			t.Fatalf("expected error for a directory path")
		}
	})

	t.Run("path outside root is rejected", func(t *testing.T) {
		if _, err := svc.resolvePath(outsideFile); err == nil {
			t.Fatalf("expected error for path outside root")
		}
	})

	t.Run("traversal is rejected", func(t *testing.T) {
		traversal := filepath.Join(root, "example.com", "..", "..", filepath.Base(outside), "secret")
		if _, err := svc.resolvePath(traversal); err == nil {
			t.Fatalf("expected error for traversal path")
		}
	})

	t.Run("missing file is rejected", func(t *testing.T) {
		if _, err := svc.resolvePath(filepath.Join(root, "nope")); err == nil {
			t.Fatalf("expected error for missing file")
		}
	})
}

func TestServiceDefaultRoot(t *testing.T) {
	svc := New(nil, "")
	if svc.root != filepath.Clean("/var/vmail") {
		t.Errorf("default root = %q, want /var/vmail", svc.root)
	}
}

func TestWrapDetail(t *testing.T) {
	sentinel := errors.New("boom")

	if got := wrapDetail(sentinel, nil); !errors.Is(got, sentinel) {
		t.Errorf("wrapDetail(nil stderr) lost sentinel: %v", got)
	}
	if got := wrapDetail(sentinel, []byte("  ")); got.Error() != sentinel.Error() {
		t.Errorf("wrapDetail(blank stderr) = %q, want %q", got.Error(), sentinel.Error())
	}
	got := wrapDetail(sentinel, []byte(" learn failed: no such symbol \n"))
	if !errors.Is(got, sentinel) {
		t.Errorf("wrapDetail lost sentinel: %v", got)
	}
	want := "boom: learn failed: no such symbol"
	if got.Error() != want {
		t.Errorf("wrapDetail() = %q, want %q", got.Error(), want)
	}
}

// learnDispatchesOnSource is a compile-time/documentation check that a bare
// queue id and a filesystem path are distinguished purely via valid.QueueID
// (no path separator survives that regex), matching the dispatch in learn().
func TestQueueIDVsPathDispatch(t *testing.T) {
	tests := []struct {
		source    string
		isQueueID bool
	}{
		{"3F1A2B4C5D", true},
		{"AAAA11", true},
		{"/var/vmail/example.com/user/Maildir/cur/123.mail", false},
		{"example.com/user/Maildir/cur/123.mail", false},
		{"../../etc/passwd", false},
	}
	for _, tt := range tests {
		_, err := valid.QueueID(tt.source)
		got := err == nil
		if got != tt.isQueueID {
			t.Errorf("valid.QueueID(%q) treated as queue id = %v, want %v", tt.source, got, tt.isQueueID)
		}
	}
}
