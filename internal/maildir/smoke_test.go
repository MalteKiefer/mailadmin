package maildir

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, p, msgid string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "From: a@b\r\nSubject: x\r\n\r\nbody\r\n"
	if msgid != "" {
		body = "From: a@b\r\nMessage-ID: <" + msgid + ">\r\nSubject: x\r\n\r\nbody\r\n"
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDedupeSmoke(t *testing.T) {
	root := t.TempDir()
	box := filepath.Join(root, "example.com", "alice", "Maildir")
	write(t, filepath.Join(box, "cur", "m1"), "id-A")
	write(t, filepath.Join(box, "cur", "m2"), "id-B")
	write(t, filepath.Join(box, "new", "m3"), "id-A")
	write(t, filepath.Join(box, ".Sent", "cur", "m4"), "id-B")
	write(t, filepath.Join(box, "cur", "m5"), "")

	m := New(root)
	dry, err := m.Dedupe("alice", "example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if dry.Kept != 2 || dry.Deleted != 2 || dry.Skipped != 1 {
		t.Fatalf("dry: %+v", dry)
	}
	real, err := m.Dedupe("alice", "example.com", false)
	if err != nil || real.Deleted != 2 {
		t.Fatalf("real: %+v err=%v", real, err)
	}
	again, _ := m.Dedupe("alice", "example.com", true)
	if again.Deleted != 0 {
		t.Fatalf("again should have 0 deleted: %+v", again)
	}
	if _, e := m.Dedupe("../../etc", "x", true); e == nil {
		t.Fatal("expected escape rejection")
	}
	if _, e := m.Dedupe("nobody", "example.com", true); e == nil {
		t.Fatal("expected not found")
	}
}
