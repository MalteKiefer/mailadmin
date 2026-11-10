package maildir

import "testing"

// A mailbox path must stay strictly inside the mail root: "..", "." and any
// name that resolves to the root itself are refused, so a purge can never
// remove the whole tree.
func TestPathRefusesRootEscapes(t *testing.T) {
	m := &Manager{root: t.TempDir()}
	for _, c := range [][2]string{{"..", "example.com"}, {".", "example.com"}, {"alice", ".."}, {"x", "."}} {
		if _, err := m.path(c[0], c[1]); err == nil {
			t.Fatalf("path(%q, %q) accepted", c[0], c[1])
		}
	}
	if _, err := m.path("alice", "example.com"); err != nil {
		t.Fatalf("valid mailbox refused: %v", err)
	}
}
