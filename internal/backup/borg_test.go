package backup

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseRepo(t *testing.T) {
	ssh, host, port, err := ParseRepo("ssh://u715884@u715884.your-storagebox.de:23/./borg-repo")
	if err != nil || !ssh || host != "u715884.your-storagebox.de" || port != "23" {
		t.Fatalf("ssh repo: %v %v %q %q", ssh, host, port, err)
	}
	if _, _, port, _ := ParseRepo("ssh://u@h/x"); port != "22" {
		t.Fatalf("default port = %q, want 22", port)
	}
	if ssh, _, _, err := ParseRepo("/srv/borg"); err != nil || ssh {
		t.Fatalf("local repo: %v %v", ssh, err)
	}
	for _, bad := range []string{"relative/path", "ssh://nouser-host/x", "http://x"} {
		if _, _, _, err := ParseRepo(bad); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
}

func TestCheckDue(t *testing.T) {
	stamp := filepath.Join(t.TempDir(), "checked")
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	if due, _ := CheckDue(stamp, "1w", now); !due {
		t.Fatal("no stamp: check is due")
	}
	if err := MarkChecked(stamp, now.Add(-3*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if due, _ := CheckDue(stamp, "1w", now); due {
		t.Fatal("checked 3 days ago with 1w: not due")
	}
	if due, _ := CheckDue(stamp, "2d", now); !due {
		t.Fatal("checked 3 days ago with 2d: due")
	}
	if due, _ := CheckDue(stamp, "", now); due {
		t.Fatal("empty check_every means never")
	}
	if _, err := CheckDue(stamp, "soon", now); err == nil {
		t.Fatal("bad check_every must be refused")
	}
	_ = os.Remove(stamp)
}

func TestArchiveNameIsPrefixedAndSortable(t *testing.T) {
	a := ArchiveName(time.Date(2026, 11, 11, 10, 5, 0, 0, time.UTC))
	if a != "mailadmin-20261111T100500Z" {
		t.Fatalf("archive name = %q", a)
	}
}
