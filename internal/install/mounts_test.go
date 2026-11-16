package install

import (
	"strings"
	"testing"
)

func TestFstabGetsHidepidAndNoexecOnce(t *testing.T) {
	in := "UUID=x / ext4 errors=remount-ro 0 1\n"
	got := FstabWithMountHardening(in)
	for _, want := range []string{"proc /proc proc defaults,hidepid=2", "tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q:\n%s", want, got)
		}
	}
	if FstabWithMountHardening(got) != got {
		t.Fatal("not idempotent")
	}
}

func TestFstabKeepsOperatorEntry(t *testing.T) {
	in := "proc /proc proc defaults 0 0\n"
	got := FstabWithMountHardening(in)
	if strings.Count(got, "proc /proc") != 1 {
		t.Fatalf("operator proc entry must not be duplicated:\n%s", got)
	}
}

func TestTmpMountIsNoexec(t *testing.T) {
	if !strings.Contains(TmpMountConfContent(), "noexec") {
		t.Fatal("/tmp must be noexec")
	}
}
