package install

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// Paths of the mount hardening mailadmin owns.
const (
	FstabPath    = "/etc/fstab"
	TmpMountConf = "/etc/systemd/system/tmp.mount.d/mailadmin.conf"
)

// fstabMountLines are the entries that hide other users' processes on /proc and
// forbid executing files from the shared-memory and temp filesystems.
var fstabMountLines = []struct{ prefix, line string }{
	{"proc /proc", "proc /proc proc defaults,hidepid=2 0 0"},
	{"tmpfs /dev/shm", "tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0"},
}

// FstabWithMountHardening adds the mount lines that are missing. Existing lines
// are not touched, so a changed operator entry wins over this one.
func FstabWithMountHardening(existing string) string {
	out := strings.TrimRight(existing, "\n")
	for _, m := range fstabMountLines {
		if !hasFstabPrefix(existing, m.prefix) {
			out += "\n" + m.line
		}
	}
	return out + "\n"
}

func hasFstabPrefix(content, prefix string) bool {
	for _, l := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), prefix) {
			return true
		}
	}
	return false
}

// TmpMountConfContent sets noexec, nosuid and nodev on /tmp through a unit drop-in.
func TmpMountConfContent() string {
	return "# Managed by mailadmin install.\n[Mount]\nOptions=mode=1777,strictatime,nosuid,nodev,noexec\n"
}

// ApplyMountHardening persists the mount options and applies them to the running
// system: /proc, /dev/shm and /tmp are remounted.
func ApplyMountHardening(ctx context.Context, x Exec) error {
	cur, err := os.ReadFile(FstabPath) // #nosec G304 -- fixed system path
	if err != nil {
		return fmt.Errorf("read %s: %w", FstabPath, err)
	}
	if want := FstabWithMountHardening(string(cur)); want != string(cur) {
		if err := writeAtomic(FstabPath, []byte(want), 0o644); err != nil {
			return err
		}
	}
	if err := os.MkdirAll("/etc/systemd/system/tmp.mount.d", 0o755); err != nil { // #nosec G301 -- systemd drop-in dir
		return err
	}
	if err := writeAtomic(TmpMountConf, []byte(TmpMountConfContent()), 0o644); err != nil {
		return err
	}
	if _, err := x.Run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	for _, args := range [][]string{
		{"mount", "-o", "remount,hidepid=2", "/proc"},
		{"mount", "-o", "remount,nosuid,nodev,noexec", "/dev/shm"},
		{"mount", "-o", "remount,nosuid,nodev,noexec", "/tmp"},
	} {
		if _, err := x.Run(ctx, nil, args...); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(args, " "), err)
		}
	}
	return nil
}
