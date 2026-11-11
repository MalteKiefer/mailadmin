package install

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// Borg timer units. The timer runs `mailadmin backup borg run` on the schedule of
// [backup.borg]. The run needs root for the ssh key and the config secrets.
const (
	BorgService     = "mailadmin-borg.service"
	BorgTimer       = "mailadmin-borg.timer"
	BorgServicePath = "/etc/systemd/system/" + BorgService
	BorgTimerPath   = "/etc/systemd/system/" + BorgTimer
)

// BorgServiceFile renders the oneshot unit that archives the backups.
func BorgServiceFile() string {
	return fmt.Sprintf(`# Managed by mailadmin install.
[Unit]
Description=Archive mailadmin backups to the borg repository
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=%s backup borg run
`, PasswordHelper)
}

// BorgTimerFile renders the timer for schedule (a systemd OnCalendar expression).
func BorgTimerFile(schedule string) string {
	return fmt.Sprintf(`# Managed by mailadmin install.
[Unit]
Description=Schedule for the mailadmin borg archive

[Timer]
OnCalendar=%s
Persistent=true

[Install]
WantedBy=timers.target
`, schedule)
}

// ApplyBorgTimer makes the borg timer match the config. When borg is on it validates
// schedule with systemd-analyze, writes both units, reloads systemd, enables the timer
// and restarts it so a changed schedule takes effect. When borg is off it stops and
// disables the timer and removes its units.
func ApplyBorgTimer(ctx context.Context, x Exec, enabled bool, schedule string) error {
	if !enabled {
		return removeBorgTimer(ctx, x)
	}
	if _, err := x.Run(ctx, nil, "systemd-analyze", "calendar", schedule); err != nil {
		return fmt.Errorf("backup.borg.schedule %q is not a systemd calendar expression: %w", schedule, err)
	}
	if err := writeAtomic(BorgServicePath, []byte(BorgServiceFile()), 0o644); err != nil {
		return err
	}
	if err := writeAtomic(BorgTimerPath, []byte(BorgTimerFile(schedule)), 0o644); err != nil {
		return err
	}
	if _, err := x.Run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if _, err := x.Run(ctx, nil, "systemctl", "enable", BorgTimer); err != nil {
		return fmt.Errorf("enable %s: %w", BorgTimer, err)
	}
	if _, err := x.Run(ctx, nil, "systemctl", "restart", BorgTimer); err != nil {
		return fmt.Errorf("restart %s: %w", BorgTimer, err)
	}
	return nil
}

// removeBorgTimer stops and disables the borg timer and deletes its units. A host
// without the units is left alone.
func removeBorgTimer(ctx context.Context, x Exec) error {
	if _, err := os.Stat(BorgTimerPath); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if _, err := x.Run(ctx, nil, "systemctl", "disable", "--now", BorgTimer); err != nil {
		return fmt.Errorf("disable %s: %w", BorgTimer, err)
	}
	for _, p := range []string{BorgTimerPath, BorgServicePath} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	_, err := x.Run(ctx, nil, "systemctl", "daemon-reload")
	return err
}
