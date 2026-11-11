package install

import (
	"context"
	"fmt"
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

// ApplyBorgTimer writes the borg units and enables the timer when borg is on in the
// config. When it is off, nothing is written.
func ApplyBorgTimer(ctx context.Context, x Exec, enabled bool, schedule string) error {
	if !enabled {
		return nil
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
	return EnableUnit(ctx, x, BorgTimer)
}
