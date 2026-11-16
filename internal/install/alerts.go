package install

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// Paths of the alerting units mailadmin owns.
const (
	DoctorTimerPath   = "/etc/systemd/system/mailadmin-doctor.timer"
	DoctorServicePath = "/etc/systemd/system/mailadmin-doctor.service"
	FailureUnitPath   = "/etc/systemd/system/mailadmin-failure@.service"
)

// AlertedUnits get an OnFailure hook: a failed unit mails root (aliased to the
// operator address by ApplyRootMail).
var AlertedUnits = []string{"postfix", "dovecot", "rspamd", "caddy", "postgresql", "unbound", "crowdsec", "mailadmin-webmail"}

// DoctorServiceContent runs the health check with notifications on.
func DoctorServiceContent() string {
	return "# Managed by mailadmin install.\n[Unit]\nDescription=mailadmin health check\n\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/mailadmin doctor --notify\n"
}

// DoctorTimerContent runs the health check every day at 07:00.
func DoctorTimerContent() string {
	return "# Managed by mailadmin install.\n[Unit]\nDescription=Daily mailadmin health check\n\n[Timer]\nOnCalendar=*-*-* 07:00:00\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
}

// FailureUnitContent mails root when a unit with an OnFailure hook fails.
func FailureUnitContent() string {
	return "# Managed by mailadmin install.\n[Unit]\nDescription=Report a failed unit to root (%i)\n\n[Service]\nType=oneshot\nExecStart=/bin/sh -c 'printf \"Subject: unit %%i failed on %%H\\n\\nSee: journalctl -u %%i\\n\" | /usr/sbin/sendmail -t -oi'\n"
}

// OnFailureDropIn adds the failure hook to one unit.
func OnFailureDropIn() string {
	return "# Managed by mailadmin install.\n[Unit]\nOnFailure=mailadmin-failure@%N.service\n"
}

// ApplyAlerting writes the daily health check and the failure hooks, then
// enables the timer.
func ApplyAlerting(ctx context.Context, x Exec) error {
	files := map[string]string{
		DoctorServicePath: DoctorServiceContent(),
		DoctorTimerPath:   DoctorTimerContent(),
		FailureUnitPath:   FailureUnitContent(),
	}
	for _, u := range AlertedUnits {
		files[fmt.Sprintf("/etc/systemd/system/%s.service.d/mailadmin-onfailure.conf", u)] = OnFailureDropIn()
	}
	for path, content := range files {
		if err := os.MkdirAll(dirOf(path), 0o755); err != nil { // #nosec G301 -- systemd unit dirs
			return err
		}
		if err := writeAtomic(path, []byte(content), 0o644); err != nil {
			return err
		}
	}
	if _, err := x.Run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if _, err := x.Run(ctx, nil, "systemctl", "enable", "--now", "mailadmin-doctor.timer"); err != nil {
		return fmt.Errorf("enable doctor timer: %w", err)
	}
	return nil
}

func dirOf(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
}
