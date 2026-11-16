package install

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// AppArmorSourceDir holds the upstream profiles shipped by apparmor-profiles.
const AppArmorSourceDir = "/usr/share/apparmor/extra-profiles"

// AppArmorProfileDir is where the profiles are loaded from.
const AppArmorProfileDir = "/etc/apparmor.d"

// MailAppArmorGlobs select the Postfix and Dovecot profiles. Caddy, rspamd and
// Valkey have no upstream profile and are not confined here.
var MailAppArmorGlobs = []string{"postfix-*", "usr.lib.dovecot.*"}

// ApplyMailAppArmor copies the Postfix and Dovecot profiles into /etc/apparmor.d
// and loads them in complain mode. Complain mode logs what enforce mode would
// deny, without blocking. Switching to enforce is a separate step, after a mail
// test covering IMAP login, submission and Sieve.
func ApplyMailAppArmor(ctx context.Context, x Exec) error {
	for _, glob := range MailAppArmorGlobs {
		matches, err := filepath.Glob(filepath.Join(AppArmorSourceDir, glob))
		if err != nil {
			return fmt.Errorf("apparmor glob %s: %w", glob, err)
		}
		for _, src := range matches {
			data, err := os.ReadFile(src) // #nosec G304 -- fixed package directory
			if err != nil {
				return fmt.Errorf("read %s: %w", src, err)
			}
			dst := filepath.Join(AppArmorProfileDir, filepath.Base(src))
			if err := writeAtomic(dst, data, 0o644); err != nil {
				return err
			}
			if _, err := x.Run(ctx, nil, "apparmor_parser", "-r", "-C", dst); err != nil {
				return fmt.Errorf("load %s in complain mode: %w", dst, err)
			}
		}
	}
	return nil
}
