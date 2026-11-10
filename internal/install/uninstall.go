package install

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Dirs that mailadmin owns outright. They are removed after the backup, after
// every saved original has been written back. StateDir goes last of all.
var ownedDirs = []string{
	"/var/vmail", "/etc/mailadmin", "/var/lib/aide", "/var/lib/crowdsec", "/etc/crowdsec",
	"/var/lib/caddy", "/var/lib/rspamd/dkim",
}

// units mailadmin runs (stopped before anything is removed). postgresql is left
// out here: its database is dropped first, while the server still runs.
var uninstallUnits = []string{
	"postfix", "dovecot", "rspamd", "caddy", "crowdsec-firewall-bouncer", "crowdsec",
}

// Summary describes what Uninstall will do, for the plan the operator confirms.
func Summary(m *Manifest) []string {
	var out []string
	out = append(out, fmt.Sprintf("install record of version %s", m.Version))
	out = append(out, fmt.Sprintf("files: %d changed or created by install (originals restored, new files removed)", len(m.Files)))
	if len(m.Packages) > 0 {
		src := "installed by install"
		if m.PackagesAssumed {
			src = "assumed from install's package list (host predates the record)"
		}
		out = append(out, fmt.Sprintf("packages purged (%s): %s", src, strings.Join(m.Packages, " ")))
	} else {
		out = append(out, "packages: none recorded")
	}
	if m.Database != "" {
		out = append(out, fmt.Sprintf("database %s dropped with roles %s; the PostgreSQL cluster is removed", m.Database, strings.Join(m.Roles, ", ")))
	}
	if len(m.Users) > 0 {
		out = append(out, "users removed: "+strings.Join(m.Users, ", "))
	}
	if m.NftTable {
		out = append(out, "nftables table inet mailadmin deleted")
	}
	out = append(out, "directories removed: "+strings.Join(ownedDirs, ", ")+", "+StateDir)
	return out
}

// Uninstall reverses the install record m on this host. It keeps going after a
// failed step and returns every failure; the caller decides what to report. Run
// it only after the backup is verified.
func Uninstall(ctx context.Context, x Exec, m *Manifest, report func(string)) []error {
	var errs []error
	step := func(msg string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", msg, err))
			report("failed: " + msg + ": " + err.Error())
			return
		}
		report("done: " + msg)
	}
	run := func(argv ...string) error { _, err := x.Run(ctx, nil, argv...); return err }

	// 1. Stop the services that serve mail and the firewall helpers.
	for _, u := range append(append([]string{}, uninstallUnits...), mailadminUnits()...) {
		// A unit that is not installed is not an error: there is nothing to stop.
		if err := run("systemctl", "disable", "--now", u); err != nil {
			report("skipped (not installed or not running): " + u)
		} else {
			report("done: stop " + u)
		}
	}

	// 2. Mount points that install created in the file system.
	step("unmount postfix postgres socket", run("umount", PostfixPgSocket))

	// 3. Write back every saved original, newest change first, and remove what
	//    install created. This also restores the repository sources and keyrings.
	for i := len(m.Files) - 1; i >= 0; i-- {
		f := m.Files[i]
		step("restore "+f.Path, restoreFile(f))
	}

	// 4. The restored sshd config is checked before sshd is reloaded.
	step("check sshd config", run("sshd", "-t"))
	step("reload sshd", run("systemctl", "try-reload-or-restart", "ssh"))

	// 5. Firewall table of mailadmin.
	if m.NftTable {
		step("delete nftables table inet mailadmin", run("nft", "delete", "table", "inet", "mailadmin"))
	}

	// 6. Database, while PostgreSQL still runs.
	if m.Database != "" {
		step("start postgresql", run("systemctl", "start", "postgresql"))
		step("drop database "+m.Database, run(asPostgres("dropdb", "--if-exists", m.Database)...))
		for _, r := range m.Roles {
			step("drop role "+r, run(asPostgres("dropuser", "--if-exists", r)...))
		}
	}
	for _, c := range clusterDirs() {
		step("drop cluster "+c.version+"/"+c.name, run("pg_dropcluster", "--stop", c.version, c.name))
	}

	// 7. Packages install installed. Base packages are never in the list.
	if len(m.Packages) > 0 {
		step("purge packages", run(aptEnv(append([]string{"purge"}, m.Packages...)...)...))
		step("autoremove", run(aptEnv("autoremove", "--purge")...))
	}
	step("refresh package index", run(aptEnv("update")...))

	// 8. Data directories, then the users that own them.
	for _, d := range ownedDirs {
		step("remove "+d, os.RemoveAll(d))
	}
	for _, u := range m.Users {
		step("remove user "+u, run("userdel", u))
		step("remove group "+u, run("groupdel", u))
	}

	// 9. Helpers and the state dir last: the saved originals are read from it above.
	for _, pat := range []string{"/usr/local/libexec/mailadmin-*", "/usr/local/sbin/mailadmin-*"} {
		matches, _ := filepath.Glob(pat)
		for _, p := range matches {
			step("remove "+p, os.Remove(p))
		}
	}
	step("remove "+StateDir, os.RemoveAll(StateDir))
	return errs
}

// restoreFile writes back the saved original of f, or removes f when install
// created it. A missing file is already in the desired state.
func restoreFile(f ManagedFile) error {
	if !f.Existed {
		if err := os.Remove(f.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	data, err := os.ReadFile(filepath.Join(originalsDir(), f.Backup)) // #nosec G304 -- state dir copy
	if err != nil {
		return fmt.Errorf("read original: %w", err)
	}
	if err := writeAtomicWith(f.Path, data, fs.FileMode(f.Mode), nil); err != nil {
		return err
	}
	if f.UID != 0 || f.GID != 0 {
		if err := os.Chown(f.Path, f.UID, f.GID); err != nil {
			return fmt.Errorf("chown: %w", err)
		}
	}
	return nil
}

// mailadminUnits are the systemd units install added: cert sync and AIDE.
func mailadminUnits() []string {
	var out []string
	for _, pat := range []string{"/etc/systemd/system/mailadmin-*.service", "/etc/systemd/system/mailadmin-*.timer"} {
		matches, _ := filepath.Glob(pat)
		for _, p := range matches {
			out = append(out, filepath.Base(p))
		}
	}
	sort.Strings(out)
	return out
}

type cluster struct{ version, name string }

// clusterDirs lists the PostgreSQL clusters of /etc/postgresql.
func clusterDirs() []cluster {
	var out []cluster
	matches, _ := filepath.Glob("/etc/postgresql/*/*")
	for _, p := range matches {
		out = append(out, cluster{version: filepath.Base(filepath.Dir(p)), name: filepath.Base(p)})
	}
	return out
}
