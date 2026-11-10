package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"mailadmin/internal/sys"
)

// managedMarker is in every file mailadmin renders. A file that carries it was
// written by mailadmin before, so it is never kept as a distribution original.
const managedMarker = "mailadmin install"

// writeAtomic writes data to path through a temp file in the same directory, so
// a half-written config is never visible to a running daemon.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	_, err := writeAtomicChanged(path, data, mode)
	return err
}

// writeAtomicChanged is writeAtomic that reports whether the file changed. A
// file that already holds data with mode is left alone: no new inode or mtime
// for AIDE to report, and callers can skip reloads.
func writeAtomicChanged(path string, data []byte, mode os.FileMode) (bool, error) {
	// Recorded even when unchanged: the file is install's, and uninstall must know it.
	if err := recordFile(path); err != nil {
		return false, err
	}
	if sameFile(path, data, mode, -1, -1) {
		return false, nil
	}
	return true, writeAtomicWith(path, data, mode, nil)
}

// sameFile reports whether path is a regular file (not a link) with exactly
// data, mode and, when uid and gid are not -1, that owner.
func sameFile(path string, data []byte, mode os.FileMode, uid, gid int) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != mode.Perm() {
		return false
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); uid >= 0 && (!ok || int(st.Uid) != uid || int(st.Gid) != gid) {
		return false
	}
	cur, err := os.ReadFile(path) // #nosec G304 -- caller's fixed config path
	return err == nil && bytes.Equal(cur, data)
}

// writeAtomicOwned is writeAtomic with an owner. The temp file gets its owner and
// group before the rename, so the final file never exists with the wrong owner.
func writeAtomicOwned(path string, data []byte, mode os.FileMode, owner, group string) error {
	uid, err := lookupUID(owner)
	if err != nil {
		return err
	}
	gid, err := lookupGID(group)
	if err != nil {
		return err
	}
	if err := recordFile(path); err != nil {
		return err
	}
	if sameFile(path, data, mode, uid, gid) {
		return nil
	}
	// Owner is set on the open descriptor, so a link swapped in at the temp name
	// cannot redirect the chown to another file.
	return writeAtomicWith(path, data, mode, func(f *os.File) error {
		if err := f.Chown(uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", path, err)
		}
		return nil
	})
}

// writeAtomicWith is the shared temp-file-and-rename path. prepare, when set, runs
// on the temp file before it is renamed into place.
func writeAtomicWith(path string, data []byte, mode os.FileMode, prepare func(f *os.File) error) error {
	if err := recordFile(path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 -- config directories
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("temp for %s: %w", path, err)
	}
	name := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(fmt.Errorf("write %s: %w", path, err))
	}
	// prepare and the mode change act on the open descriptor, never on the name.
	if prepare != nil {
		if err := prepare(tmp); err != nil {
			return fail(err)
		}
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(fmt.Errorf("chmod %s: %w", path, err))
	}
	// Data must reach the disk before the rename, or a power loss can leave an empty file under the final name.
	if err := tmp.Sync(); err != nil {
		return fail(fmt.Errorf("sync %s: %w", path, err))
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// lookupUID resolves a user name or a numeric uid.
func lookupUID(name string) (int, error) {
	if n, err := strconv.Atoi(name); err == nil {
		return n, nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("user %s: %w", name, err)
	}
	return strconv.Atoi(u.Uid)
}

// lookupGID resolves a group name or a numeric gid.
func lookupGID(name string) (int, error) {
	if n, err := strconv.Atoi(name); err == nil {
		return n, nil
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("group %s: %w", name, err)
	}
	return strconv.Atoi(g.Gid)
}

// writeManaged writes a file mailadmin fully owns. When a distribution file is
// replaced for the first time, the original is kept as <path>.mailadmin-orig.
func writeManaged(path string, data []byte, mode os.FileMode) error {
	return writeManagedOwned(path, data, mode, "", "")
}

// writeManagedOwned is writeManaged with an owner. An empty owner leaves the
// ownership to the default of a root process.
func writeManagedOwned(path string, data []byte, mode os.FileMode, owner, group string) error {
	if _, err := os.Stat(path); err == nil {
		orig := path + ".mailadmin-orig"
		if _, serr := os.Stat(orig); errors.Is(serr, fs.ErrNotExist) {
			cur, rerr := os.ReadFile(path) // #nosec G304 -- fixed config path
			if rerr != nil {
				return fmt.Errorf("read %s: %w", path, rerr)
			}
			// Only a file that is not already mailadmin's own gets a backup.
			if !strings.Contains(string(cur), managedMarker) {
				if werr := writeAtomic(orig, cur, 0o600); werr != nil {
					return werr
				}
			}
		}
	}
	if owner == "" {
		return writeAtomic(path, data, mode)
	}
	return writeAtomicOwned(path, data, mode, owner, group)
}

// ApplyPostfix writes the lookup maps, sets the main.cf keys with postconf and
// adds the submission services. It finishes with postfix check.
func ApplyPostfix(ctx context.Context, x Exec, hostname string) error {
	if err := ensurePostfixPgSocket(ctx, x); err != nil {
		return err
	}
	for path, content := range PostfixPgsqlMaps() {
		// The postfix lookup processes run as the postfix user and must read the map.
		if err := writeManagedOwned(path, []byte(content), 0o640, "root", "postfix"); err != nil {
			return err
		}
	}
	// One postconf call rewrites main.cf once for all keys.
	args := []string{"postconf", "-e"}
	for _, s := range PostfixSettings(hostname, installedTLSGroups(ctx, x)) {
		args = append(args, s.Key+"="+s.Value)
	}
	if _, err := x.Run(ctx, nil, args...); err != nil {
		return fmt.Errorf("postconf -e: %w", err)
	}
	for _, args := range PostfixSubmissionServices() {
		if _, err := x.Run(ctx, nil, append([]string{"postconf"}, args...)...); err != nil {
			return fmt.Errorf("postconf %s: %w", strings.Join(args, " "), err)
		}
	}
	if _, err := x.Run(ctx, nil, "postfix", "check"); err != nil {
		return fmt.Errorf("postfix check: %w", err)
	}
	return nil
}

// ApplyDovecot writes dovecot.conf and validates it with doveconf.
func ApplyDovecot(ctx context.Context, x Exec) error {
	if err := writeManaged(DovecotConfPath, []byte(DovecotConf(installedTLSGroups(ctx, x))), 0o644); err != nil {
		return err
	}
	if _, err := x.Run(ctx, nil, "doveconf", "-n"); err != nil {
		return fmt.Errorf("doveconf validation: %w", err)
	}
	return nil
}

// ApplyRspamd writes the local.d overrides. The controller password is hashed by
// rspamadm and only the hash is written to the config.
func ApplyRspamd(ctx context.Context, x Exec, controllerPW string, selectors [][2]string) error {
	res, err := x.Run(ctx, nil, "rspamadm", "pw", "-e", "-p", controllerPW)
	if err != nil {
		return fmt.Errorf("hash rspamd controller password: %w", err)
	}
	hash := strings.TrimSpace(string(res.Stdout))
	if !strings.HasPrefix(hash, "$") {
		return errors.New("rspamadm pw returned no hash")
	}
	for path, content := range RspamdLocal(hash) {
		if err := writeManaged(path, []byte(content), 0o644); err != nil {
			return err
		}
	}
	// rspamd reads the map as its own user. An unreadable map is silently empty,
	// and every message is then signed with the default selector or not at all.
	if err := writeManagedOwned(RspamdSelectorMap, []byte(RspamdSelectorMapContent(selectors)), 0o640, "root", "_rspamd"); err != nil {
		return err
	}
	if _, err := x.Run(ctx, nil, "rspamadm", "configtest"); err != nil {
		return fmt.Errorf("rspamd configtest: %w", err)
	}
	return nil
}

// ErrNotManaged reports a file mailadmin did not write, which it leaves alone.
var ErrNotManaged = errors.New("not written by mailadmin install, left unchanged")

// SyncRspamdSelectors rewrites the DKIM selector map rspamd signs from and
// reloads rspamd, so a new domain or a changed selector is signed at once. A
// map that mailadmin install did not write belongs to the operator and is left
// unchanged (ErrNotManaged); an unchanged map is not rewritten.
func SyncRspamdSelectors(ctx context.Context, x Exec, selectors [][2]string) error {
	want := RspamdSelectorMapContent(selectors)
	if cur, err := os.ReadFile(RspamdSelectorMap); err == nil {
		if !strings.Contains(string(cur), managedMarker) {
			return fmt.Errorf("%s: %w", RspamdSelectorMap, ErrNotManaged)
		}
		if string(cur) == want {
			return nil
		}
	}
	if err := writeAtomicOwned(RspamdSelectorMap, []byte(want), 0o640, "root", "_rspamd"); err != nil {
		return err
	}
	if _, err := x.Run(ctx, nil, "systemctl", "try-reload-or-restart", "rspamd"); err != nil {
		return fmt.Errorf("reload rspamd: %w", err)
	}
	return nil
}

// ApplyCaddy writes the main Caddyfile and validates it. tlsInternal selects
// Caddy's local CA for the mail host instead of public ACME.
func ApplyCaddy(ctx context.Context, x Exec, hostname string, tlsInternal bool) error {
	if err := os.MkdirAll(CaddyIncludeDir, 0o755); err != nil { // #nosec G301 -- caddy config dir
		return fmt.Errorf("mkdir %s: %w", CaddyIncludeDir, err)
	}
	if err := writeManaged(CaddyfilePath, []byte(CaddyfileMain(hostname, tlsInternal)), 0o644); err != nil {
		return err
	}
	if _, err := x.Run(ctx, nil, "caddy", "validate", "--config", CaddyfilePath, "--adapter", "caddyfile"); err != nil {
		return fmt.Errorf("caddy validate: %w", err)
	}
	return nil
}

// ApplyFirewall loads the mailadmin nftables table. The table drops inbound by
// default and keeps SSH open. It is validated with nft -c before it is applied.
func ApplyFirewall(ctx context.Context, x Exec) error {
	if err := os.MkdirAll(filepath.Dir(NftPersistPath), 0o755); err != nil { // #nosec G301 -- nftables include dir
		return fmt.Errorf("mkdir nftables.d: %w", err)
	}
	ssh := mergePorts(SSHPorts(), listeningSSHPorts(ctx, x))
	// The table is checked as the temp file before it is renamed over
	// NftPersistPath, so a bad table never replaces a good one.
	check := func(f *os.File) error {
		if _, err := x.Run(ctx, nil, "nft", "-c", "-f", f.Name()); err != nil {
			return fmt.Errorf("nft check: %w", err)
		}
		return nil
	}
	if err := recordFile(NftPersistPath); err != nil {
		return err
	}
	if !sameFile(NftPersistPath, []byte(NftTableFile(DefaultTCPPorts, nil, ssh)), 0o600, -1, -1) {
		if err := writeAtomicWith(NftPersistPath, []byte(NftTableFile(DefaultTCPPorts, nil, ssh)), 0o600, check); err != nil {
			return err
		}
	}
	// The conf only includes the persisted table, so it is written once that table is
	// in place. Loading the conf replaces the loaded table with the checked version.
	if err := writeAtomic(NftConfPath, []byte(NftConf()), 0o755); err != nil {
		return err
	}
	if _, err := x.Run(ctx, nil, "nft", "-f", NftConfPath); err != nil {
		return fmt.Errorf("nft load: %w", err)
	}
	if _, err := x.Run(ctx, nil, "systemctl", "enable", "nftables"); err != nil {
		return fmt.Errorf("enable nftables: %w", err)
	}
	return nil
}

// listeningSSHPorts returns the TCP ports sshd (or the socket unit that starts
// it) listens on right now, plus the port of the operator's own connection. The
// config files miss ports set with SSHD_OPTS="-p ..." or in an ssh.socket
// drop-in, and a firewall without them locks the operator out.
func listeningSSHPorts(ctx context.Context, x Exec) []int {
	var ports []int
	if res, err := x.Run(ctx, nil, "ss", "-Hltnp"); err == nil {
		for _, l := range strings.Split(string(res.Stdout), "\n") {
			f := strings.Fields(l)
			if len(f) < 4 || !strings.Contains(l, `"sshd`) {
				continue
			}
			if n, ok := listenPort(f[3]); ok {
				ports = append(ports, n)
			}
		}
	}
	if res, err := x.Run(ctx, nil, "systemctl", "show", "-p", "Listen", "ssh.socket"); err == nil {
		for _, f := range strings.Fields(string(res.Stdout)) {
			f = strings.TrimPrefix(f, "Listen=")
			if n, ok := listenPort(f); ok {
				ports = append(ports, n)
			} else if n, ok := validPort(f); ok {
				ports = append(ports, n)
			}
		}
	}
	if f := strings.Fields(os.Getenv("SSH_CONNECTION")); len(f) == 4 {
		if n, ok := validPort(f[3]); ok {
			ports = append(ports, n)
		}
	}
	return ports
}

// mergePorts returns the distinct ports of both lists, sorted.
func mergePorts(a, b []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, p := range append(append([]int{}, a...), b...) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

// InstallHelpers writes the three root helpers and the certificate sync units.
// domain is the primary mail domain the certificate sync publishes TLSA records for.
func InstallHelpers(ctx context.Context, x Exec, hostname, domain string) error {
	helpers := map[string]string{
		FwPortHelperPath:   FwPortHelper,
		DKIMGenHelperPath:  DKIMGenHelper,
		CertSyncHelperPath: CertSyncHelper,
	}
	for path, body := range helpers {
		if err := writeAtomic(path, []byte(body), 0o750); err != nil { // #nosec G306 -- root-only helper
			return err
		}
	}
	service, timer := CertSyncUnits(hostname, domain)
	if err := writeAtomic(CertSyncServicePath, []byte(service), 0o644); err != nil {
		return err
	}
	if err := writeAtomic(CertSyncTimerPath, []byte(timer), 0o644); err != nil {
		return err
	}
	if _, err := x.Run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	}
	return EnableUnit(ctx, x, "mailadmin-cert-sync.timer")
}

// EnableUnit enables and starts a unit. It is idempotent.
func EnableUnit(ctx context.Context, x Exec, unit string) error {
	if _, err := x.Run(ctx, nil, "systemctl", "enable", "--now", unit); err != nil {
		return fmt.Errorf("enable %s: %w", unit, err)
	}
	// A running daemon picks up rewritten config only after a reload.
	if _, err := x.Run(ctx, nil, "systemctl", "reload-or-restart", unit); err != nil {
		return fmt.Errorf("reload %s: %w", unit, err)
	}
	return nil
}

// WaitForCertificate runs the certificate sync helper until Caddy has issued a
// certificate for host, or until timeout. It returns an error if none appeared.
func WaitForCertificate(ctx context.Context, x Exec, host, domain string, timeout, interval time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		_, err := x.Run(ctx, nil, CertSyncHelperPath, host, domain)
		if err == nil {
			return nil
		}
		// Only exit 3 means "no certificate yet". Any other failure is final, so the
		// helper's side effects (TLSA publish, reload) are not repeated for ten minutes.
		var ee *sys.ExitError
		if !errors.As(err, &ee) || ee.ExitCode != 3 {
			return fmt.Errorf("certificate sync for %s: %w", host, err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no certificate for %s after %s (check DNS points here and ports 80/443 are reachable): %w",
				host, timeout, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

// PostfixPgSocket is the PostgreSQL socket directory inside the postfix chroot.
const PostfixPgSocket = "/var/spool/postfix/var/run/postgresql"

// ensurePostfixPgSocket bind-mounts the PostgreSQL socket directory into the
// postfix chroot. The lookup tables use unix:/var/run/postgresql, which is only
// reachable from inside the chroot through this mount. The mount is recorded in
// fstab with nofail, so a missing source never blocks boot. /run/postgresql is
// created by systemd-tmpfiles at boot, after local file systems are mounted, so
// the mount is ordered after it (after, not requires: one failing tmpfiles entry
// must not cancel the mount) and before Postfix starts.
func ensurePostfixPgSocket(ctx context.Context, x Exec) error {
	if err := os.MkdirAll(PostfixPgSocket, 0o755); err != nil { // #nosec G301 -- chroot mount point
		return fmt.Errorf("mkdir %s: %w", PostfixPgSocket, err)
	}
	if _, err := x.Run(ctx, nil, "mountpoint", "-q", PostfixPgSocket); err != nil {
		if _, err := x.Run(ctx, nil, "mount", "--bind", "/var/run/postgresql", PostfixPgSocket); err != nil {
			return fmt.Errorf("bind mount postgres socket into postfix chroot: %w", err)
		}
	}
	return setFstabEntry("/etc/fstab", PostfixPgSocket, PostfixPgFstabLine)
}

// PostfixPgFstabLine is the fstab entry for the socket bind mount.
const PostfixPgFstabLine = "/var/run/postgresql " + PostfixPgSocket + " none " +
	"bind,nofail,x-systemd.after=systemd-tmpfiles-setup.service," +
	"x-systemd.before=postfix.service,x-systemd.before=postfix@-.service 0 0"

// setFstabEntry makes line the only fstab entry for mountpoint. An entry an
// earlier release wrote with other options is replaced, not duplicated.
func setFstabEntry(path, mountpoint, line string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- /etc/fstab
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	var out []string
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && !strings.HasPrefix(f[0], "#") && f[1] == mountpoint {
			continue
		}
		out = append(out, l)
	}
	out = append(out, line)
	next := strings.Join(out, "\n") + "\n"
	if next == string(data) {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	return writeAtomic(path, []byte(next), fi.Mode().Perm())
}

// ApplyAutoconfig writes the client-configuration documents into the web roots
// that the managed Caddy sites serve.
func ApplyAutoconfig(hostname string) error {
	for path, body := range AutoconfigFiles(hostname) {
		if err := writeAtomic(path, []byte(body), 0o644); err != nil {
			return err
		}
	}
	return nil
}
