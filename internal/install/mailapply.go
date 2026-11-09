package install

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// managedMarker is in every file mailadmin renders. A file that carries it was
// written by mailadmin before, so it is never kept as a distribution original.
const managedMarker = "mailadmin install"

// writeAtomic writes data to path through a temp file in the same directory, so
// a half-written config is never visible to a running daemon.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	return writeAtomicWith(path, data, mode, nil)
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
	for _, s := range PostfixSettings(hostname) {
		if _, err := x.Run(ctx, nil, "postconf", "-e", s.Key+"="+s.Value); err != nil {
			return fmt.Errorf("postconf %s: %w", s.Key, err)
		}
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
	if err := writeManaged(DovecotConfPath, []byte(DovecotConf()), 0o644); err != nil {
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
	ssh := SSHPorts()
	if err := writeAtomic(NftConfPath, []byte(NftConf()), 0o755); err != nil {
		return err
	}
	// The table is checked as a temp file in the persist directory and only renamed
	// over NftPersistPath once nft accepts it, so a bad table never replaces a good one.
	tmp, err := os.CreateTemp(filepath.Dir(NftPersistPath), "."+filepath.Base(NftPersistPath)+".*")
	if err != nil {
		return fmt.Errorf("temp for %s: %w", NftPersistPath, err)
	}
	name := tmp.Name()
	if _, err := tmp.WriteString(NftTableFile(DefaultTCPPorts, nil, ssh)); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return fmt.Errorf("write %s: %w", NftPersistPath, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("close %s: %w", NftPersistPath, err)
	}
	if err := os.Chmod(name, 0o600); err != nil { // root loads this file; nothing else reads it
		_ = os.Remove(name)
		return fmt.Errorf("chmod %s: %w", NftPersistPath, err)
	}
	if _, err := x.Run(ctx, nil, "nft", "-c", "-f", name); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("nft check: %w", err)
	}
	if err := os.Rename(name, NftPersistPath); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("install %s: %w", NftPersistPath, err)
	}
	// The table starts with "destroy table", so this replaces the loaded table
	// instead of adding a second copy of the rules.
	if _, err := x.Run(ctx, nil, "nft", "-f", NftConfPath); err != nil {
		return fmt.Errorf("nft load: %w", err)
	}
	if _, err := x.Run(ctx, nil, "systemctl", "enable", "nftables"); err != nil {
		return fmt.Errorf("enable nftables: %w", err)
	}
	return nil
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
// fstab with nofail, so a missing source never blocks boot.
func ensurePostfixPgSocket(ctx context.Context, x Exec) error {
	if err := os.MkdirAll(PostfixPgSocket, 0o755); err != nil { // #nosec G301 -- chroot mount point
		return fmt.Errorf("mkdir %s: %w", PostfixPgSocket, err)
	}
	if _, err := x.Run(ctx, nil, "mountpoint", "-q", PostfixPgSocket); err != nil {
		if _, err := x.Run(ctx, nil, "mount", "--bind", "/var/run/postgresql", PostfixPgSocket); err != nil {
			return fmt.Errorf("bind mount postgres socket into postfix chroot: %w", err)
		}
	}
	return ensureLine("/etc/fstab", "/var/run/postgresql "+PostfixPgSocket+" none bind,nofail 0 0", false)
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
