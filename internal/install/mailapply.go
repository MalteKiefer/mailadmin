package install

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// writeAtomic writes data to path through a temp file in the same directory, so
// a half-written config is never visible to a running daemon.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 -- config directories
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("temp for %s: %w", path, err)
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Chmod(name, mode); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// writeManaged writes a file mailadmin fully owns. When a distribution file is
// replaced for the first time, the original is kept as <path>.mailadmin-orig.
func writeManaged(path string, data []byte, mode os.FileMode) error {
	if _, err := os.Stat(path); err == nil {
		orig := path + ".mailadmin-orig"
		if _, serr := os.Stat(orig); errors.Is(serr, fs.ErrNotExist) {
			cur, rerr := os.ReadFile(path) // #nosec G304 -- fixed config path
			if rerr != nil {
				return fmt.Errorf("read %s: %w", path, rerr)
			}
			if werr := writeAtomic(orig, cur, 0o600); werr != nil {
				return werr
			}
		}
	}
	return writeAtomic(path, data, mode)
}

// ApplyPostfix writes the lookup maps, sets the main.cf keys with postconf and
// adds the submission services. It finishes with postfix check.
func ApplyPostfix(ctx context.Context, x Exec, hostname string) error {
	if err := ensurePostfixPgSocket(ctx, x); err != nil {
		return err
	}
	for path, content := range PostfixPgsqlMaps() {
		if err := writeManaged(path, []byte(content), 0o640); err != nil {
			return err
		}
		// The postfix lookup processes run as the postfix user and must read the map.
		if _, err := x.Run(ctx, nil, "chown", "root:postfix", path); err != nil {
			return fmt.Errorf("chown %s: %w", path, err)
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
	if err := writeManaged(RspamdSelectorMap, []byte(RspamdSelectorMapContent(selectors)), 0o640); err != nil {
		return err
	}
	// rspamd reads the map as its own user. An unreadable map is silently empty,
	// and every message is then signed with the default selector or not at all.
	if _, err := x.Run(ctx, nil, "chown", "root:_rspamd", RspamdSelectorMap); err != nil {
		return fmt.Errorf("chown %s: %w", RspamdSelectorMap, err)
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
	if err := writeAtomic(NftPersistPath, []byte(NftTableFile(DefaultTCPPorts, nil, ssh)), 0o644); err != nil {
		return err
	}
	if err := writeAtomic(NftConfPath, []byte(NftConf()), 0o755); err != nil {
		return err
	}
	if _, err := x.Run(ctx, nil, "nft", "-c", "-f", NftConfPath); err != nil {
		return fmt.Errorf("nft check: %w", err)
	}
	// Load the ruleset exactly once. The service unit reloads the same file, so a
	// second load would duplicate the rules. The table is replaced on each run.
	_, _ = x.Run(ctx, nil, "nft", "delete", "table", "inet", "mailadmin")
	if _, err := x.Run(ctx, nil, "nft", "-f", NftConfPath); err != nil {
		return fmt.Errorf("nft load: %w", err)
	}
	if _, err := x.Run(ctx, nil, "systemctl", "enable", "nftables"); err != nil {
		return fmt.Errorf("enable nftables: %w", err)
	}
	return nil
}

// InstallHelpers writes the three root helpers and the certificate sync units.
func InstallHelpers(ctx context.Context, x Exec, hostname string) error {
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
	service, timer := CertSyncUnits(hostname)
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
func WaitForCertificate(ctx context.Context, x Exec, host string, timeout, interval time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		_, err := x.Run(ctx, nil, CertSyncHelperPath, host)
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
