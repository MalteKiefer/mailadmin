package install

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"mailadmin/internal/config"
	"mailadmin/internal/valid"
)

// Answers are the values install needs from the operator.
type Answers struct {
	Hostname string // mail host FQDN, e.g. mx.example.com
	Domain   string // primary mail domain
	IPv4     string // public IPv4 of the host
	IPv6     string // optional public IPv6
	Selector string // default DKIM selector
}

// Validate checks every answer before anything is changed on the host and
// stores the normalized form (lower case, no trailing dot, canonical IPv6),
// which is what the database, Postfix and DNS records must use.
func (a *Answers) Validate() error {
	var err error
	if a.Hostname, err = valid.Domain(a.Hostname); err != nil {
		return fmt.Errorf("hostname: %w", err)
	}
	if a.Domain, err = valid.Domain(a.Domain); err != nil {
		return fmt.Errorf("domain: %w", err)
	}
	if a.Selector, err = valid.Selector(a.Selector); err != nil {
		return fmt.Errorf("selector: %w", err)
	}
	if ip := net.ParseIP(a.IPv4); ip == nil || ip.To4() == nil || strings.Contains(a.IPv4, ":") {
		return fmt.Errorf("ipv4 %q is not an IPv4 address", a.IPv4)
	}
	if a.IPv6 != "" {
		ip := net.ParseIP(a.IPv6)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("ipv6 %q is not an IPv6 address", a.IPv6)
		}
		a.IPv6 = ip.String()
	}
	return nil
}

// RenderConfig returns the config file for the answers. The rspamd controller
// password is stored under [secrets]; the file is written 0600.
func RenderConfig(a Answers, rspamdPW string) []byte {
	return config.RenderTemplate(config.Template{
		Header: "Managed by mailadmin install.", Service: PgService, ServiceFile: PgServiceFile,
		Hostname: a.Hostname, Selector: a.Selector, TLSCert: TLSFullchain,
		IPv4: a.IPv4, IPv6: a.IPv6, RspamdPW: rspamdPW,
	})
}

// RenderSecrets returns a freshly generated rspamd controller password.
func RenderSecrets() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate rspamd password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// ErrExists is returned when a file install must create already exists.
var ErrExists = errors.New("file already exists")

// writeNew creates path with mode, failing if it exists. A re-run never
// overwrites config or secrets; --adopt keeps the existing files as they are.
// The content is written to a temp file and linked to path only when complete,
// so a crash cannot leave a truncated file under the final name.
func writeNew(path string, data []byte, mode os.FileMode) error {
	if err := recordFile(path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	// link fails if path exists, which is the no-overwrite guarantee.
	if err := os.Link(name, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", ErrExists, path)
		}
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// WriteConfig writes the single config file config.toml (0600) into dir. An
// existing config file is kept and reported as ErrExists.
func WriteConfig(dir string, a Answers) error {
	// #nosec G301 -- the directory is traversable; the config file is 0600
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	pw, err := RenderSecrets()
	if err != nil {
		return err
	}
	return writeNew(filepath.Join(dir, "config.toml"), RenderConfig(a, pw), 0o600)
}

// MigrateSecrets moves a legacy secrets.env into the [secrets] table of the TOML
// config and removes the file. It does nothing when there is no secrets.env,
// when the config is YAML or JSON (the file is kept and read as before), or
// when the config already has a [secrets] table.
func MigrateSecrets(dir string) (migrated bool, err error) {
	cfgPath := filepath.Join(dir, "config.toml")
	secPath := filepath.Join(dir, config.SecretsFile)
	if _, err := os.Lstat(secPath); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	cfg, rerr := os.ReadFile(cfgPath) // #nosec G304 -- config in the fixed config dir
	if rerr != nil {
		return false, nil // no TOML config here: nothing to migrate into
	}
	if config.HasSecretsTable(cfg) {
		return false, nil
	}
	m, err := config.ReadSecretsEnv(secPath)
	if err != nil {
		return false, err
	}
	text := strings.TrimRight(string(cfg), "\n") + "\n" + config.SecretsTOML(m)
	if err := writeAtomic(cfgPath, []byte(text), 0o600); err != nil {
		return false, err
	}
	if err := os.Remove(secPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return true, fmt.Errorf("remove %s: %w", secPath, err)
	}
	return true, nil
}

// HostDir is one directory the mail stack needs, with its owner and mode.
type HostDir struct {
	Path  string
	Owner string // user:group
	Mode  os.FileMode
}

// HostDirs are created after the packages, so the rspamd group exists.
func HostDirs() []HostDir {
	return []HostDir{
		{"/etc/mailadmin", "root:root", 0o755},
		{"/var/lib/mailadmin", "mailadmin:mailadmin", 0o750},
		{"/var/lib/mailadmin/dns-backups", "mailadmin:mailadmin", 0o750},
		{"/var/lib/mailadmin/backups", "mailadmin:mailadmin", 0o750},
		{"/var/lib/rspamd/dkim", "mailadmin:_rspamd", 0o750},
		{"/var/vmail", "vmail:vmail", 0o700},
	}
}

// EnsureUser creates a service account when it does not exist.
func EnsureUser(ctx context.Context, x Exec, name, home string, uid int) error {
	if _, err := x.Run(ctx, nil, "id", "-u", name); err == nil {
		return nil
	}
	argv := []string{"useradd", "--home-dir", home, "--shell", "/usr/sbin/nologin"}
	if uid > 0 {
		argv = append(argv, "--uid", fmt.Sprint(uid))
	} else {
		argv = append(argv, "--system")
	}
	argv = append(argv, name)
	if _, err := x.Run(ctx, nil, argv...); err != nil {
		return fmt.Errorf("create user %s: %w", name, err)
	}
	return nil
}

// EnsureHostDirs creates the directories and sets owner and mode on each. A directory
// mailadmin owns is opened without following links, so a link swapped in at its path
// is refused, and owner and mode are set on the open descriptor. Other directories,
// such as a vmail volume, may be links to another disk, so they are followed as before.
func EnsureHostDirs(ctx context.Context, x Exec) error {
	for _, d := range HostDirs() {
		if err := os.MkdirAll(d.Path, d.Mode); err != nil {
			return fmt.Errorf("mkdir %s: %w", d.Path, err)
		}
		if strings.HasPrefix(d.Owner, "mailadmin:") {
			if err := setOwnedDir(d); err != nil {
				return err
			}
			continue
		}
		if _, err := x.Run(ctx, nil, "chown", d.Owner, d.Path); err != nil {
			return fmt.Errorf("chown %s: %w", d.Path, err)
		}
		if err := os.Chmod(d.Path, d.Mode); err != nil {
			return fmt.Errorf("chmod %s: %w", d.Path, err)
		}
	}
	return nil
}

// setOwnedDir sets owner and mode on a directory mailadmin owns. The directory is
// opened with O_DIRECTORY|O_NOFOLLOW, so a link at the path fails the open, and the
// owner and mode are applied to the descriptor, so a later swap cannot redirect them.
func setOwnedDir(d HostDir) error {
	user, group, ok := strings.Cut(d.Owner, ":")
	if !ok {
		return fmt.Errorf("owner %q: want user:group", d.Owner)
	}
	uid, err := lookupUID(user)
	if err != nil {
		return err
	}
	gid, err := lookupGID(group)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(d.Path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- fixed host paths
	if err != nil {
		return fmt.Errorf("open %s (a symlink here is refused): %w", d.Path, err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Chown(uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", d.Path, err)
	}
	if err := f.Chmod(d.Mode); err != nil {
		return fmt.Errorf("chmod %s: %w", d.Path, err)
	}
	return nil
}

// InstallBinary copies the running executable to dst (0755). The copy is
// written next to dst and renamed into place, so a running mailadmin keeps working.
func InstallBinary(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- os.Executable of this process
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer func() { _ = in.Close() }()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755) // #nosec G302 G304 -- root-owned executable install
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("copy binary: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install %s: %w", dst, err)
	}
	return nil
}

// EnableService enables and starts a systemd unit.
func EnableService(ctx context.Context, x Exec, unit string) error {
	if _, err := x.Run(ctx, nil, "systemctl", "enable", "--now", unit); err != nil {
		return fmt.Errorf("enable %s: %w", unit, err)
	}
	return nil
}
