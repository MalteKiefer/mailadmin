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

// Validate checks every answer before anything is changed on the host.
func (a Answers) Validate() error {
	if _, err := valid.Domain(a.Hostname); err != nil {
		return fmt.Errorf("hostname: %w", err)
	}
	if _, err := valid.Domain(a.Domain); err != nil {
		return fmt.Errorf("domain: %w", err)
	}
	if _, err := valid.Selector(a.Selector); err != nil {
		return fmt.Errorf("selector: %w", err)
	}
	if ip := net.ParseIP(a.IPv4); ip == nil || ip.To4() == nil || strings.Contains(a.IPv4, ":") {
		return fmt.Errorf("ipv4 %q is not an IPv4 address", a.IPv4)
	}
	if a.IPv6 != "" {
		if ip := net.ParseIP(a.IPv6); ip == nil || ip.To4() != nil {
			return fmt.Errorf("ipv6 %q is not an IPv6 address", a.IPv6)
		}
	}
	return nil
}

// RenderConfig returns config.toml in the layout ARCHITECTURE.md documents.
// Non-secret values only; tokens and the rspamd password go to secrets.env.
func RenderConfig(a Answers) []byte {
	return []byte(fmt.Sprintf(`[postgres]
service      = %q
service_file = %q

[mail]
hostname         = %q
dkim_dir         = "/var/lib/rspamd/dkim"
default_selector = %q
tls_cert         = %q

[server]
ipv4 = %q
ipv6 = %q

[dns]
resolver = "1.1.1.1:53"

[backup]
dns_backup_dir = "/var/lib/mailadmin/dns-backups"
dir            = "/var/lib/mailadmin/backups"

[logs]
units = ["postfix", "dovecot", "rspamd", "caddy", "postgresql"]
`, PgService, PgServiceFile, a.Hostname, a.Selector, TLSFullchain, a.IPv4, a.IPv6))
}

// RenderSecrets returns secrets.env with a freshly generated rspamd controller
// password. The file is written 0600 and never logged.
func RenderSecrets() ([]byte, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate rspamd password: %w", err)
	}
	return []byte("RSPAMD_CONTROLLER_PW=" + base64.RawURLEncoding.EncodeToString(buf) + "\n"), nil
}

// ErrExists is returned when a file install must create already exists.
var ErrExists = errors.New("file already exists")

// writeNew creates path with mode, failing if it exists. A re-run never
// overwrites config or secrets; --adopt keeps the existing files as they are.
func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304 -- fixed install paths, O_EXCL
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", ErrExists, path)
		}
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

// WriteConfig writes config.toml (0644) and secrets.env (0600) into dir.
// Existing files are kept, and ErrExists is returned for the first one found.
func WriteConfig(dir string, a Answers) error {
	// #nosec G301 -- config dir is deliberately traversable, secrets.env is 0600
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	secrets, err := RenderSecrets()
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(dir, "secrets.env"), secrets, 0o600); err != nil {
		return err
	}
	return writeNew(filepath.Join(dir, "config.toml"), RenderConfig(a), 0o644)
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

// EnsureHostDirs creates the directories and sets owner and mode on each.
func EnsureHostDirs(ctx context.Context, x Exec) error {
	for _, d := range HostDirs() {
		if err := os.MkdirAll(d.Path, d.Mode); err != nil {
			return fmt.Errorf("mkdir %s: %w", d.Path, err)
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
