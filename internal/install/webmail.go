package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"mailadmin/internal/config"
)

// Webmail paths and names. The alps binary, its unit and the password helper's
// sudo rule are managed by mailadmin; uninstall removes them through the install
// journal and the mailadmin-* globs.
const (
	AlpsBin      = "/usr/local/libexec/mailadmin-alps"
	AlpsConfPath = "/etc/mailadmin/alps.toml"
	AlpsUnit     = "mailadmin-webmail.service"
	AlpsUnitPath = "/etc/systemd/system/" + AlpsUnit
	AlpsUser     = "alps"
	CaddyWebmail = CaddyIncludeDir + "/webmail.caddy"
	// AlpsSudoers lets the alps user run the password helper as root, and nothing else.
	AlpsSudoers = "/etc/sudoers.d/mailadmin-webmail"
	// PasswordHelper is the mailadmin subcommand alps calls to change a password.
	PasswordHelper = "/usr/local/sbin/mailadmin" // #nosec G101 -- binary path, not a credential
	maxAlpsBinary  = 64 << 20
	alpsFetchWait  = 2 * time.Minute
)

// AlpsConf renders the alps configuration. alps listens on the local address of the
// webmail config, Caddy proxies the domain to it, and alps talks to the local mail
// host over implicit TLS (IMAP 993, submission 465) so certificates are verified
// against the mail host name. Password changes go through the helper.
func AlpsConf(w config.Webmail, hostname string) string {
	return fmt.Sprintf(`# Managed by mailadmin install. Source of truth: the [webmail] section of config.toml.
[server]
addr = %q
debug = false
# Caddy on this host is the only proxy. Its forwarded headers are trusted from loopback.
trusted_proxies = ["127.0.0.1/32", "::1/128"]
trusted_origins = [%q]

[provider]
type = "imap"

[provider.imap]
server = %q

[smtp]
server = %q

# Once any plugin section exists, only the plugins listed as enabled run. Every
# plugin the webmail ships is listed here.
# WebAuthn (2FA) needs the relying party id and the exact origin the browser uses.
[webauthn]
rpid = %q
display_name = "Webmail"
origins = [%q]

[plugin.base]
enabled = true

%[7]s
%[8]s
[plugin.gpg]
enabled = %[9]t

[plugin.managesieve]
enabled = %[10]t

[plugin.password]
enabled = %[11]t

[plugin.password.options]
# The helper checks the current password itself, then changes it. The password
# travels on stdin only, never in argv.
command = ["/usr/bin/sudo", "-n", %[12]q, "webmail-passwd", "{email}"]
stdin = "{old_password}\n{new_password}\n"
`, w.Listen, "https://"+w.Domain, "imaps://"+hostname+":993", "smtps://"+hostname+":465", w.Domain, "https://"+w.Domain,
		davSection("caldav", w.CalDAV), davSection("carddav", w.CardDAV), w.Plugins.GPG, w.Plugins.ManageSieve, w.Plugins.Password, PasswordHelper)
}

// davSection renders the [plugin.<name>] section of a CalDAV or CardDAV default.
// The server line is left out when none is set, so each user enters their own.
func davSection(name string, d config.DAVServer) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[plugin.%s]\nenabled = %t\n", name, d.Enabled)
	if d.Server != "" {
		fmt.Fprintf(&b, "server = %q\n", d.Server)
	}
	return b.String()
}

// AlpsUnitFile renders the systemd unit. alps needs no write access and no root.
func AlpsUnitFile() string {
	return `# Managed by mailadmin install.
[Unit]
Description=mailadmin webmail (alps)
After=network-online.target dovecot.service postfix.service
Wants=network-online.target

[Service]
User=` + AlpsUser + `
Group=` + AlpsUser + `
ExecStart=` + AlpsBin + ` -config ` + AlpsConfPath + `
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
`
}

// AlpsSudoersFile lets the alps user run the password helper as root with any
// mailbox address and nothing else. The helper checks the current password before
// it changes anything.
func AlpsSudoersFile() string {
	return "# Managed by mailadmin install.\n" +
		AlpsUser + " ALL=(root) NOPASSWD: " + PasswordHelper + " webmail-passwd *\n"
}

// CaddyWebmailFile routes the webmail domain to alps. Caddy obtains the certificate
// for the domain itself.
func CaddyWebmailFile(w config.Webmail) string {
	return fmt.Sprintf(`# Managed by mailadmin install.
%s {
	header {
		Strict-Transport-Security "max-age=63072000"
		X-Content-Type-Options "nosniff"
		-Server
	}
	reverse_proxy %s
}
`, w.Domain, w.Listen)
}

// fetchAlps downloads the alps binary from url and returns it only when its sha256
// matches want. Nothing is returned on a mismatch.
func fetchAlps(ctx context.Context, url, want string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, alpsFetchWait)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch alps: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch alps: HTTP %d", resp.StatusCode)
	}
	bin, err := io.ReadAll(io.LimitReader(resp.Body, maxAlpsBinary+1))
	if err != nil {
		return nil, fmt.Errorf("read alps: %w", err)
	}
	if len(bin) > maxAlpsBinary {
		return nil, fmt.Errorf("alps: binary larger than %d bytes", maxAlpsBinary)
	}
	if got := sha256Hex(bin); got != want {
		return nil, fmt.Errorf("alps checksum mismatch: got %s, want %s", got, want)
	}
	return bin, nil
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ApplyWebmail installs alps as a service and routes the webmail domain to it. Nothing
// is changed when webmail is disabled. The binary is checked against the pinned
// sha256 before anything is written.
func ApplyWebmail(ctx context.Context, x Exec, w config.Webmail, hostname string) error {
	if !w.Enabled {
		return nil
	}
	bin, err := fetchAlps(ctx, w.URL, w.SHA256)
	if err != nil {
		return err
	}
	if err := EnsureUser(ctx, x, AlpsUser, "/nonexistent", 0); err != nil {
		return err
	}
	if err := RecordUsers(AlpsUser); err != nil {
		return err
	}
	if err := writeAtomic(AlpsBin, bin, 0o755); err != nil { // #nosec G306 -- root-owned executable
		return err
	}
	if err := writeAtomic(AlpsConfPath, []byte(AlpsConf(w, hostname)), 0o644); err != nil {
		return err
	}
	if err := writeAtomic(AlpsUnitPath, []byte(AlpsUnitFile()), 0o644); err != nil {
		return err
	}
	if err := writeAtomic(AlpsSudoers, []byte(AlpsSudoersFile()), 0o440); err != nil {
		return err
	}
	if _, err := x.Run(ctx, nil, "visudo", "-cf", AlpsSudoers); err != nil {
		return fmt.Errorf("sudoers rule for the webmail password helper is invalid: %w", err)
	}
	if err := writeAtomic(CaddyWebmail, []byte(CaddyWebmailFile(w)), 0o644); err != nil {
		return err
	}
	if _, err := x.Run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if _, err := x.Run(ctx, nil, "caddy", "validate", "--config", CaddyfilePath, "--adapter", "caddyfile"); err != nil {
		return fmt.Errorf("caddy validate with webmail route: %w", err)
	}
	if err := EnableUnit(ctx, x, AlpsUnit); err != nil {
		return err
	}
	if _, err := x.Run(ctx, nil, "systemctl", "reload", "caddy"); err != nil {
		return fmt.Errorf("reload caddy: %w", err)
	}
	return nil
}
