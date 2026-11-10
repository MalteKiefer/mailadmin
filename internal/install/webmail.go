package install

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"mailadmin/internal/config"
)

// Webmail paths and names. The alps binary and its unit are managed by mailadmin;
// uninstall removes them through the install journal and the mailadmin-* globs.
const (
	AlpsBin       = "/usr/local/libexec/mailadmin-alps"
	AlpsConfPath  = "/etc/mailadmin/alps.toml"
	AlpsUnit      = "mailadmin-webmail.service"
	AlpsUnitPath  = "/etc/systemd/system/" + AlpsUnit
	AlpsUser      = "alps"
	CaddyWebmail  = CaddyIncludeDir + "/webmail.caddy"
	alpsZipName   = "alps-linux-amd64.zip"
	alpsBinEntry  = "alps-linux-amd64"
	maxAlpsZip    = 64 << 20
	alpsFetchWait = 2 * time.Minute
)

// alpsReleaseBase is the GitHub release location. Tests replace it.
var alpsReleaseBase = "https://github.com/migadu/alps/releases/download"

// AlpsConf renders the alps configuration. alps listens on the local address of
// the webmail config, Caddy proxies the domain to it, and alps talks to the local
// mail host over implicit TLS (IMAP 993, submission 465), so certificates are
// verified against the mail host name.
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
`, w.Listen, "https://"+w.Domain, "imaps://"+hostname+":993", "smtps://"+hostname+":465")
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

// CaddyWebmailFile routes the webmail domain to alps. Caddy obtains the
// certificate for the domain itself.
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

// ExtractAlps returns the alps binary from the release zip after checking its
// sha256 against want. A mismatch is an error and nothing is returned.
func ExtractAlps(zipData []byte, want string) ([]byte, error) {
	sum := sha256.Sum256(zipData)
	if got := hex.EncodeToString(sum[:]); got != want {
		return nil, fmt.Errorf("alps release checksum mismatch: got %s, want %s", got, want)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("alps release zip: %w", err)
	}
	for _, f := range zr.File {
		if path.Base(f.Name) != alpsBinEntry || strings.Contains(f.Name, "__MACOSX") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open %s in alps zip: %w", f.Name, err)
		}
		bin, err := io.ReadAll(io.LimitReader(rc, maxAlpsZip))
		_ = rc.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s from alps zip: %w", f.Name, err)
		}
		return bin, nil
	}
	return nil, fmt.Errorf("alps zip has no %s", alpsBinEntry)
}

// fetchAlpsZip downloads the release zip for version.
func fetchAlpsZip(ctx context.Context, version string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, alpsFetchWait)
	defer cancel()
	url := alpsReleaseBase + "/" + version + "/" + alpsZipName
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch alps %s: %w", version, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch alps %s: HTTP %d", version, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAlpsZip+1))
	if err != nil {
		return nil, fmt.Errorf("read alps %s: %w", version, err)
	}
	if len(data) > maxAlpsZip {
		return nil, fmt.Errorf("alps %s: release larger than %d bytes", version, maxAlpsZip)
	}
	return data, nil
}

// ApplyWebmail installs alps as a service and routes the webmail domain to it.
// Nothing is changed when webmail is disabled. The release is checked against
// the pinned sha256 before anything is written.
func ApplyWebmail(ctx context.Context, x Exec, w config.Webmail, hostname string) error {
	if !w.Enabled {
		return nil
	}
	zipData, err := fetchAlpsZip(ctx, w.Version)
	if err != nil {
		return err
	}
	bin, err := ExtractAlps(zipData, w.SHA256)
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
