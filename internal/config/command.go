package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ConfigView is the redacted, presentable form of a loaded config for
// `config show` (never includes secret values).
type ConfigView struct {
	Path             string   `json:"path"`
	PostgresService  string   `json:"postgres_service"`
	MailHostname     string   `json:"mail_hostname"`
	DefaultSelector  string   `json:"default_selector"`
	IPv4             string   `json:"ipv4"`
	IPv6             string   `json:"ipv6"`
	Resolver         string   `json:"resolver"`
	DNSBackupDir     string   `json:"dns_backup_dir"`
	LogUnits         []string `json:"log_units"`
	NjallaConfigured bool     `json:"njalla_configured"`
	DeSECConfigured  bool     `json:"desec_configured"`
	RspamdConfigured bool     `json:"rspamd_configured"`
}

// CheckResult reports one config/secret sanity check for `config check`.
type CheckResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// View builds the redacted view for `config show`.
func View(c *Config, s *Secrets) ConfigView {
	return ConfigView{
		Path:             c.Path,
		PostgresService:  c.Postgres.Service,
		MailHostname:     c.Mail.Hostname,
		DefaultSelector:  c.Mail.DefaultSelector,
		IPv4:             c.Server.IPv4,
		IPv6:             c.Server.IPv6,
		Resolver:         c.DNS.Resolver,
		DNSBackupDir:     c.Backup.DNSBackupDir,
		LogUnits:         c.Logs.Units,
		NjallaConfigured: s.HasNjalla(),
		DeSECConfigured:  s.HasDeSEC(),
		RspamdConfigured: s.RspamdControllerPW() != "",
	}
}

// Check runs config/secret sanity checks for `config check`. It reports the
// state of on-disk dependencies (paths, permissions, configured secrets)
// without printing any secret value. It returns an error only on an internal
// failure; per-check problems surface as OK=false results so the caller can
// render the full picture.
func Check(c *Config, s *Secrets) ([]CheckResult, error) {
	if c == nil || s == nil {
		return nil, fmt.Errorf("%w: nil config or secrets", ErrInvalidConfig)
	}

	var results []CheckResult
	add := func(name string, ok bool, detail string) {
		results = append(results, CheckResult{Name: name, OK: ok, Detail: detail})
	}

	if err := c.Validate(); err != nil {
		add("config", false, err.Error())
	} else {
		add("config", true, "syntax and values valid")
	}

	add("dkim_dir", dirExists(c.Mail.DKIMDir), c.Mail.DKIMDir)
	add("dns_backup_dir", dirExists(c.Backup.DNSBackupDir), c.Backup.DNSBackupDir)

	if c.Postgres.ServiceFile == "" {
		add("postgres_service_file", true, "not set (using default libpq lookup)")
	} else {
		add("postgres_service_file", fileExists(c.Postgres.ServiceFile), c.Postgres.ServiceFile)
	}

	secretsOK, secretsDetail := secretsFileState(c.secretsPath())
	add("secrets_file", secretsOK, secretsDetail)

	add("njalla_token", s.HasNjalla(), configuredDetail(s.HasNjalla()))
	add("desec_token", s.HasDeSEC(), configuredDetail(s.HasDeSEC()))
	add("cloudflare_api_token", s.HasCloudflare(), configuredDetail(s.HasCloudflare()))
	add("inwx", s.HasINWX(), configuredDetail(s.HasINWX()))
	add("servercow", s.HasServercow(), configuredDetail(s.HasServercow()))
	add("servfail", s.HasServfail(), configuredDetail(s.HasServfail()))
	add("rspamd_controller_pw", s.RspamdControllerPW() != "", configuredDetail(s.RspamdControllerPW() != ""))

	return results, nil
}

// secretsFileState reports whether secrets.env exists with owner-only 0600
// permissions, reusing the same rules LoadSecrets enforces. It never reveals
// file contents.
func secretsFileState(path string) (ok bool, detail string) {
	if _, err := LoadSecrets(path); err != nil {
		return false, err.Error()
	}
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, path + " missing"
	}
	if err != nil {
		return false, err.Error()
	}
	return true, fmt.Sprintf("%s mode %#o", path, fi.Mode().Perm())
}

func configuredDetail(ok bool) string {
	if ok {
		return "configured"
	}
	return "not configured"
}

func dirExists(path string) bool {
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// starterConfig is the commented template written by Init.
const starterConfig = `[postgres]
service      = "mail-admin"
service_file = "/var/lib/mailadmin/.pg_service.conf"

[mail]
hostname         = "mail.example.com"
dkim_dir         = "/var/lib/rspamd/dkim"
default_selector = "mail2026"

[server]
ipv4 = "203.0.113.10"
ipv6 = "2001:db8::10"

[dns]
resolver = "1.1.1.1:53"

[backup]
dns_backup_dir = "/var/lib/mailadmin/dns-backups"

[logs]
units = ["postfix", "dovecot", "rspamd", "caddy", "crowdsec", "postgresql"]
`

// starterSecrets is the template written by Init (values left blank; 0600).
const starterSecrets = `# mailadmin secrets — mode 0600, root only. Never commit or share.
# Set the credentials for whichever DNS provider you use (only one is needed).
NJALLA_TOKEN=
DESEC_TOKEN=
CLOUDFLARE_API_TOKEN=
INWX_USER=
INWX_PASSWORD=
INWX_SHARED_SECRET=
SERVERCOW_USERNAME=
SERVERCOW_PASSWORD=
SERVFAIL_API_KEY=
SERVFAIL_SERVER=
RSPAMD_CONTROLLER_PW=
` // #nosec G101 -- template with empty values, not a hardcoded credential

// Init writes a starter config.toml (0644) and secrets.env (0600) in dir,
// creating the directory (0755) if needed and refusing to overwrite either
// existing file. It returns the two paths it wrote.
func Init(dir string) (configPath, secretsPath string, err error) {
	if dir == "" {
		return "", "", fmt.Errorf("%w: empty target directory", ErrInvalidConfig)
	}
	// The config directory is intentionally traversable (0755): config.toml is
	// world-readable (0644) by design; secrets.env is protected by its own 0600
	// mode, not by directory permissions.
	// #nosec G301 -- config dir is deliberately world-traversable; secrets.env is 0600
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", fmt.Errorf("config init: mkdir: %w", err)
	}

	configPath = filepath.Join(dir, "config.toml")
	secretsPath = filepath.Join(dir, SecretsFile)

	if err := writeNew(configPath, []byte(starterConfig), 0o644); err != nil {
		return "", "", err
	}
	if err := writeNew(secretsPath, []byte(starterSecrets), 0o600); err != nil {
		return "", "", err
	}
	return configPath, secretsPath, nil
}

// writeNew creates path with the given mode, failing if it already exists so a
// re-run never clobbers real config or secrets.
func writeNew(path string, data []byte, mode os.FileMode) error {
	// path is the operator-chosen config directory target (root CLI); O_EXCL
	// refuses to follow into or clobber an existing file. No untrusted input.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304 -- operator-supplied config path, O_EXCL create
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("config init: %s already exists (refusing to overwrite)", path)
		}
		return fmt.Errorf("config init: create %s: %w", path, err)
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return fmt.Errorf("config init: write %s: %w", path, werr)
	}
	if cerr := f.Close(); cerr != nil {
		return fmt.Errorf("config init: close %s: %w", path, cerr)
	}
	return nil
}
