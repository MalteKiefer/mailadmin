// Package config loads mailadmin's non-secret TOML config and the 0600
// secrets.env, validates them, and applies MAILADMIN_* environment overrides.
//
// Secrets live in Secrets, a type deliberately without a leaking String() or
// marshaler, so they cannot be printed, logged, or serialised by accident.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"mailadmin/internal/valid"
)

// DefaultPath is the config location used when nothing else is configured.
// Discover finds the config file in the directory of this path.
const DefaultPath = "/etc/mailadmin/config.toml"

// ConfigDir is the directory mailadmin keeps its single config file in.
const ConfigDir = "/etc/mailadmin"

// SecretsFile is the fixed basename of the secrets file, resolved relative to
// the directory holding the TOML config.
const SecretsFile = "secrets.env"

// Secret env-var keys understood in secrets.env.
const (
	keyNjallaToken      = "NJALLA_TOKEN"         // #nosec G101 -- env-var name, not a credential value
	keyDeSECToken       = "DESEC_TOKEN"          // #nosec G101 -- env-var name, not a credential value
	keyCloudflareToken  = "CLOUDFLARE_API_TOKEN" // #nosec G101 -- env-var name, not a credential value
	keyINWXUser         = "INWX_USER"            // #nosec G101 -- env-var name, not a credential value
	keyINWXPassword     = "INWX_PASSWORD"        // #nosec G101 -- env-var name, not a credential value
	keyINWXSharedSecret = "INWX_SHARED_SECRET"   // #nosec G101 -- env-var name, not a credential value
	keyServercowUser    = "SERVERCOW_USERNAME"   // #nosec G101 -- env-var name, not a credential value
	keyServercowPass    = "SERVERCOW_PASSWORD"   // #nosec G101 -- env-var name, not a credential value
	keyServfailAPIKey   = "SERVFAIL_API_KEY"     // #nosec G101 -- env-var name, not a credential value
	keyServfailServer   = "SERVFAIL_SERVER"      // #nosec G101 -- env-var name, not a credential value
	keyRspamdPW         = "RSPAMD_CONTROLLER_PW" // #nosec G101 -- env-var name, not a credential value
	keyNtfyToken        = "NTFY_TOKEN"           // #nosec G101 -- env-var name, not a credential value
	keyBorgPassphrase   = "BORG_PASSPHRASE"      // #nosec G101 -- env-var name, not a credential value
)

// reFingerprint matches an OpenPGP primary key fingerprint (40 hex digits).
var reFingerprint = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)

// ErrInvalidConfig is wrapped by all validation failures.
var ErrInvalidConfig = errors.New("invalid config")

// ErrInsecureSecrets is wrapped when secrets.env is not exclusively owner-only.
var ErrInsecureSecrets = errors.New("insecure secrets file")

// Postgres holds DB connection config.
type Postgres struct {
	Service     string `toml:"service"`
	ServiceFile string `toml:"service_file"`
}

// Mail holds mail-host and DKIM config.
type Mail struct {
	Hostname        string `toml:"hostname"`
	DKIMDir         string `toml:"dkim_dir"`
	DefaultSelector string `toml:"default_selector"`
	// TLSCert is the mail host's TLS certificate (PEM) used to derive DANE TLSA
	// records. Optional; when empty, TLSA is read live via STARTTLS on port 25.
	TLSCert string `toml:"tls_cert"`
	// TLSMode is "acme" (public CA, the default) or "internal" (Caddy's local CA).
	TLSMode string `toml:"tls_mode"`
	// QuotaDefault is the quota in bytes for mailbox add without --quota; 0 means 5 GiB.
	QuotaDefault int64 `toml:"quota_default"`
	// DNSTTL is the TTL in seconds of the records mailadmin publishes. 0 means DefaultDNSTTL.
	DNSTTL int `toml:"dns_ttl"`
}

// Hardening switches the parts of install's host hardening on or off. Unset
// values mean on, so a config without the table keeps the full hardening.
type Hardening struct {
	System   *bool `toml:"system"`
	SSH      *bool `toml:"ssh"`
	CrowdSec *bool `toml:"crowdsec"`
}

// On reports whether a switch is on (unset counts as on).
func On(b *bool) bool { return b == nil || *b }

// Repos holds the expected fingerprints of the vendor repository keys.
type Repos struct {
	PGDGFingerprint     string `toml:"pgdg_fingerprint"`
	CaddyFingerprint    string `toml:"caddy_fingerprint"`
	CrowdSecFingerprint string `toml:"crowdsec_fingerprint"`
}

// Server holds the public server addresses.
type Server struct {
	IPv4 string `toml:"ipv4"`
	IPv6 string `toml:"ipv6"`
}

// DNS holds resolver config for verification.
type DNS struct {
	Resolver string `toml:"resolver"`
}

// Backup holds paths for DNS snapshots and full disaster-recovery bundles.
type Backup struct {
	DNSBackupDir string `toml:"dns_backup_dir"`
	// Dir is the default directory `backup create`/`backup list` use for
	// full DR bundles (DB dump + DKIM keys + Sieve scripts + config.toml).
	// Optional: unset means the operator must pass --out/--dir explicitly.
	Dir string `toml:"dir"`
	// Borg archives the bundles of backup create to a Borg repository.
	Borg BorgBackup `toml:"borg"`
}

// Logs holds the unit allowlist for the log/journal commands.
type Logs struct {
	Units []string `toml:"units"`
}

// Notify holds the ntfy.sh alerting target for `doctor --notify` and
// `dns drift-check --notify`. URL is not secret (the topic is only useful
// with its bearer token, which lives in secrets.env as NTFY_TOKEN); it is
// entirely optional, an unset URL (or a missing token) simply means
// --notify no-ops instead of erroring, so a fresh install never breaks on
// this.
type Notify struct {
	URL string `toml:"url"`
}

// Config is the fully-parsed, validated configuration. Secrets are part of it
// in the [secrets] table (same key names as secrets.env); the config file then
// has to be 0600.
type Config struct {
	Postgres  Postgres          `toml:"postgres"`
	Mail      Mail              `toml:"mail"`
	Server    Server            `toml:"server"`
	DNS       DNS               `toml:"dns"`
	Backup    Backup            `toml:"backup"`
	Webmail   Webmail           `toml:"webmail"`
	Timeouts  Timeouts          `toml:"timeouts"`
	Logs      Logs              `toml:"logs"`
	Notify    Notify            `toml:"notify"`
	Hardening Hardening         `toml:"hardening"`
	Repos     Repos             `toml:"repos"`
	Secrets   map[string]string `toml:"secrets"`

	// Path is the file this config was loaded from (not serialised).
	Path string `toml:"-"`
}

// Secrets holds sensitive values from secrets.env. It intentionally provides no
// String, GoString, MarshalText, or MarshalJSON so it cannot leak via fmt/json.
type Secrets struct {
	njallaToken      string
	desecToken       string
	cloudflareToken  string
	inwxUser         string
	inwxPassword     string
	inwxSharedSecret string
	servercowUser    string
	servercowPass    string
	servfailAPIKey   string
	servfailServer   string
	rspamdControllPW string
	ntfyToken        string
	borgPassphrase   string
}

// BorgPassphrase returns the Borg repository passphrase (empty if unset).
func (s *Secrets) BorgPassphrase() string { return s.borgPassphrase }

// HasBorgPassphrase reports whether a Borg passphrase is configured.
func (s *Secrets) HasBorgPassphrase() bool { return s.borgPassphrase != "" }

// NjallaToken returns the Njalla API token (empty if unset).
func (s *Secrets) NjallaToken() string { return s.njallaToken }

// DeSECToken returns the deSEC API token (empty if unset).
func (s *Secrets) DeSECToken() string { return s.desecToken }

// HasDeSEC reports whether a non-empty deSEC token is configured.
func (s *Secrets) HasDeSEC() bool { return s.desecToken != "" }

// CloudflareToken returns the Cloudflare API token (empty if unset).
func (s *Secrets) CloudflareToken() string { return s.cloudflareToken }

// HasCloudflare reports whether a Cloudflare API token is configured.
func (s *Secrets) HasCloudflare() bool { return s.cloudflareToken != "" }

// INWXUser / INWXPassword / INWXSharedSecret return the INWX credentials. The
// shared secret is the base32 TOTP seed and is only needed when the account has
// two-factor authentication enabled.
func (s *Secrets) INWXUser() string         { return s.inwxUser }
func (s *Secrets) INWXPassword() string     { return s.inwxPassword }
func (s *Secrets) INWXSharedSecret() string { return s.inwxSharedSecret }

// HasINWX reports whether INWX username and password are both configured.
func (s *Secrets) HasINWX() bool { return s.inwxUser != "" && s.inwxPassword != "" }

// ServercowUser / ServercowPassword return the Servercow DNS-API credentials.
func (s *Secrets) ServercowUser() string     { return s.servercowUser }
func (s *Secrets) ServercowPassword() string { return s.servercowPass }

// HasServercow reports whether Servercow username and password are both set.
func (s *Secrets) HasServercow() bool { return s.servercowUser != "" && s.servercowPass != "" }

// ServfailAPIKey / ServfailServer return the servfail.network PowerDNS API key
// and the primary-nameserver server id (the FQDN, including trailing dot, shown
// in the zone's SOA / account dashboard).
func (s *Secrets) ServfailAPIKey() string { return s.servfailAPIKey }
func (s *Secrets) ServfailServer() string { return s.servfailServer }

// HasServfail reports whether the servfail.network API key and server id are set.
func (s *Secrets) HasServfail() bool { return s.servfailAPIKey != "" && s.servfailServer != "" }

// RspamdControllerPW returns the rspamd controller password (empty if unset).
func (s *Secrets) RspamdControllerPW() string { return s.rspamdControllPW }

// NtfyToken returns the ntfy.sh bearer token (empty if unset).
func (s *Secrets) NtfyToken() string { return s.ntfyToken }

// HasNtfy reports whether a non-empty ntfy.sh token is configured. Note this
// only reports the secret half, `doctor --notify`/`dns drift-check
// --notify` also need notify.url set in config.toml before an alert can
// actually be sent (see notify.Config.Configured).
func (s *Secrets) HasNtfy() bool { return s.ntfyToken != "" }

// HasNjalla reports whether a non-empty Njalla token is configured.
func (s *Secrets) HasNjalla() bool { return s.njallaToken != "" }

// String masks all secret content so accidental printing never leaks values.
func (s *Secrets) String() string { return "config.Secrets{REDACTED}" }

// GoString masks secrets under the %#v verb as well.
func (s *Secrets) GoString() string { return "config.Secrets{REDACTED}" }

// Load reads and validates the TOML config at path, applies MAILADMIN_*
// overrides, and loads secrets.env from the same directory (0600 enforced).
//
// It fails closed: any decode, override, validation, or secrets error returns a
// wrapped error and nil results.
func Load(path string) (*Config, *Secrets, error) {
	text, err := readTOML(path)
	if err != nil {
		return nil, nil, err
	}
	var c Config
	md, err := toml.Decode(string(text), &c)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return nil, nil, fmt.Errorf("%w: unknown key %q", ErrInvalidConfig, undecoded[0].String())
	}
	c.Path = path

	c.applyEnvOverrides(os.Getenv)
	c.normalize()

	if err := c.Validate(); err != nil {
		return nil, nil, err
	}

	secrets, err := c.loadSecrets()
	if err != nil {
		return nil, nil, err
	}
	return &c, secrets, nil
}

// loadSecrets merges the [secrets] table of the config file with a legacy
// secrets.env next to it (the table wins). A config that holds secrets must be
// owner-only, like secrets.env.
func (c *Config) loadSecrets() (*Secrets, error) {
	m, err := readSecretsFile(c.secretsPath())
	if err != nil {
		return nil, err
	}
	if len(c.Secrets) > 0 {
		fi, err := os.Stat(c.Path)
		if err != nil {
			return nil, fmt.Errorf("config: stat: %w", err)
		}
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			return nil, fmt.Errorf("%w: %s holds secrets and has mode %#o, want 0600", ErrInsecureSecrets, c.Path, perm)
		}
		for k, v := range c.Secrets {
			m[k] = v
		}
	}
	return SecretsFromMap(m), nil
}

// secretsPath returns secrets.env in the same directory as the TOML config.
func (c *Config) secretsPath() string {
	return filepath.Join(filepath.Dir(c.Path), SecretsFile)
}

// normalize trims surrounding whitespace from string fields.
func (c *Config) normalize() {
	c.Postgres.Service = strings.TrimSpace(c.Postgres.Service)
	c.Postgres.ServiceFile = strings.TrimSpace(c.Postgres.ServiceFile)
	c.Mail.Hostname = strings.TrimSpace(c.Mail.Hostname)
	c.Mail.DKIMDir = strings.TrimSpace(c.Mail.DKIMDir)
	c.Mail.DefaultSelector = strings.TrimSpace(c.Mail.DefaultSelector)
	c.Mail.TLSCert = strings.TrimSpace(c.Mail.TLSCert)
	c.Server.IPv4 = strings.TrimSpace(c.Server.IPv4)
	c.Server.IPv6 = strings.TrimSpace(c.Server.IPv6)
	c.DNS.Resolver = strings.TrimSpace(c.DNS.Resolver)
	c.Backup.DNSBackupDir = strings.TrimSpace(c.Backup.DNSBackupDir)
	c.Backup.Dir = strings.TrimSpace(c.Backup.Dir)
	c.Webmail.Domain = strings.ToLower(strings.TrimSpace(c.Webmail.Domain))
	c.Backup.Borg.Repo = strings.TrimSpace(c.Backup.Borg.Repo)
	c.Notify.URL = strings.TrimSpace(c.Notify.URL)
	for i := range c.Logs.Units {
		c.Logs.Units[i] = strings.TrimSpace(c.Logs.Units[i])
	}
}

// applyEnvOverrides applies MAILADMIN_* overrides. getenv is injected so the
// logic is testable without touching the real process environment.
func (c *Config) applyEnvOverrides(getenv func(string) string) {
	overrides := []struct {
		key string
		dst *string
	}{
		{"MAILADMIN_POSTGRES_SERVICE", &c.Postgres.Service},
		{"MAILADMIN_POSTGRES_SERVICE_FILE", &c.Postgres.ServiceFile},
		{"MAILADMIN_MAIL_HOSTNAME", &c.Mail.Hostname},
		{"MAILADMIN_MAIL_DKIM_DIR", &c.Mail.DKIMDir},
		{"MAILADMIN_MAIL_DEFAULT_SELECTOR", &c.Mail.DefaultSelector},
		{"MAILADMIN_MAIL_TLS_CERT", &c.Mail.TLSCert},
		{"MAILADMIN_SERVER_IPV4", &c.Server.IPv4},
		{"MAILADMIN_SERVER_IPV6", &c.Server.IPv6},
		{"MAILADMIN_DNS_RESOLVER", &c.DNS.Resolver},
		{"MAILADMIN_BACKUP_DNS_BACKUP_DIR", &c.Backup.DNSBackupDir},
		{"MAILADMIN_BACKUP_DIR", &c.Backup.Dir},
		{"MAILADMIN_NOTIFY_URL", &c.Notify.URL},
	}
	for _, o := range overrides {
		if v := getenv(o.key); v != "" {
			*o.dst = v
		}
	}
	if v := getenv("MAILADMIN_LOGS_UNITS"); v != "" {
		fields := strings.Split(v, ",")
		units := make([]string, 0, len(fields))
		for _, f := range fields {
			if f = strings.TrimSpace(f); f != "" {
				units = append(units, f)
			}
		}
		c.Logs.Units = units
	}
}

// DSN returns the libpq connection string ("service=<name>") for the pool.
func (c *Config) DSN() string {
	return "service=" + c.Postgres.Service
}

// Validate checks required keys and value formats, failing closed.
func (c *Config) Validate() error {
	if c.Postgres.Service == "" {
		return fmt.Errorf("%w: postgres.service is required", ErrInvalidConfig)
	}
	if c.Postgres.ServiceFile != "" && !filepath.IsAbs(c.Postgres.ServiceFile) {
		return fmt.Errorf("%w: postgres.service_file must be absolute", ErrInvalidConfig)
	}

	if c.Mail.Hostname == "" {
		return fmt.Errorf("%w: mail.hostname is required", ErrInvalidConfig)
	}
	if _, err := valid.Domain(c.Mail.Hostname); err != nil {
		return fmt.Errorf("%w: mail.hostname: %w", ErrInvalidConfig, err)
	}
	if c.Mail.DKIMDir == "" || !filepath.IsAbs(c.Mail.DKIMDir) {
		return fmt.Errorf("%w: mail.dkim_dir must be an absolute path", ErrInvalidConfig)
	}
	if c.Mail.DefaultSelector == "" {
		return fmt.Errorf("%w: mail.default_selector is required", ErrInvalidConfig)
	}
	if _, err := valid.Selector(c.Mail.DefaultSelector); err != nil {
		return fmt.Errorf("%w: mail.default_selector: %w", ErrInvalidConfig, err)
	}

	if c.Mail.DNSTTL != 0 && (c.Mail.DNSTTL < 60 || c.Mail.DNSTTL > 86400) {
		return fmt.Errorf("%w: mail.dns_ttl must be 0 (default %d) or 60 to 86400 seconds", ErrInvalidConfig, DefaultDNSTTL)
	}
	if err := c.Timeouts.validate(); err != nil {
		return err
	}

	if c.Server.IPv4 == "" {
		return fmt.Errorf("%w: server.ipv4 is required", ErrInvalidConfig)
	}
	if ip := net.ParseIP(c.Server.IPv4); ip == nil || ip.To4() == nil {
		return fmt.Errorf("%w: server.ipv4 is not a valid IPv4 address", ErrInvalidConfig)
	}
	if c.Server.IPv6 != "" {
		if ip := net.ParseIP(c.Server.IPv6); ip == nil || ip.To4() != nil {
			return fmt.Errorf("%w: server.ipv6 is not a valid IPv6 address", ErrInvalidConfig)
		}
	}

	if c.Mail.TLSMode != "" && c.Mail.TLSMode != "acme" && c.Mail.TLSMode != "internal" {
		return fmt.Errorf("%w: mail.tls_mode must be acme or internal", ErrInvalidConfig)
	}
	if c.Mail.QuotaDefault < 0 {
		return fmt.Errorf("%w: mail.quota_default must be >= 0", ErrInvalidConfig)
	}
	for _, fp := range []string{c.Repos.PGDGFingerprint, c.Repos.CaddyFingerprint, c.Repos.CrowdSecFingerprint} {
		if fp != "" && !reFingerprint.MatchString(fp) {
			return fmt.Errorf("%w: repos.*_fingerprint must be 40 hex digits", ErrInvalidConfig)
		}
	}

	if c.DNS.Resolver == "" {
		return fmt.Errorf("%w: dns.resolver is required", ErrInvalidConfig)
	}
	if err := validateHostPort(c.DNS.Resolver); err != nil {
		return fmt.Errorf("%w: dns.resolver: %w", ErrInvalidConfig, err)
	}

	if c.Backup.DNSBackupDir == "" || !filepath.IsAbs(c.Backup.DNSBackupDir) {
		return fmt.Errorf("%w: backup.dns_backup_dir must be an absolute path", ErrInvalidConfig)
	}
	// backup.dir is optional (unlike dns_backup_dir): a fresh deployed config
	// without it should still validate, and `mailadmin backup create`/`list`
	// require --out/--dir explicitly when it is unset. When set, it must still
	// be absolute.
	if c.Backup.Dir != "" && !filepath.IsAbs(c.Backup.Dir) {
		return fmt.Errorf("%w: backup.dir must be an absolute path", ErrInvalidConfig)
	}

	if err := c.Webmail.validate(); err != nil {
		return err
	}
	if err := c.Backup.Borg.validate(c.Backup.Dir); err != nil {
		return err
	}

	if c.Notify.URL != "" && !strings.HasPrefix(c.Notify.URL, "https://") && !strings.HasPrefix(c.Notify.URL, "http://") {
		return fmt.Errorf("%w: notify.url must start with http:// or https://", ErrInvalidConfig)
	}

	if len(c.Logs.Units) == 0 {
		return fmt.Errorf("%w: logs.units must list at least one unit", ErrInvalidConfig)
	}
	for _, u := range c.Logs.Units {
		if _, err := valid.Unit(u); err != nil {
			return fmt.Errorf("%w: logs.units: %w", ErrInvalidConfig, err)
		}
	}
	return nil
}

// validateHostPort ensures s is a host:port with a numeric port in range.
func validateHostPort(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("must be host:port: %w", err)
	}
	if host == "" {
		return errors.New("missing host")
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port %q is not numeric", port)
	}
	if _, err := valid.Port(p); err != nil {
		return err
	}
	return nil
}

// LoadSecrets reads secrets.env, enforcing regular-file 0600 owner-only
// permissions, and returns the parsed Secrets. A missing file is not an error
// (returns empty Secrets so unconfigured providers simply report absent).
func LoadSecrets(path string) (*Secrets, error) {
	m, err := readSecretsFile(path)
	if err != nil {
		return nil, err
	}
	return SecretsFromMap(m), nil
}

// SecretsFromMap builds Secrets from secret keys (the secrets.env names). Unknown
// keys are ignored: they may be read by other tools, and no error echoes a value.
func SecretsFromMap(m map[string]string) *Secrets {
	return &Secrets{
		njallaToken:      m[keyNjallaToken],
		desecToken:       m[keyDeSECToken],
		cloudflareToken:  m[keyCloudflareToken],
		inwxUser:         m[keyINWXUser],
		inwxPassword:     m[keyINWXPassword],
		inwxSharedSecret: m[keyINWXSharedSecret],
		servercowUser:    m[keyServercowUser],
		servercowPass:    m[keyServercowPass],
		servfailAPIKey:   m[keyServfailAPIKey],
		servfailServer:   m[keyServfailServer],
		rspamdControllPW: m[keyRspamdPW],
		ntfyToken:        m[keyNtfyToken],
		borgPassphrase:   m[keyBorgPassphrase],
	}
}

// readSecretsFile returns the KEY=VALUE pairs of secrets.env, or none when the
// file is missing. The file must be a regular 0600 file.
func readSecretsFile(path string) (map[string]string, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("secrets: stat: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s must not be a symlink", ErrInsecureSecrets, path)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrInsecureSecrets, path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %#o, want 0600 (no group/other access)", ErrInsecureSecrets, path, perm)
	}
	f, err := os.Open(path) // #nosec G304 -- secrets file next to the config, permission-checked above
	if err != nil {
		return nil, fmt.Errorf("secrets: open: %w", err)
	}
	defer func() { _ = f.Close() }()
	m := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if key, val, ok := parseEnvLine(sc.Text()); ok {
			m[key] = val
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("secrets: read: %w", err)
	}
	return m, nil
}

// parseEnvLine parses a single KEY=VALUE secrets line. It skips blanks and
// comments, tolerates a leading "export ", and strips one layer of matching
// single or double quotes. The value is never logged by callers.
func parseEnvLine(raw string) (key, val string, ok bool) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	line = strings.TrimPrefix(line, "export ")
	eq := strings.IndexByte(line, '=')
	if eq <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:eq])
	val = strings.TrimSpace(line[eq+1:])
	if len(val) >= 2 {
		if (val[0] == '"' && val[len(val)-1] == '"') ||
			(val[0] == '\'' && val[len(val)-1] == '\'') {
			val = val[1 : len(val)-1]
		}
	}
	if key == "" {
		return "", "", false
	}
	return key, val, true
}
