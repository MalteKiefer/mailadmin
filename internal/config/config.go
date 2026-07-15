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
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"mailadmin/internal/valid"
)

// DefaultPath is the standard config location.
const DefaultPath = "/etc/mailadmin/config.toml"

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
)

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

// Backup holds paths for DNS snapshots.
type Backup struct {
	DNSBackupDir string `toml:"dns_backup_dir"`
}

// Logs holds the unit allowlist for the log/journal commands.
type Logs struct {
	Units []string `toml:"units"`
}

// Config is the fully-parsed, validated, non-secret configuration.
type Config struct {
	Postgres Postgres `toml:"postgres"`
	Mail     Mail     `toml:"mail"`
	Server   Server   `toml:"server"`
	DNS      DNS      `toml:"dns"`
	Backup   Backup   `toml:"backup"`
	Logs     Logs     `toml:"logs"`

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
}

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
	var c Config
	md, err := toml.DecodeFile(path, &c)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return nil, nil, fmt.Errorf("%w: unknown key %q", ErrInvalidConfig, undecoded[0].String())
	}
	c.Path = path

	if err := c.applyEnvOverrides(os.Getenv); err != nil {
		return nil, nil, err
	}
	c.normalize()

	if err := c.Validate(); err != nil {
		return nil, nil, err
	}

	secrets, err := LoadSecrets(c.secretsPath())
	if err != nil {
		return nil, nil, err
	}
	return &c, secrets, nil
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
	c.Server.IPv4 = strings.TrimSpace(c.Server.IPv4)
	c.Server.IPv6 = strings.TrimSpace(c.Server.IPv6)
	c.DNS.Resolver = strings.TrimSpace(c.DNS.Resolver)
	c.Backup.DNSBackupDir = strings.TrimSpace(c.Backup.DNSBackupDir)
	for i := range c.Logs.Units {
		c.Logs.Units[i] = strings.TrimSpace(c.Logs.Units[i])
	}
}

// applyEnvOverrides applies MAILADMIN_* overrides. getenv is injected so the
// logic is testable without touching the real process environment.
func (c *Config) applyEnvOverrides(getenv func(string) string) error {
	overrides := []struct {
		key string
		dst *string
	}{
		{"MAILADMIN_POSTGRES_SERVICE", &c.Postgres.Service},
		{"MAILADMIN_POSTGRES_SERVICE_FILE", &c.Postgres.ServiceFile},
		{"MAILADMIN_MAIL_HOSTNAME", &c.Mail.Hostname},
		{"MAILADMIN_MAIL_DKIM_DIR", &c.Mail.DKIMDir},
		{"MAILADMIN_MAIL_DEFAULT_SELECTOR", &c.Mail.DefaultSelector},
		{"MAILADMIN_SERVER_IPV4", &c.Server.IPv4},
		{"MAILADMIN_SERVER_IPV6", &c.Server.IPv6},
		{"MAILADMIN_DNS_RESOLVER", &c.DNS.Resolver},
		{"MAILADMIN_BACKUP_DNS_BACKUP_DIR", &c.Backup.DNSBackupDir},
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
	return nil
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
		return fmt.Errorf("%w: mail.hostname: %v", ErrInvalidConfig, err)
	}
	if c.Mail.DKIMDir == "" || !filepath.IsAbs(c.Mail.DKIMDir) {
		return fmt.Errorf("%w: mail.dkim_dir must be an absolute path", ErrInvalidConfig)
	}
	if c.Mail.DefaultSelector == "" {
		return fmt.Errorf("%w: mail.default_selector is required", ErrInvalidConfig)
	}
	if _, err := valid.Selector(c.Mail.DefaultSelector); err != nil {
		return fmt.Errorf("%w: mail.default_selector: %v", ErrInvalidConfig, err)
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

	if c.DNS.Resolver == "" {
		return fmt.Errorf("%w: dns.resolver is required", ErrInvalidConfig)
	}
	if err := validateHostPort(c.DNS.Resolver); err != nil {
		return fmt.Errorf("%w: dns.resolver: %v", ErrInvalidConfig, err)
	}

	if c.Backup.DNSBackupDir == "" || !filepath.IsAbs(c.Backup.DNSBackupDir) {
		return fmt.Errorf("%w: backup.dns_backup_dir must be an absolute path", ErrInvalidConfig)
	}

	if len(c.Logs.Units) == 0 {
		return fmt.Errorf("%w: logs.units must list at least one unit", ErrInvalidConfig)
	}
	for _, u := range c.Logs.Units {
		if _, err := valid.Unit(u); err != nil {
			return fmt.Errorf("%w: logs.units: %v", ErrInvalidConfig, err)
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
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Secrets{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("secrets: stat: %w", err)
	}
	mode := fi.Mode()
	if mode&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s must not be a symlink", ErrInsecureSecrets, path)
	}
	if !mode.IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrInsecureSecrets, path)
	}
	if perm := mode.Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %#o, want 0600 (no group/other access)", ErrInsecureSecrets, path, perm)
	}

	// path is the secrets file location from the operator's config/--config flag
	// (root CLI); mode was already verified 0600 above. No untrusted input.
	f, err := os.Open(path) // #nosec G304 -- operator-supplied config path, permission-checked above
	if err != nil {
		return nil, fmt.Errorf("secrets: open: %w", err)
	}
	defer func() { _ = f.Close() }()

	s := &Secrets{}
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		key, val, ok := parseEnvLine(sc.Text())
		if !ok {
			continue
		}
		switch key {
		case keyNjallaToken:
			s.njallaToken = val
		case keyDeSECToken:
			s.desecToken = val
		case keyCloudflareToken:
			s.cloudflareToken = val
		case keyINWXUser:
			s.inwxUser = val
		case keyINWXPassword:
			s.inwxPassword = val
		case keyINWXSharedSecret:
			s.inwxSharedSecret = val
		case keyServercowUser:
			s.servercowUser = val
		case keyServercowPass:
			s.servercowPass = val
		case keyServfailAPIKey:
			s.servfailAPIKey = val
		case keyServfailServer:
			s.servfailServer = val
		case keyRspamdPW:
			s.rspamdControllPW = val
		default:
			// Unknown keys are ignored deliberately: secrets.env may hold
			// values consumed by other tools; error messages never echo the
			// key's value.
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("secrets: read: %w", err)
	}
	return s, nil
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
