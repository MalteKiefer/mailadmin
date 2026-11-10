package config

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Webmail configures the alps webmail client. It is served on Domain through
// Caddy and talks to Dovecot over the local IMAP and submission ports.
type Webmail struct {
	// Enabled turns the webmail on. Off, nothing is installed and the other
	// fields are not checked.
	Enabled bool `toml:"enabled"`
	// Domain is the host name the web client is served on, e.g. webmail.example.com.
	Domain string `toml:"domain"`
	// URL is where the linux-amd64 alps binary is downloaded from (https).
	URL string `toml:"url"`
	// SHA256 is the checksum of that binary. The download is refused when it does
	// not match.
	SHA256 string `toml:"sha256"`
	// Listen is the local address alps listens on. Caddy proxies Domain to it.
	Listen string `toml:"listen"`
}

// BorgBackup configures the Borg repository that archives the backup bundles.
type BorgBackup struct {
	// Enabled turns the archive job on. Off, no timer is installed.
	Enabled bool `toml:"enabled"`
	// Repo is ssh://user@host:port/./path (a storage box, a remote host) or an
	// absolute local or mounted path. The passphrase is BORG_PASSPHRASE in [secrets].
	Repo string `toml:"repo"`
	// SSHKey is the private key for ssh:// repositories (absolute, mode 0600).
	SSHKey string `toml:"ssh_key"`
	// KnownHosts pins the storage host key for ssh:// repositories (absolute).
	KnownHosts string `toml:"known_hosts"`
	// Encryption is one of repokey-blake2, repokey, keyfile-blake2, keyfile, none.
	Encryption string `toml:"encryption"`
	// Compression is a borg --compression value, e.g. zstd,6 or lz4.
	Compression string `toml:"compression"`
	// Source is the directory whose contents are archived. Empty: backup.dir.
	Source string `toml:"source"`
	// Schedule is the systemd OnCalendar expression of the timer.
	Schedule string `toml:"schedule"`
	// Prune removes archives outside Retention after each run.
	Prune bool `toml:"prune"`
	// Compact frees the space of pruned archives (borg compact).
	Compact bool `toml:"compact"`
	// CheckEvery runs borg check at this interval, e.g. 1w or 30d. Empty: never.
	CheckEvery string `toml:"check_every"`
	// Retention is how many archives to keep per period.
	Retention BorgRetention `toml:"retention"`
}

// BorgRetention is the number of archives kept per period.
type BorgRetention struct {
	Daily   int `toml:"daily"`
	Weekly  int `toml:"weekly"`
	Monthly int `toml:"monthly"`
}

var (
	reHostName   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	reSHA256Hex  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reCheckEvery = regexp.MustCompile(`^[1-9][0-9]*[dw]$`)
)

// borgEncryptions are the modes borg init accepts that mailadmin allows.
var borgEncryptions = map[string]bool{
	"repokey-blake2": true, "repokey": true, "keyfile-blake2": true, "keyfile": true, "none": true,
}

func (w Webmail) validate() error {
	if !w.Enabled {
		return nil
	}
	if !reHostName.MatchString(w.Domain) {
		return fmt.Errorf("%w: webmail.domain must be a host name, got %q", ErrInvalidConfig, w.Domain)
	}
	if !strings.HasPrefix(w.URL, "https://") {
		return fmt.Errorf("%w: webmail.url must be an https URL of the alps binary", ErrInvalidConfig)
	}
	if !reSHA256Hex.MatchString(w.SHA256) {
		return fmt.Errorf("%w: webmail.sha256 must be 64 lowercase hex digits of the alps binary", ErrInvalidConfig)
	}
	if err := validateHostPort(w.Listen); err != nil {
		return fmt.Errorf("%w: webmail.listen: %w", ErrInvalidConfig, err)
	}
	return nil
}

// validate checks the borg section. backupDir is backup.dir, the default source.
func (b BorgBackup) validate(backupDir string) error {
	if !b.Enabled {
		return nil
	}
	switch {
	case b.Repo == "":
		return fmt.Errorf("%w: backup.borg.repo is required when borg is enabled", ErrInvalidConfig)
	case strings.HasPrefix(b.Repo, "ssh://"):
		if !filepath.IsAbs(b.SSHKey) {
			return fmt.Errorf("%w: backup.borg.ssh_key must be an absolute path", ErrInvalidConfig)
		}
		if !filepath.IsAbs(b.KnownHosts) {
			return fmt.Errorf("%w: backup.borg.known_hosts must be an absolute path (it pins the storage host)", ErrInvalidConfig)
		}
	case !filepath.IsAbs(b.Repo):
		return fmt.Errorf("%w: backup.borg.repo must be ssh://... or an absolute path", ErrInvalidConfig)
	}
	if !borgEncryptions[b.Encryption] {
		return fmt.Errorf("%w: backup.borg.encryption must be repokey-blake2, repokey, keyfile-blake2, keyfile or none", ErrInvalidConfig)
	}
	if b.Compression == "" {
		return fmt.Errorf("%w: backup.borg.compression is required (e.g. zstd,6)", ErrInvalidConfig)
	}
	src := b.Source
	if src == "" {
		src = backupDir
	}
	if !filepath.IsAbs(src) {
		return fmt.Errorf("%w: backup.borg.source must be an absolute path (or set backup.dir)", ErrInvalidConfig)
	}
	if b.Schedule == "" {
		return fmt.Errorf("%w: backup.borg.schedule is required", ErrInvalidConfig)
	}
	if b.CheckEvery != "" && !reCheckEvery.MatchString(b.CheckEvery) {
		return fmt.Errorf("%w: backup.borg.check_every must look like 1w or 30d", ErrInvalidConfig)
	}
	r := b.Retention
	if r.Daily < 0 || r.Weekly < 0 || r.Monthly < 0 {
		return fmt.Errorf("%w: backup.borg.retention values must not be negative", ErrInvalidConfig)
	}
	if r.Daily+r.Weekly+r.Monthly == 0 {
		return fmt.Errorf("%w: backup.borg.retention must keep at least one archive", ErrInvalidConfig)
	}
	return nil
}
