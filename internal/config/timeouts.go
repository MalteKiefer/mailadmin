package config

import (
	"fmt"
	"time"
)

// Built-in bounds, used when the config leaves a value empty.
const (
	DefaultCommandTimeout = 30 * time.Second
	DefaultDBToolTimeout  = 30 * time.Minute
	maxTimeout            = 2 * time.Hour
)

// DefaultDNSTTL is the record TTL in seconds used when mail.dns_ttl is 0.
const DefaultDNSTTL = 3600

// Timeouts bounds external work. Values are Go durations such as "45s" or "1h".
// An empty value means the built-in default.
type Timeouts struct {
	// Command bounds one privileged command (doveadm, nft, systemctl).
	Command string `toml:"command"`
	// DBTool bounds pg_dump and pg_restore, which can take minutes on a large database.
	DBTool string `toml:"db_tool"`
}

// CommandTimeout returns the bound for one privileged command.
func (t Timeouts) CommandTimeout() time.Duration {
	return durationOr(t.Command, DefaultCommandTimeout)
}

// DBToolTimeout returns the bound for pg_dump and pg_restore.
func (t Timeouts) DBToolTimeout() time.Duration {
	return durationOr(t.DBTool, DefaultDBToolTimeout)
}

func durationOr(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 || d > maxTimeout {
		return def // Validate refuses these values before any command runs
	}
	return d
}

func (t Timeouts) validate() error {
	for _, f := range []struct{ name, val string }{
		{"timeouts.command", t.Command},
		{"timeouts.db_tool", t.DBTool},
	} {
		if f.val == "" {
			continue
		}
		d, err := time.ParseDuration(f.val)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrInvalidConfig, f.name, err)
		}
		if d <= 0 || d > maxTimeout {
			return fmt.Errorf("%w: %s must be above 0 and at most %s", ErrInvalidConfig, f.name, maxTimeout)
		}
	}
	return nil
}
