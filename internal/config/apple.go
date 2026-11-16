package config

import (
	"fmt"
	"strings"
)

// Apple configures the profile form for iPhone and Mac. Off by default. When on,
// visitors enter a mail address and download a .mobileconfig with the server settings.
type Apple struct {
	// Enabled turns the form on. Off, nothing is installed and the other fields are not checked.
	Enabled bool `toml:"enabled"`
	// Domain is the host name the form is served on, e.g. apple.example.com.
	Domain string `toml:"domain"`
	// Listen is the local address the form service listens on. Caddy proxies Domain to it.
	Listen string `toml:"listen"`
}

func (a Apple) validate() error {
	if !a.Enabled {
		return nil
	}
	if !reHostName.MatchString(a.Domain) {
		return fmt.Errorf("%w: apple.domain must be a host name, got %q", ErrInvalidConfig, a.Domain)
	}
	if err := validateHostPort(a.Listen); err != nil {
		return fmt.Errorf("%w: apple.listen: %w", ErrInvalidConfig, err)
	}
	return nil
}

// normalizeApple trims and lowercases the Apple fields in place.
func normalizeApple(a *Apple) {
	a.Domain = strings.ToLower(strings.TrimSpace(a.Domain))
	a.Listen = strings.TrimSpace(a.Listen)
}
