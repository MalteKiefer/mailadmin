package cli

import (
	"path/filepath"

	"mailadmin/internal/config"
)

// adoptDefaults are the values an adopt run takes from the existing config. Flags
// win; a value the config lacks is asked for, or is a usage error without a terminal.
type adoptDefaults struct {
	hostname, domain, ipv4, ipv6 string
	pgdg, caddy, crowdsec        string
}

// loadAdoptDefaults reads the config in dir. A missing or unreadable config gives
// empty defaults, so the run falls back to flags and questions.
func loadAdoptDefaults(dir string) adoptDefaults {
	path, err := config.Discover(dir)
	if err != nil {
		return adoptDefaults{}
	}
	cfg, _, err := config.Load(filepath.Clean(path))
	if err != nil {
		return adoptDefaults{}
	}
	return adoptDefaults{
		hostname: cfg.Mail.Hostname,
		domain:   cfg.Mail.PrimaryDomain,
		ipv4:     cfg.Server.IPv4,
		ipv6:     cfg.Server.IPv6,
		pgdg:     cfg.Repos.PGDGFingerprint,
		caddy:    cfg.Repos.CaddyFingerprint,
		crowdsec: cfg.Repos.CrowdSecFingerprint,
	}
}

// applyAdoptDefaults fills every empty install input from the config.
func applyAdoptDefaults(in *installInputs, d adoptDefaults) {
	fill := func(dst *string, v string) {
		if *dst == "" {
			*dst = v
		}
	}
	fill(&in.hostname, d.hostname)
	fill(&in.domain, d.domain)
	fill(&in.ipv4, d.ipv4)
	fill(&in.ipv6, d.ipv6)
	fill(&in.pgdgFingerprint, d.pgdg)
	fill(&in.caddyFingerprint, d.caddy)
	fill(&in.crowdsecFingerprint, d.crowdsec)
}
