// Package webserver manages the Caddy autodiscovery include so that
// autoconfig.<domain> (Thunderbird) and autodiscover.<domain> (Outlook) resolve
// and serve the host-templated client-config XML for every hosted domain — the
// mailbox.org model, a single endpoint for all domains.
//
// mailadmin regenerates one managed include file from the domain list and
// reloads Caddy; it never edits the main Caddyfile. The XML itself is a Caddy
// template keyed off the request host, so no per-domain file is needed.
package webserver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"mailadmin/internal/sys"
)

// Defaults for the managed paths and the reload unit.
const (
	DefaultIncludePath      = "/etc/caddy/Caddyfile.d/autodiscovery.caddy"
	DefaultAutoconfigRoot   = "/srv/caddy/autoconfig"
	DefaultAutodiscoverRoot = "/srv/caddy/autodiscover"
	DefaultReloadUnit       = "caddy"
	binSystemctl            = "/usr/bin/systemctl"
)

// Manager writes the autodiscovery include and reloads Caddy.
type Manager struct {
	runner           *sys.Runner
	includePath      string
	autoconfigRoot   string
	autodiscoverRoot string
	reloadUnit       string
}

// New builds a Manager; empty options fall back to the defaults.
func New(runner *sys.Runner, includePath, autoconfigRoot, autodiscoverRoot, reloadUnit string) *Manager {
	return &Manager{
		runner:           runner,
		includePath:      orDefault(includePath, DefaultIncludePath),
		autoconfigRoot:   orDefault(autoconfigRoot, DefaultAutoconfigRoot),
		autodiscoverRoot: orDefault(autodiscoverRoot, DefaultAutodiscoverRoot),
		reloadUnit:       orDefault(reloadUnit, DefaultReloadUnit),
	}
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// Block renders the Caddy autodiscovery site block for the given domains. It is
// pure (no I/O) so it is unit-testable. Domains are sorted and de-duplicated;
// an empty list yields an empty string (no block).
func (m *Manager) Block(domains []string) string {
	hosts := dedupeSorted(domains)
	if len(hosts) == 0 {
		return ""
	}
	var ac, ad []string
	for _, d := range hosts {
		ac = append(ac, "autoconfig."+d)
		ad = append(ad, "autodiscover."+d)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by mailadmin — do not edit. Regenerated on domain add/remove.\n")
	fmt.Fprintf(&b, "%s {\n\troot * %s\n\ttemplates {\n\t\tmime text/xml application/xml text/html text/plain\n\t}\n\tfile_server\n}\n\n",
		strings.Join(ac, ", "), m.autoconfigRoot)
	fmt.Fprintf(&b, "%s {\n\troot * %s\n\t@ms path /autodiscover/autodiscover.xml /Autodiscover/Autodiscover.xml /AutoDiscover/AutoDiscover.xml\n\trewrite @ms /autodiscover.xml\n\tmethod GET\n\ttemplates {\n\t\tmime text/xml application/xml text/html text/plain\n\t}\n\tfile_server\n}\n",
		strings.Join(ad, ", "), m.autodiscoverRoot)
	return b.String()
}

// Sync writes the include for the given domains and reloads Caddy. Writing is
// atomic (temp file + rename) so a partial write never breaks Caddy.
func (m *Manager) Sync(ctx context.Context, domains []string) error {
	block := m.Block(domains)
	if err := writeFileAtomic(m.includePath, []byte(block), 0o644); err != nil {
		return fmt.Errorf("write autodiscovery include: %w", err)
	}
	if _, err := m.runner.Output(ctx, binSystemctl, "reload", m.reloadUnit); err != nil {
		return fmt.Errorf("reload %s: %w", m.reloadUnit, err)
	}
	return nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".autodiscovery-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func dedupeSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
