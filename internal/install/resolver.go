package install

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// Paths of the local validating resolver and the settings around it.
const (
	UnboundConfPath    = "/etc/unbound/unbound.conf.d/mailadmin.conf"
	UnboundDropInPath  = "/etc/systemd/system/unbound.service.d/mailadmin.conf"
	UnboundAnchorPath  = "/var/lib/unbound/root.key"
	RootAnchorSource   = "/usr/share/dns/root.key"
	ResolvconfHeadPath = "/etc/resolvconf/resolv.conf.d/head"
	DhcpcdConfPath     = "/etc/dhcpcd.conf"
	AuditdConfPath     = "/etc/audit/auditd.conf"
)

// UnboundConf is a validating resolver. It forwards over TLS to two resolvers
// that do not log queries and refuses bogus DNSSEC answers.
func UnboundConf() string {
	return `# Managed by mailadmin install. Validating resolver, forwards over TLS to
# no-log resolvers (Quad9, Mullvad). DNSSEC is enforced: bogus answers are refused.
server:
	interface: 127.0.0.1
	interface: ::1
	access-control: 127.0.0.0/8 allow
	access-control: ::1/128 allow
	do-not-query-localhost: no
	hide-identity: yes
	hide-version: yes
	harden-glue: yes
	harden-dnssec-stripped: yes
	harden-referral-path: yes
	qname-minimisation: yes
	val-permissive-mode: no
	prefetch: yes
	tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt

forward-zone:
	name: "."
	forward-tls-upstream: yes
	forward-addr: 9.9.9.9@853#dns.quad9.net
	forward-addr: 149.112.112.112@853#dns.quad9.net
	forward-addr: 2620:fe::fe@853#dns.quad9.net
	forward-addr: 194.242.2.2@853#dns.mullvad.net
`
}

// ResolvconfHead makes the local resolver the only nameserver. There is no
// fallback to unvalidated upstreams.
func ResolvconfHead() string {
	return "# Managed by mailadmin install. Only the local validating resolver.\nnameserver 127.0.0.1\nnameserver ::1\n"
}

// UnboundDropInContent restarts unbound on failure, so a dead resolver comes back.
func UnboundDropInContent() string {
	return "# Managed by mailadmin install. A dead resolver must come back on its own.\n[Service]\nRestart=always\nRestartSec=2\n"
}

// ConfigSetLine sets key = value in a "key = value" config file (auditd style).
// Existing lines for the key are replaced, others stay untouched.
func ConfigSetLine(content, key, value string) string {
	var out []string
	done := false
	for _, l := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		t := strings.TrimSpace(strings.TrimLeft(l, "# \t"))
		if strings.HasPrefix(t, key+" ") || strings.HasPrefix(t, key+"=") {
			if !done {
				out = append(out, fmt.Sprintf("%s = %s", key, value))
				done = true
			}
			continue
		}
		out = append(out, l)
	}
	if !done {
		out = append(out, fmt.Sprintf("%s = %s", key, value))
	}
	return strings.Join(out, "\n") + "\n"
}

// ApplyResolver installs the validating resolver, points the system at it and
// keeps DHCP from writing resolv.conf again. The new config is checked before
// the system resolver is switched.
func ApplyResolver(ctx context.Context, x Exec) error {
	if err := writeAtomic(UnboundConfPath, []byte(UnboundConf()), 0o644); err != nil {
		return err
	}
	if _, err := x.Run(ctx, nil, "unbound-checkconf", "/etc/unbound/unbound.conf"); err != nil {
		return fmt.Errorf("unbound config: %w", err)
	}
	if _, err := os.Stat(RootAnchorSource); err == nil {
		if _, err := os.Stat(UnboundAnchorPath); err != nil {
			data, rerr := os.ReadFile(RootAnchorSource) // #nosec G304 -- fixed package path
			if rerr != nil {
				return rerr
			}
			if err := writeAtomic(UnboundAnchorPath, data, 0o644); err != nil {
				return err
			}
		}
	}
	if err := os.MkdirAll("/etc/systemd/system/unbound.service.d", 0o755); err != nil { // #nosec G301 -- systemd drop-in dir
		return err
	}
	if err := writeAtomic(UnboundDropInPath, []byte(UnboundDropInContent()), 0o644); err != nil {
		return err
	}
	if err := writeAtomic(ResolvconfHeadPath, []byte(ResolvconfHead()), 0o644); err != nil {
		return err
	}
	if cur, err := os.ReadFile(DhcpcdConfPath); err == nil && !strings.Contains(string(cur), "nohook resolv.conf") { // #nosec G304 -- fixed system path
		if err := writeAtomic(DhcpcdConfPath, []byte(strings.TrimRight(string(cur), "\n")+"\nnohook resolv.conf\n"), 0o644); err != nil {
			return err
		}
	}
	if _, err := x.Run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if _, err := x.Run(ctx, nil, "systemctl", "enable", "--now", "unbound"); err != nil {
		return fmt.Errorf("enable unbound: %w", err)
	}
	if _, err := x.Run(ctx, nil, "systemctl", "restart", "unbound"); err != nil {
		return fmt.Errorf("restart unbound: %w", err)
	}
	if _, err := x.Run(ctx, nil, "resolvconf", "-u"); err != nil {
		return fmt.Errorf("resolvconf -u: %w", err)
	}
	return nil
}

// ApplyAuditRetention keeps about 500 MB of audit history (10 files of 50 MB).
func ApplyAuditRetention(ctx context.Context, x Exec) error {
	cur, err := os.ReadFile(AuditdConfPath) // #nosec G304 -- fixed system path
	if err != nil {
		return fmt.Errorf("read %s: %w", AuditdConfPath, err)
	}
	want := ConfigSetLine(ConfigSetLine(string(cur), "max_log_file", "50"), "num_logs", "10")
	if want != string(cur) {
		if err := writeAtomic(AuditdConfPath, []byte(want), 0o640); err != nil {
			return err
		}
		if _, err := x.Run(ctx, nil, "systemctl", "restart", "auditd"); err != nil {
			return fmt.Errorf("restart auditd: %w", err)
		}
	}
	return nil
}

// CrowdSecMailScenarios are the brute-force scenarios for IMAP and SASL.
var CrowdSecMailScenarios = []string{"Guezli/postfix-sasl-bf", "melite/dovecot-time-based-bf", "melite/dovecot-slow-bf"}

// ApplyCrowdSecMailScenarios installs the hub scenarios and reloads CrowdSec.
func ApplyCrowdSecMailScenarios(ctx context.Context, x Exec) error {
	args := append([]string{"scenarios", "install"}, CrowdSecMailScenarios...)
	if _, err := x.Run(ctx, nil, append([]string{"cscli"}, args...)...); err != nil {
		return fmt.Errorf("cscli scenarios install: %w", err)
	}
	if _, err := x.Run(ctx, nil, "systemctl", "reload", "crowdsec"); err != nil {
		return fmt.Errorf("reload crowdsec: %w", err)
	}
	return nil
}
