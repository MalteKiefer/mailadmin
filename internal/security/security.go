// Package security wraps CrowdSec (cscli), the nftables firewall (nft, read +
// explicit port open/close only), and fail2ban-client, all via internal/sys.
// IPs/CIDRs, ports and protocols are validated before use; nft is never called
// with a wildcard ruleset mutation — port changes go through the dedicated
// setuid helper mailadmin-fw-port, which only ever adds/removes a single
// proto/port element in the managed set.
package security

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"mailadmin/internal/sys"
	"mailadmin/internal/valid"
)

// Binary paths (absolute; matches the old system).
const (
	binCscli    = "/usr/bin/cscli"
	binNft      = "/usr/sbin/nft"
	binFail2ban = "/usr/bin/fail2ban-client"
	// binFWPort is the least-privilege helper that adds/removes exactly one
	// proto/port element in the managed nft set. mailadmin never mutates the
	// ruleset directly (no `nft add rule …` with attacker-influenced text).
	binFWPort = "/usr/local/libexec/mailadmin-fw-port"
)

// allowlistName is the CrowdSec allowlist mailadmin owns. Bans and allowlist
// entries are scoped to this single, well-known list so a caller can never
// touch an arbitrary allowlist.
const allowlistName = "mailadmin"

// banType is the CrowdSec decision type mailadmin creates and lists. We never
// surface captcha/throttle decisions as "bans".
const banType = "ban"

// ErrInvalidResponse is returned when a tool emits output we cannot parse.
var ErrInvalidResponse = errors.New("security: invalid tool response")

// Decision is one active CrowdSec ban/decision.
type Decision struct {
	IP       string    `json:"ip"`
	Scenario string    `json:"scenario"`
	Type     string    `json:"type"`
	Duration string    `json:"duration"`
	Until    time.Time `json:"until"`
	Origin   string    `json:"origin"`
}

// AllowEntry is one allowlist (whitelist) member.
type AllowEntry struct {
	IP      string `json:"ip"`
	Comment string `json:"comment,omitempty"`
}

// FirewallPort is one open port in the managed nft ruleset.
type FirewallPort struct {
	Proto string `json:"proto"`
	Port  int    `json:"port"`
}

// Overview aggregates the security posture for `security overview`.
type Overview struct {
	Decisions []Decision     `json:"decisions"`
	Allowlist []AllowEntry   `json:"allowlist"`
	OpenPorts []FirewallPort `json:"open_ports"`
	Fail2ban  bool           `json:"fail2ban_running"`
}

// Service runs cscli/nft/fail2ban.
type Service struct {
	runner *sys.Runner
}

// New builds a Service.
func New(runner *sys.Runner) *Service { return &Service{runner: runner} }

// ---- bans (cscli decisions) ----

// ListBans returns active CrowdSec ban decisions (scope: ip), sorted by IP for
// stable output.
func (s *Service) ListBans(ctx context.Context) ([]Decision, error) {
	out, err := s.runner.Output(ctx, binCscli, "decisions", "list", "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("security.ListBans: %w", err)
	}
	decisions, err := parseDecisions([]byte(out))
	if err != nil {
		return nil, fmt.Errorf("security.ListBans: %w", err)
	}
	sort.Slice(decisions, func(i, j int) bool { return decisions[i].IP < decisions[j].IP })
	return decisions, nil
}

// AddBan bans an ip/cidr for the given duration (empty = provider default). The
// value and duration are validated before they reach the command line.
func (s *Service) AddBan(ctx context.Context, ip, duration string) error {
	value, err := valid.CIDR(ip)
	if err != nil {
		return fmt.Errorf("security.AddBan: %w", err)
	}
	argv := []string{binCscli, "decisions", "add", "--ip", value, "--type", banType}
	if duration != "" {
		dur, derr := valid.Duration(duration)
		if derr != nil {
			return fmt.Errorf("security.AddBan: %w", derr)
		}
		argv = append(argv, "--duration", dur)
	}
	if _, err := s.runner.Output(ctx, argv...); err != nil {
		return fmt.Errorf("security.AddBan %s: %w", value, err)
	}
	return nil
}

// RemoveBan removes all decisions for ip/cidr.
func (s *Service) RemoveBan(ctx context.Context, ip string) error {
	value, err := valid.CIDR(ip)
	if err != nil {
		return fmt.Errorf("security.RemoveBan: %w", err)
	}
	if _, err := s.runner.Output(ctx, binCscli, "decisions", "delete", "--ip", value); err != nil {
		return fmt.Errorf("security.RemoveBan %s: %w", value, err)
	}
	return nil
}

// ---- allowlist ----

// ListAllow returns entries of the managed CrowdSec allowlist, sorted by IP.
func (s *Service) ListAllow(ctx context.Context) ([]AllowEntry, error) {
	out, err := s.runner.Output(ctx, binCscli, "allowlists", "inspect", allowlistName, "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("security.ListAllow: %w", err)
	}
	entries, err := parseAllowlist([]byte(out))
	if err != nil {
		return nil, fmt.Errorf("security.ListAllow: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].IP < entries[j].IP })
	return entries, nil
}

// AddAllow adds an ip/cidr to the managed allowlist.
func (s *Service) AddAllow(ctx context.Context, ip string) error {
	value, err := valid.CIDR(ip)
	if err != nil {
		return fmt.Errorf("security.AddAllow: %w", err)
	}
	if _, err := s.runner.Output(ctx, binCscli, "allowlists", "add", allowlistName, value); err != nil {
		return fmt.Errorf("security.AddAllow %s: %w", value, err)
	}
	return nil
}

// RemoveAllow removes an ip/cidr from the managed allowlist.
func (s *Service) RemoveAllow(ctx context.Context, ip string) error {
	value, err := valid.CIDR(ip)
	if err != nil {
		return fmt.Errorf("security.RemoveAllow: %w", err)
	}
	if _, err := s.runner.Output(ctx, binCscli, "allowlists", "remove", allowlistName, value); err != nil {
		return fmt.Errorf("security.RemoveAllow %s: %w", value, err)
	}
	return nil
}

// ---- firewall (nft) ----

// ShowFirewall lists managed open ports, sorted by proto then port.
func (s *Service) ShowFirewall(ctx context.Context) ([]FirewallPort, error) {
	out, err := s.runner.Output(ctx, binNft, "-j", "list", "ruleset")
	if err != nil {
		return nil, fmt.Errorf("security.ShowFirewall: %w", err)
	}
	ports, err := parseNftPorts([]byte(out))
	if err != nil {
		return nil, fmt.Errorf("security.ShowFirewall: %w", err)
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Proto != ports[j].Proto {
			return ports[i].Proto < ports[j].Proto
		}
		return ports[i].Port < ports[j].Port
	})
	return ports, nil
}

// OpenPort opens a validated proto/port via the setuid helper.
func (s *Service) OpenPort(ctx context.Context, proto string, port int) error {
	return s.fwPort(ctx, "OpenPort", "open", proto, port)
}

// ClosePort closes a validated proto/port via the setuid helper.
func (s *Service) ClosePort(ctx context.Context, proto string, port int) error {
	return s.fwPort(ctx, "ClosePort", "close", proto, port)
}

// fwPort validates proto/port and invokes mailadmin-fw-port with a fixed verb.
// verb is a compile-time constant from OpenPort/ClosePort, never user input.
func (s *Service) fwPort(ctx context.Context, op, verb, proto string, port int) error {
	p, err := valid.Proto(proto)
	if err != nil {
		return fmt.Errorf("security.%s: %w", op, err)
	}
	n, err := valid.Port(port)
	if err != nil {
		return fmt.Errorf("security.%s: %w", op, err)
	}
	if _, err := s.runner.Output(ctx, binFWPort, verb, p, strconv.Itoa(n)); err != nil {
		return fmt.Errorf("security.%s %s/%d: %w", op, p, n, err)
	}
	return nil
}

// ---- overview ----

// Overview aggregates bans, allowlist, firewall and fail2ban status. It fails
// closed on the security-critical sources (bans, allowlist, firewall) but
// treats fail2ban as best-effort: fail2ban is optional in this deployment, so
// its absence is reported as "not running" rather than aborting the overview.
func (s *Service) Overview(ctx context.Context) (Overview, error) {
	decisions, err := s.ListBans(ctx)
	if err != nil {
		return Overview{}, fmt.Errorf("security.Overview: %w", err)
	}
	allow, err := s.ListAllow(ctx)
	if err != nil {
		return Overview{}, fmt.Errorf("security.Overview: %w", err)
	}
	ports, err := s.ShowFirewall(ctx)
	if err != nil {
		return Overview{}, fmt.Errorf("security.Overview: %w", err)
	}
	return Overview{
		Decisions: decisions,
		Allowlist: allow,
		OpenPorts: ports,
		Fail2ban:  s.fail2banRunning(ctx),
	}, nil
}

// fail2banRunning reports whether fail2ban responds to a ping. fail2ban is
// optional; any error (missing binary, socket down) yields false without
// surfacing an error, matching the old system's best-effort probe.
func (s *Service) fail2banRunning(ctx context.Context) bool {
	res, err := s.runner.Run(ctx, nil, binFail2ban, "ping")
	if err != nil || res.ExitCode != 0 {
		return false
	}
	return isFail2banPong(res.Stdout)
}
