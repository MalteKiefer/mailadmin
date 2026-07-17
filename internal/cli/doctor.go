package cli

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"mailadmin/internal/output"
	"mailadmin/internal/services"
	"mailadmin/internal/sys"
)

// Binary paths for the read-only health probes. Absolute (no PATH lookup) and
// pinned to the Debian locations, matching the old system's `mailadmin test`.
const (
	binSS       = "/usr/bin/ss"
	binRspamadm = "/usr/bin/rspamadm"
	binOpenSSL  = "/usr/bin/openssl"
	binPostconf = "/usr/sbin/postconf"
	binCat      = "/bin/cat"
)

// tlsCertPath is the fullchain certificate the mail listeners serve, as laid
// down by the deployment. The old CLI inspected exactly this file.
const tlsCertPath = "/etc/ssl/mail/fullchain.pem"

// expectedPorts are the TCP ports that must be listening for a healthy mail
// host: SSH (22, 2222), SMTP (25), HTTP/HTTPS (80, 443), submissions (465),
// IMAPS (993) and ManageSieve (4190). Mirrors the old `mailadmin test` probe.
var expectedPorts = []int{25, 80, 443, 465, 993, 2222, 4190}

// checkStatus is the outcome of one health check, kept as a small closed set so
// output and (future) exit-code decisions stay consistent.
type checkStatus string

const (
	statusOK    checkStatus = "OK"
	statusWarn  checkStatus = "WARN"
	statusFail  checkStatus = "FAIL"
	statusError checkStatus = "ERROR"
)

// checkResult is one row of the doctor report. Detail carries only non-secret,
// operator-facing context (unit states, port numbers, cert subjects).
type checkResult struct {
	Name   string
	Status checkStatus
	Detail string
}

func newDoctorCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Health check (services, ports, TLS, rspamd config)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runDoctor(app, c)
		},
	}
}

// runDoctor performs the read-only health checks and renders them. It never
// mutates state, so no confirmation or audit record is required. It aggregates
// every probe's outcome and returns a runtime error only if a check FAILs,
// giving scripts a non-zero exit while still printing the full report.
func runDoctor(app *App, c *cobra.Command) error {
	cfg, _, err := app.Config()
	if err != nil {
		return err
	}
	r, err := app.Renderer()
	if err != nil {
		return err
	}

	runner := sys.New(sys.DefaultTimeout, nil)
	svc := services.New(runner, cfg.Logs.Units)

	ctx := ctx(c)
	results := make([]checkResult, 0, len(cfg.Logs.Units)+6)
	results = append(results, serviceChecks(ctx, svc)...)
	results = append(results, portCheck(ctx, runner))
	results = append(results, rspamdCheck(ctx, runner))
	results = append(results, tlsCheck(ctx, runner))
	results = append(results, daneOutboundCheck(ctx, runner))
	results = append(results, daneCertCheck(ctx, runner, cfg.Mail.TLSCert))
	results = append(results, resolverCheck(ctx, runner))

	if err := renderChecks(r, results); err != nil {
		return err
	}

	if anyFailed(results) {
		return fmt.Errorf("%w: one or more health checks failed", errDoctorUnhealthy)
	}
	return nil
}

// errDoctorUnhealthy signals a failed health check. It maps to the default
// runtime exit code (1); doctor deliberately does not use not-found/declined.
var errDoctorUnhealthy = fmt.Errorf("doctor")

// serviceChecks reports one row per allowlisted unit. A unit that is not active
// is a FAIL; a probe error (systemctl unreachable) is an ERROR but does not
// abort the remaining checks.
func serviceChecks(ctx context.Context, svc *services.Service) []checkResult {
	statuses, err := svc.List(ctx)
	if err != nil {
		return []checkResult{{
			Name:   "service",
			Status: statusError,
			Detail: "querying units: " + err.Error(),
		}}
	}
	out := make([]checkResult, 0, len(statuses))
	for _, st := range statuses {
		res := checkResult{
			Name:   "service:" + st.Unit,
			Detail: strings.TrimSpace(st.Active + "/" + st.Sub + " (" + st.Enabled + ")"),
		}
		if st.Active == "active" {
			res.Status = statusOK
		} else {
			res.Status = statusFail
		}
		out = append(out, res)
	}
	return out
}

// portCheck verifies every expectedPort is in LISTEN state. It runs `ss` once
// (numeric, no name resolution) through the exec chokepoint and diffs the
// listening set against the expected set.
func portCheck(ctx context.Context, runner *sys.Runner) checkResult {
	res := checkResult{Name: "ports"}
	out, err := runner.Output(ctx, binSS, "-H", "-tln")
	if err != nil {
		res.Status = statusError
		res.Detail = "ss: " + err.Error()
		return res
	}
	listening := parseListeningPorts(out)
	var missing []int
	for _, p := range expectedPorts {
		if !listening[p] {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		res.Status = statusOK
		res.Detail = "all expected ports listening: " + joinInts(expectedPorts)
		return res
	}
	res.Status = statusFail
	res.Detail = "not listening: " + joinInts(missing)
	return res
}

// rspamdCheck runs `rspamadm configtest`; a non-zero exit is a config FAIL.
func rspamdCheck(ctx context.Context, runner *sys.Runner) checkResult {
	res := checkResult{Name: "rspamd-config"}
	out, err := runner.Output(ctx, binRspamadm, "configtest")
	if err != nil {
		res.Status = statusFail
		res.Detail = firstNonEmptyLine(err.Error())
		return res
	}
	res.Status = statusOK
	if out == "" {
		res.Detail = "syntax OK"
	} else {
		res.Detail = firstNonEmptyLine(out)
	}
	return res
}

// tlsCheck inspects the mail TLS certificate's subject, issuer and validity via
// openssl. A missing/unreadable cert is a WARN (the host may be pre-issuance),
// matching the old system's "no cert yet" behaviour rather than hard-failing.
func tlsCheck(ctx context.Context, runner *sys.Runner) checkResult {
	res := checkResult{Name: "tls-cert"}
	out, err := runner.Output(ctx, binOpenSSL, "x509",
		"-in", tlsCertPath, "-noout", "-subject", "-issuer", "-enddate")
	if err != nil {
		res.Status = statusWarn
		res.Detail = "no readable certificate at " + tlsCertPath
		return res
	}
	res.Status = statusOK
	res.Detail = strings.Join(splitNonEmptyLines(out), "; ")
	return res
}

// classifyDANEOutbound grades Postfix outbound DANE from smtp_tls_security_level
// and smtp_dns_support_level. DANE requires dnssec support to function at all; a
// dane level without it is silently inactive (FAIL). The detail names the
// fallback behaviour: "dane" is opportunistic (falls back to plaintext),
// "dane-only" has no fallback.
func classifyDANEOutbound(level, support string) checkResult {
	res := checkResult{Name: "dane-outbound"}
	level = strings.TrimSpace(level)
	support = strings.TrimSpace(support)
	isDane := level == "dane" || level == "dane-only"
	switch {
	case !isDane:
		res.Status = statusWarn
		res.Detail = "smtp_tls_security_level=" + quoteEmpty(level) + " — outbound DANE not enabled"
	case support != "dnssec":
		res.Status = statusFail
		res.Detail = "smtp_tls_security_level=" + level + " but smtp_dns_support_level=" +
			quoteEmpty(support) + " — DANE inactive without dnssec"
	default:
		fallback := "opportunistic, falls back to plaintext"
		if level == "dane-only" {
			fallback = "no fallback"
		}
		res.Status = statusOK
		res.Detail = level + " + dnssec (" + fallback + ")"
	}
	return res
}

// quoteEmpty renders an empty value as (unset) so blank postconf output is clear.
func quoteEmpty(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

// daneOutboundCheck reads the two postconf keys separately (one call per key)
// and classifies them. Querying each key individually avoids the positional
// collapse that occurs when splitNonEmptyLines drops a blank line emitted by
// postconf for an unset key.
func daneOutboundCheck(ctx context.Context, runner *sys.Runner) checkResult {
	level, err := postconfValue(ctx, runner, "smtp_tls_security_level")
	if err != nil {
		return checkResult{Name: "dane-outbound", Status: statusError, Detail: "postconf: " + firstNonEmptyLine(err.Error())}
	}
	support, err := postconfValue(ctx, runner, "smtp_dns_support_level")
	if err != nil {
		return checkResult{Name: "dane-outbound", Status: statusError, Detail: "postconf: " + firstNonEmptyLine(err.Error())}
	}
	return classifyDANEOutbound(level, support)
}

// postconfValue reads a single postconf parameter's value (empty string when unset).
func postconfValue(ctx context.Context, runner *sys.Runner, key string) (string, error) {
	out, err := runner.Output(ctx, binPostconf, "-h", key)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(firstNonEmptyLine(out)), nil
}

// daneCertCheck reports whether the cert Postfix's smtpd serves is the same file
// that feeds the DANE TLSA. A mismatch means the published TLSA pins a different
// key than inbound senders actually see. wantCert is the DANE cert source
// (config mail.tls_cert, falling back to the deploy path).
func daneCertCheck(ctx context.Context, runner *sys.Runner, wantCert string) checkResult {
	res := checkResult{Name: "dane-smtpd-cert"}
	if wantCert == "" {
		wantCert = tlsCertPath
	}
	out, err := runner.Output(ctx, binPostconf, "-h", "smtpd_tls_cert_file")
	if err != nil {
		res.Status = statusError
		res.Detail = "postconf: " + firstNonEmptyLine(err.Error())
		return res
	}
	got := firstNonEmptyLine(out)
	switch {
	case got == "":
		res.Status = statusWarn
		res.Detail = "smtpd_tls_cert_file is unset"
	case got != wantCert:
		res.Status = statusWarn
		res.Detail = "smtpd serves " + got + " but DANE TLSA is derived from " + wantCert + " — cert drift"
	default:
		res.Status = statusOK
		res.Detail = "smtpd cert matches DANE source: " + got
	}
	return res
}

// classifyResolver inspects resolv.conf nameservers. Outbound DANE needs a local
// validating resolver to trust the AD flag; a loopback nameserver is the expected
// topology (OK, best-effort — true validation is not directly probeable), a
// remote resolver is flagged.
func classifyResolver(resolvConf string) checkResult {
	res := checkResult{Name: "dane-resolver"}
	var ns []string
	for _, line := range splitNonEmptyLines(resolvConf) {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			ns = append(ns, f[1])
		}
	}
	if len(ns) == 0 {
		res.Status = statusWarn
		res.Detail = "no nameserver in resolv.conf — cannot confirm a validating resolver"
		return res
	}
	for _, n := range ns {
		if n == "::1" || strings.HasPrefix(n, "127.") {
			res.Status = statusOK
			res.Detail = "local resolver " + n + " (best-effort: DANE needs it to validate DNSSEC)"
			return res
		}
	}
	res.Status = statusWarn
	res.Detail = "resolver " + strings.Join(ns, ",") + " not loopback — DANE outbound needs a local validating resolver"
	return res
}

// resolverCheck reads resolv.conf through the exec chokepoint and classifies it.
func resolverCheck(ctx context.Context, runner *sys.Runner) checkResult {
	out, err := runner.Output(ctx, binCat, "/etc/resolv.conf")
	if err != nil {
		return checkResult{Name: "dane-resolver", Status: statusWarn, Detail: "cannot read /etc/resolv.conf: " + firstNonEmptyLine(err.Error())}
	}
	return classifyResolver(out)
}

// renderChecks emits the report through the shared renderer, respecting -o. It
// routes through Table so json/plain/table all derive from one shape (json mode
// yields an array of {check,status,detail} objects keyed by the columns).
func renderChecks(r *output.Renderer, results []checkResult) error {
	if len(results) == 0 {
		r.Message("no checks ran")
		return nil
	}
	t := output.Table{Columns: []string{"check", "status", "detail"}}
	for _, res := range results {
		t.Rows = append(t.Rows, []string{res.Name, string(res.Status), res.Detail})
	}
	return r.Table(t)
}

// anyFailed reports whether any check FAILed. ERROR/WARN do not flip the exit
// code: ERROR is an unreachable probe (inconclusive) and WARN is advisory.
func anyFailed(results []checkResult) bool {
	for _, res := range results {
		if res.Status == statusFail {
			return true
		}
	}
	return false
}

// parseListeningPorts extracts the local port from each `ss -tln` row into a
// set. ss prints the local address in column 4 as ADDR:PORT (IPv6 addresses are
// bracketed, and "*" is used for the wildcard address).
func parseListeningPorts(out string) map[int]bool {
	ports := make(map[int]bool)
	for _, line := range splitNonEmptyLines(out) {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		local := fields[3]
		idx := strings.LastIndex(local, ":")
		if idx < 0 || idx == len(local)-1 {
			continue
		}
		if p, err := strconv.Atoi(local[idx+1:]); err == nil {
			ports[p] = true
		}
	}
	return ports
}

// joinInts renders a sorted, comma-separated list of ports for display.
func joinInts(ns []int) string {
	cp := append([]int(nil), ns...)
	sort.Ints(cp)
	parts := make([]string, len(cp))
	for i, n := range cp {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ",")
}

// splitNonEmptyLines splits s on newlines, trimming and dropping blank lines.
func splitNonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// firstNonEmptyLine returns the first non-blank trimmed line, for terse detail.
func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}
