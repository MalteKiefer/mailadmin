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
	results := make([]checkResult, 0, len(cfg.Logs.Units)+3)
	results = append(results, serviceChecks(ctx, svc)...)
	results = append(results, portCheck(ctx, runner))
	results = append(results, rspamdCheck(ctx, runner))
	results = append(results, tlsCheck(ctx, runner))

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
