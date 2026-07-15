// Package dnsaudit evaluates a domain's mail-security posture from live public
// DNS (SPF, DKIM, DMARC, DNSSEC, MTA-STS, TLS-RPT, BIMI). Unlike dnscheck (which
// compares live DNS against a desired record-set), it grades correctness and
// policy strength per RFC. It uses a fixed configured resolver — no
// user-controlled resolver, so no SSRF — and one outbound HTTPS GET to the
// domain's own mta-sts host to fetch the STS policy (TLS-verified, no redirects,
// bounded body).
package dnsaudit

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"

	"mailadmin/internal/valid"
)

// Status is a single finding's verdict.
type Status string

const (
	// Pass means the check is correct / strongest posture.
	Pass Status = "pass"
	// Warn means present but weak, deprecated, or incomplete.
	Warn Status = "warn"
	// Fail means broken, missing where required, or dangerously permissive.
	Fail Status = "fail"
	// Info means optional/not-configured, no action implied.
	Info Status = "info"
)

// Finding is one evaluated aspect.
type Finding struct {
	Check  string `json:"check"`
	Status Status `json:"status"`
	Value  string `json:"value,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Report is the full per-domain audit.
type Report struct {
	Domain   string    `json:"domain"`
	Findings []Finding `json:"findings"`
}

// Counts tallies findings by severity (info excluded from pass/warn/fail).
func (r Report) Counts() (pass, warn, fail int) {
	for _, f := range r.Findings {
		switch f.Status {
		case Pass:
			pass++
		case Warn:
			warn++
		case Fail:
			fail++
		}
	}
	return
}

// Grade returns the worst non-info status: Fail > Warn > Pass.
func (r Report) Grade() Status {
	grade := Pass
	for _, f := range r.Findings {
		switch f.Status {
		case Fail:
			return Fail
		case Warn:
			grade = Warn
		}
	}
	return grade
}

// resolverConn abstracts the DNS transport so the pure evaluators can be tested
// without a network.
type resolverConn interface {
	txt(ctx context.Context, name string) ([]string, error)
	// dnssec reports whether the zone publishes a DNSKEY, whether the parent
	// publishes a DS (chain of trust delegated at the registrar), and whether a
	// validating resolver set the AD (Authenticated Data) flag.
	dnssec(ctx context.Context, domain string) (dnskey, ds, ad bool, err error)
}

// Auditor runs the checks against a fixed resolver and HTTP client.
type Auditor struct {
	conn        resolverConn
	http        *http.Client
	selectors   []string
	speculative bool
}

// New builds an Auditor. resolver is "host:port"; selectors are DKIM selectors
// to evaluate. When speculative is true the selectors are guesses (a common
// provider set, not the domain's known selector), so selectors with no record
// are silently skipped rather than reported as warnings.
func New(resolver string, selectors []string, speculative bool) *Auditor {
	return &Auditor{
		conn:        &liveConn{resolver: resolver, c: &dns.Client{Net: "udp", Timeout: 4 * time.Second}},
		selectors:   selectors,
		speculative: speculative,
		http: &http.Client{
			Timeout: 8 * time.Second,
			// MTA-STS policies are served without redirects (RFC 8461 §3.3);
			// refusing them also prevents being bounced to an unrelated host.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
				ForceAttemptHTTP2: true,
			},
		},
	}
}

// Audit runs every check for domain and returns the ordered report.
func (a *Auditor) Audit(ctx context.Context, rawDomain string) (Report, error) {
	domain, err := valid.Domain(rawDomain)
	if err != nil {
		return Report{}, fmt.Errorf("dnsaudit: %w", err)
	}
	var fs []Finding

	// SPF.
	spf, _ := a.conn.txt(ctx, domain)
	fs = append(fs, evalSPF(spf)...)
	if rec, ok := singleSPF(spf); ok {
		n, capped := a.spfLookups(ctx, domain, rec, 0, map[string]bool{domain: true})
		fs = append(fs, spfLookupFinding(n, capped))
	}

	// DKIM (one finding per configured selector).
	for _, sel := range a.selectors {
		s, err := valid.Selector(sel)
		if err != nil {
			continue
		}
		rec, _ := a.conn.txt(ctx, s+"._domainkey."+domain)
		f, found := evalDKIM(s, rec)
		if !found && a.speculative {
			continue // a guessed selector that does not exist — not a finding
		}
		fs = append(fs, f)
	}

	// DMARC.
	dmarc, _ := a.conn.txt(ctx, "_dmarc."+domain)
	policy, dmarcFindings := evalDMARC(dmarc)
	fs = append(fs, dmarcFindings...)

	// DNSSEC.
	fs = append(fs, a.evalDNSSEC(ctx, domain))

	// MTA-STS (DNS record + fetched policy).
	sts, _ := a.conn.txt(ctx, "_mta-sts."+domain)
	fs = append(fs, evalMTASTSRecord(sts))
	fs = append(fs, a.fetchMTASTSPolicy(ctx, domain))

	// TLS-RPT.
	tlsrpt, _ := a.conn.txt(ctx, "_smtp._tls."+domain)
	fs = append(fs, evalTLSRPT(tlsrpt))

	// BIMI (cross-checked against the DMARC policy strength).
	bimi, _ := a.conn.txt(ctx, "default._bimi."+domain)
	fs = append(fs, evalBIMI(bimi, policy))

	return Report{Domain: domain, Findings: fs}, nil
}

// spfLookups recursively counts the DNS-querying mechanisms of an SPF record
// (include, a, mx, ptr, exists, and the redirect modifier) per RFC 7208 §4.6.4.
// It follows include/redirect targets, guards against cycles, and stops once the
// count exceeds the limit (returning capped=true).
func (a *Auditor) spfLookups(ctx context.Context, domain, record string, depth int, seen map[string]bool) (int, bool) {
	if depth > 10 {
		return 0, true
	}
	count := 0
	for _, tok := range strings.Fields(record) {
		mech, arg := spfMechanism(tok)
		switch mech {
		case "a", "mx", "ptr", "exists":
			count++
		case "include", "redirect":
			count++
			target := arg
			if target == "" || seen[target] {
				continue
			}
			seen[target] = true
			sub, _ := a.conn.txt(ctx, target)
			if rec, ok := singleSPF(sub); ok {
				n, capped := a.spfLookups(ctx, target, rec, depth+1, seen)
				count += n
				if capped {
					return count, true
				}
			}
		}
		if count > spfLookupLimit {
			return count, true
		}
	}
	return count, false
}

// fetchMTASTSPolicy retrieves and evaluates https://mta-sts.<domain>/.well-known
// /mta-sts.txt. The host is derived from the validated domain (not user input),
// TLS is verified, redirects are refused, and the body is size-bounded.
func (a *Auditor) fetchMTASTSPolicy(ctx context.Context, domain string) Finding {
	url := "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
	f := Finding{Check: "MTA-STS policy"}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		f.Status, f.Detail = Fail, err.Error()
		return f
	}
	resp, err := a.http.Do(req)
	if err != nil {
		f.Status, f.Detail = Info, "policy not reachable (MTA-STS not deployed)"
		return f
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		f.Status, f.Detail = Info, fmt.Sprintf("policy not served (HTTP %d)", resp.StatusCode)
		return f
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		f.Status, f.Detail = Fail, "policy read error"
		return f
	}
	return evalMTASTSPolicy(string(body))
}

// evalDNSSEC classifies the chain-of-trust state.
func (a *Auditor) evalDNSSEC(ctx context.Context, domain string) Finding {
	f := Finding{Check: "DNSSEC"}
	dnskey, ds, ad, err := a.conn.dnssec(ctx, domain)
	if err != nil {
		f.Status, f.Detail = Warn, "lookup failed: "+err.Error()
		return f
	}
	switch {
	case !dnskey:
		f.Status, f.Value, f.Detail = Fail, "unsigned", "zone publishes no DNSKEY"
	case !ds:
		f.Status, f.Value, f.Detail = Warn, "signed, not delegated", "DNSKEY present but no DS at the parent — set the DS at your registrar"
	case ad:
		f.Status, f.Value, f.Detail = Pass, "signed + validated", "DS delegated and validated by the resolver"
	default:
		f.Status, f.Value, f.Detail = Warn, "signed, unvalidated", "DS present but the resolver did not set AD"
	}
	return f
}

// liveConn is the network-backed resolverConn.
type liveConn struct {
	resolver string
	c        *dns.Client
}

func (l *liveConn) exchange(ctx context.Context, name string, qtype uint16, dnssecOK bool) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	// Always advertise a 4096-byte EDNS0 buffer; large apex TXT sets (SPF plus
	// many verification records) overflow the 512-byte default and truncate. The
	// DO bit (DNSSEC records + AD validation) is only requested when needed.
	m.SetEdns0(4096, dnssecOK)
	resp, _, err := l.c.ExchangeContext(ctx, m, l.resolver)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", name, err)
	}
	if resp.Truncated {
		// Retry over TCP when the answer still did not fit.
		tcp := &dns.Client{Net: "tcp", Timeout: l.c.Timeout}
		if r2, _, err2 := tcp.ExchangeContext(ctx, m, l.resolver); err2 == nil {
			resp = r2
		}
	}
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("resolve %s: rcode %s", name, dns.RcodeToString[resp.Rcode])
	}
	return resp, nil
}

func (l *liveConn) txt(ctx context.Context, name string) ([]string, error) {
	msg, err := l.exchange(ctx, name, dns.TypeTXT, false)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range msg.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out, nil
}

func (l *liveConn) dnssec(ctx context.Context, domain string) (dnskey, ds, ad bool, err error) {
	kmsg, err := l.exchange(ctx, domain, dns.TypeDNSKEY, true)
	if err != nil {
		return false, false, false, err
	}
	for _, rr := range kmsg.Answer {
		if _, ok := rr.(*dns.DNSKEY); ok {
			dnskey = true
			break
		}
	}
	ad = kmsg.AuthenticatedData
	dmsg, err := l.exchange(ctx, domain, dns.TypeDS, true)
	if err != nil {
		return dnskey, false, ad, nil // DNSKEY result still usable
	}
	for _, rr := range dmsg.Answer {
		if _, ok := rr.(*dns.DS); ok {
			ds = true
			break
		}
	}
	return dnskey, ds, ad, nil
}
