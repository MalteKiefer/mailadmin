// Package dnsaudit evaluates a domain's mail-security posture from live public
// DNS (SPF, DKIM, DMARC, DNSSEC, DANE, MTA-STS, TLS-RPT, BIMI). Unlike dnscheck (which
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

	"mailadmin/internal/dane"
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
	// mx returns the domain's MX hostnames (lowercased, trailing dot stripped).
	mx(ctx context.Context, domain string) ([]string, error)
	// tlsa returns the raw TLSA record values ("usage selector match hex",
	// lowercase hex) at name and reports whether the answer was
	// DNSSEC-authenticated (AD flag) — DANE requires signed TLSA (RFC 7672).
	tlsa(ctx context.Context, name string) (values []string, ad bool, err error)
}

// Auditor runs the checks against a fixed resolver and HTTP client.
type Auditor struct {
	conn        resolverConn
	http        *http.Client
	selectors   []string
	speculative bool
	// probeCert reads the live cert for host and returns its "3 1 1" TLSA value.
	// Defaults to a live STARTTLS read; overridden in tests to avoid the network.
	probeCert func(ctx context.Context, host string) (string, error)
}

// New builds an Auditor. resolver is "host:port"; selectors are DKIM selectors
// to evaluate. When speculative is true the selectors are guesses (a common
// provider set, not the domain's known selector), so selectors with no record
// are silently skipped rather than reported as warnings.
func New(resolver string, selectors []string, speculative bool) *Auditor {
	a := &Auditor{
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
	a.probeCert = func(ctx context.Context, host string) (string, error) {
		res, err := dane.Value(ctx, "", host)
		return res.Value, err
	}
	return a
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

	// DANE (TLSA at _25._tcp.<MX>, must be DNSSEC-authenticated).
	fs = append(fs, a.evalDANE(ctx, domain))

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

// evalDANE checks inbound SMTP DANE: TLSA records at _25._tcp.<MX> that are
// DNSSEC-authenticated (RFC 7672). DANE is optional, so absence is Info; a TLSA
// that is not authenticated is a failure (it cannot be trusted).
func (a *Auditor) evalDANE(ctx context.Context, domain string) Finding {
	hosts, err := a.conn.mx(ctx, domain)
	if err != nil {
		return Finding{Check: "DANE", Status: Warn, Detail: "MX lookup failed: " + err.Error()}
	}
	total, authed := 0, true
	var published, tlsaHosts []string
	for _, h := range hosts {
		vals, ad, terr := a.conn.tlsa(ctx, "_25._tcp."+h)
		if terr != nil || len(vals) == 0 {
			continue
		}
		total += len(vals)
		tlsaHosts = append(tlsaHosts, h)
		published = append(published, vals...)
		if !ad {
			authed = false
		}
	}
	base := classifyDANE(len(hosts), total, authed)
	if base.Status != Pass {
		return base // not deployed / unsigned / no MX — nothing to match
	}
	return a.verifyDANEMatch(ctx, tlsaHosts, published, base)
}

// verifyDANEMatch confirms the DNSSEC-authenticated TLSA actually matches the
// live certificate. Only "3 1 1" values are derivable; other usages leave the
// presence verdict intact. A reachable non-match is a hard Fail (senders bounce);
// an unreachable host downgrades only to Warn.
func (a *Auditor) verifyDANEMatch(ctx context.Context, hosts, published []string, base Finding) Finding {
	has311 := false
	for _, v := range published {
		if strings.HasPrefix(v, "3 1 1 ") {
			has311 = true
			break
		}
	}
	if !has311 {
		base.Detail += "; TLSA is not 3 1 1 — live-cert match not checked"
		return base
	}
	var lastErr error
	for _, h := range hosts {
		live, err := a.probeCert(ctx, h)
		if err != nil {
			lastErr = err
			continue
		}
		if !daneMatch(published, live) {
			return Finding{Check: "DANE", Status: Fail, Value: "cert mismatch",
				Detail: "published TLSA does not match live certificate (" + h +
					") — stale after key rotation, DANE senders will reject mail"}
		}
		return Finding{Check: "DANE", Status: Pass, Value: base.Value,
			Detail: base.Detail + "; matches live certificate"}
	}
	return Finding{Check: "DANE", Status: Warn, Value: base.Value,
		Detail: "TLSA authenticated but live cert unreachable to confirm match: " + lastErr.Error()}
}

// classifyDANE turns the gathered MX/TLSA counts into a finding.
func classifyDANE(mxCount, tlsaCount int, authenticated bool) Finding {
	f := Finding{Check: "DANE"}
	switch {
	case mxCount == 0:
		f.Status, f.Detail = Info, "no MX records — DANE not applicable"
	case tlsaCount == 0:
		f.Status, f.Value, f.Detail = Info, "not deployed", "no TLSA at _25._tcp.<MX> — DANE not configured"
	case !authenticated:
		f.Status, f.Value, f.Detail = Fail, "unauthenticated",
			"TLSA present but not DNSSEC-signed — DANE cannot be trusted (RFC 7672 requires signed TLSA)"
	default:
		f.Status, f.Value, f.Detail = Pass, fmt.Sprintf("%d TLSA, authenticated", tlsaCount),
			"TLSA published at _25._tcp.<MX> and DNSSEC-validated"
	}
	return f
}

// daneMatch reports whether the live-cert TLSA value equals any published value.
// Comparison is case-insensitive and whitespace-trimmed; a rollover overlap
// (old + new published together) still matches the live cert.
func daneMatch(published []string, live string) bool {
	want := strings.TrimSpace(live)
	for _, p := range published {
		if strings.EqualFold(strings.TrimSpace(p), want) {
			return true
		}
	}
	return false
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

func (l *liveConn) mx(ctx context.Context, domain string) ([]string, error) {
	msg, err := l.exchange(ctx, domain, dns.TypeMX, false)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range msg.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			out = append(out, strings.ToLower(strings.TrimSuffix(mx.Mx, ".")))
		}
	}
	return out, nil
}

func (l *liveConn) tlsa(ctx context.Context, name string) (values []string, ad bool, err error) {
	msg, err := l.exchange(ctx, name, dns.TypeTLSA, true)
	if err != nil {
		return nil, false, err
	}
	for _, rr := range msg.Answer {
		if t, ok := rr.(*dns.TLSA); ok {
			values = append(values, fmt.Sprintf("%d %d %d %s",
				t.Usage, t.Selector, t.MatchingType, strings.ToLower(t.Certificate)))
		}
	}
	return values, msg.AuthenticatedData, nil
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
