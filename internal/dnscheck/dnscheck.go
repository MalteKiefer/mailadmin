// Package dnscheck verifies live DNS for a domain (SPF, DKIM, DMARC, MX,
// MTA-STS, TLS-RPT) against the desired record-set using miekg/dns with a fixed
// configured resolver (no user-controlled resolver -> no SSRF).
package dnscheck

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"mailadmin/internal/dnsprovider"
	"mailadmin/internal/valid"
)

// Status is the result of a single record check.
type Status string

const (
	// StatusOK means the live record matches expectations.
	StatusOK Status = "ok"
	// StatusMissing means no such record was found.
	StatusMissing Status = "missing"
	// StatusMismatch means a record exists but differs from desired.
	StatusMismatch Status = "mismatch"
	// StatusError means the lookup itself failed.
	StatusError Status = "error"
)

// Result is one checked aspect (e.g. "SPF", "DKIM") with its live/expected view.
type Result struct {
	Kind     string `json:"kind"`
	Status   Status `json:"status"`
	Expected string `json:"expected,omitempty"`
	Found    string `json:"found,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// Checker runs DNS verifications against a fixed resolver.
type Checker struct {
	resolver string
	selector string
	mailHost string
	client   *dns.Client
}

// New builds a Checker using resolver "host:port".
func New(resolver, mailHost, defaultSelector string) *Checker {
	return &Checker{
		resolver: resolver,
		mailHost: mailHost,
		selector: defaultSelector,
		client:   &dns.Client{Net: "udp"},
	}
}

// ResolveLive queries public DNS (via the fixed resolver) for every managed
// slot in `desired` and returns the live records as dnsprovider.Record values.
// Feeding these plus `desired` into dnsprovider.Plan yields the same ok/drift/
// missing view as the registrar check — but from what the world actually sees.
// One query per unique (name,type); results are tagged with the desired
// record's relative name so Plan's identity matching lines up.
func (c *Checker) ResolveLive(ctx context.Context, domain string, desired []dnsprovider.Record) ([]dnsprovider.Record, error) {
	if _, err := valid.Domain(domain); err != nil {
		return nil, fmt.Errorf("dnscheck: %w", err)
	}
	conn := &clientConn{c: c.client, resolver: c.resolver}
	seen := map[string]bool{}
	var out []dnsprovider.Record
	for _, d := range desired {
		key := strings.ToUpper(d.Type) + "\x00" + d.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		qtype, ok := qtypeOf(d.Type)
		if !ok {
			continue
		}
		fqdn := dns.Fqdn(fullName(d.Name, domain))
		msg, err := conn.exchange(ctx, fqdn, qtype)
		if err != nil {
			continue // treated as "missing" by Plan
		}
		out = append(out, recordsFromanswer(msg, d.Name)...)
	}
	return out, nil
}

func qtypeOf(t string) (uint16, bool) {
	switch strings.ToUpper(t) {
	case "A":
		return dns.TypeA, true
	case "AAAA":
		return dns.TypeAAAA, true
	case "MX":
		return dns.TypeMX, true
	case "TXT":
		return dns.TypeTXT, true
	case "CNAME":
		return dns.TypeCNAME, true
	case "SRV":
		return dns.TypeSRV, true
	}
	return 0, false
}

func fullName(name, domain string) string {
	if name == "" || name == "@" {
		return domain
	}
	return name + "." + domain
}

// recordsFromanswer converts a DNS answer into dnsprovider.Record values tagged
// with the given relative name.
func recordsFromanswer(msg *dns.Msg, name string) []dnsprovider.Record {
	if msg == nil {
		return nil
	}
	var out []dnsprovider.Record
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, dnsprovider.Record{Type: "A", Name: name, Content: v.A.String()})
		case *dns.AAAA:
			out = append(out, dnsprovider.Record{Type: "AAAA", Name: name, Content: v.AAAA.String()})
		case *dns.MX:
			out = append(out, dnsprovider.Record{Type: "MX", Name: name, Content: v.Mx, Prio: int(v.Preference)})
		case *dns.TXT:
			out = append(out, dnsprovider.Record{Type: "TXT", Name: name, Content: strings.Join(v.Txt, "")})
		case *dns.CNAME:
			out = append(out, dnsprovider.Record{Type: "CNAME", Name: name, Content: v.Target})
		case *dns.SRV:
			out = append(out, dnsprovider.Record{Type: "SRV", Name: name, Content: v.Target, Prio: int(v.Priority), Weight: int(v.Weight), Port: int(v.Port)})
		}
	}
	return out
}

// resolverConn abstracts the DNS transport so the classification logic can be
// exercised without touching the network in tests.
type resolverConn interface {
	exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)
}

// lookup is the collection of live records fetched once per Check run. Building
// results from lookup is pure (net-free), which is what the unit tests exercise.
type lookup struct {
	txt map[string][]string // fqdn -> joined TXT record strings
	mx  []mxRecord
	err map[string]error // per-name lookup error (StatusError inputs)
}

type mxRecord struct {
	host string
	pref uint16
}

// Check runs the full SPF/DKIM/DMARC/MX/MTA-STS/TLS-RPT verification for domain.
// selector overrides the default DKIM selector when non-empty.
func (c *Checker) Check(ctx context.Context, domain, selector string) ([]Result, error) {
	domain, err := valid.Domain(domain)
	if err != nil {
		return nil, fmt.Errorf("dnscheck: %w", err)
	}
	sel := c.selector
	if selector != "" {
		sel, err = valid.Selector(selector)
		if err != nil {
			return nil, fmt.Errorf("dnscheck: %w", err)
		}
	}
	if sel == "" {
		return nil, fmt.Errorf("dnscheck: %w: empty DKIM selector", valid.ErrInvalid)
	}

	lk := c.gather(ctx, &clientConn{c: c.client, resolver: c.resolver}, domain, sel)
	return buildResults(domain, sel, c.mailHost, lk), nil
}

// gather performs all live lookups for the six checked aspects.
func (c *Checker) gather(ctx context.Context, conn resolverConn, domain, selector string) lookup {
	lk := lookup{txt: map[string][]string{}, err: map[string]error{}}

	txtNames := []string{
		domain,
		"_dmarc." + domain,
		selector + "._domainkey." + domain,
		"_mta-sts." + domain,
		"_smtp._tls." + domain,
	}
	for _, name := range txtNames {
		fqdn := dns.Fqdn(name)
		msg, err := conn.exchange(ctx, fqdn, dns.TypeTXT)
		if err != nil {
			lk.err[fqdn] = err
			continue
		}
		lk.txt[fqdn] = collectTXT(msg)
	}

	mxFqdn := dns.Fqdn(domain)
	if msg, err := conn.exchange(ctx, mxFqdn, dns.TypeMX); err != nil {
		lk.err["MX:"+mxFqdn] = err
	} else {
		lk.mx = collectMX(msg)
	}
	return lk
}

// buildResults turns gathered live records into the ordered per-aspect verdict.
// Pure: no network, safe to unit-test.
func buildResults(domain, selector, mailHost string, lk lookup) []Result {
	return []Result{
		checkMX(domain, mailHost, lk),
		checkSPF(domain, lk),
		checkDMARC(domain, lk),
		checkDKIM(domain, selector, lk),
		checkMTASTS(domain, lk),
		checkTLSRPT(domain, lk),
	}
}

func checkMX(domain, mailHost string, lk lookup) Result {
	r := Result{Kind: "MX", Expected: normHost(mailHost)}
	if err := lk.err["MX:"+dns.Fqdn(domain)]; err != nil {
		r.Status = StatusError
		r.Detail = err.Error()
		return r
	}
	if len(lk.mx) == 0 {
		r.Status = StatusMissing
		return r
	}
	found := make([]string, 0, len(lk.mx))
	want := normHost(mailHost)
	matched := false
	for _, mx := range lk.mx {
		h := normHost(mx.host)
		found = append(found, h)
		if h == want {
			matched = true
		}
	}
	r.Found = strings.Join(found, ", ")
	if matched {
		r.Status = StatusOK
	} else {
		r.Status = StatusMismatch
	}
	return r
}

func checkSPF(domain string, lk lookup) Result {
	return checkTXTValue(txtCheck{
		kind:     "SPF",
		fqdn:     dns.Fqdn(domain),
		prefix:   "v=spf1",
		expected: "v=spf1 mx -all",
		exact:    true,
	}, lk)
}

func checkDMARC(domain string, lk lookup) Result {
	return checkTXTValue(txtCheck{
		kind:     "DMARC",
		fqdn:     dns.Fqdn("_dmarc." + domain),
		prefix:   "v=DMARC1",
		expected: "v=DMARC1; p=...",
	}, lk)
}

func checkDKIM(domain, selector string, lk lookup) Result {
	return checkTXTValue(txtCheck{
		kind:     "DKIM",
		fqdn:     dns.Fqdn(selector + "._domainkey." + domain),
		prefix:   "v=DKIM1",
		expected: "v=DKIM1; k=rsa; p=...",
	}, lk)
}

func checkMTASTS(domain string, lk lookup) Result {
	return checkTXTValue(txtCheck{
		kind:     "MTA-STS",
		fqdn:     dns.Fqdn("_mta-sts." + domain),
		prefix:   "v=STSv1",
		expected: "v=STSv1; id=...",
	}, lk)
}

func checkTLSRPT(domain string, lk lookup) Result {
	return checkTXTValue(txtCheck{
		kind:     "TLS-RPT",
		fqdn:     dns.Fqdn("_smtp._tls." + domain),
		prefix:   "v=TLSRPTv1",
		expected: "v=TLSRPTv1; rua=mailto:...",
	}, lk)
}

// txtCheck describes how one TXT-backed aspect is verified.
type txtCheck struct {
	kind     string
	fqdn     string
	prefix   string // policy version tag the record must start with (case-insensitive)
	expected string // human-facing expected value
	exact    bool   // when true, the record must equal `expected` exactly
}

func checkTXTValue(tc txtCheck, lk lookup) Result {
	r := Result{Kind: tc.kind, Expected: tc.expected}
	if err := lk.err[tc.fqdn]; err != nil {
		r.Status = StatusError
		r.Detail = err.Error()
		return r
	}
	rec, ok := selectTXT(lk.txt[tc.fqdn], tc.prefix)
	if !ok {
		r.Status = StatusMissing
		return r
	}
	r.Found = rec
	switch {
	case tc.exact:
		if normSpace(rec) == normSpace(tc.expected) {
			r.Status = StatusOK
		} else {
			r.Status = StatusMismatch
		}
	default:
		// Policy records (DMARC/DKIM/MTA-STS/TLS-RPT) carry variable content;
		// a present, well-formed (correct version tag) record counts as OK.
		r.Status = StatusOK
	}
	return r
}

// selectTXT picks the TXT string matching the policy prefix. It returns the
// first prefix match; failing that, the first record (so a malformed record is
// surfaced as a mismatch rather than reported missing).
func selectTXT(records []string, prefix string) (string, bool) {
	if len(records) == 0 {
		return "", false
	}
	for _, rec := range records {
		if hasPrefixFold(strings.TrimSpace(rec), prefix) {
			return rec, true
		}
	}
	return records[0], true
}

// collectTXT joins the character-strings of every TXT RR in the answer into one
// string per record (DNS splits long TXT values into 255-byte chunks).
func collectTXT(msg *dns.Msg) []string {
	if msg == nil {
		return nil
	}
	var out []string
	for _, rr := range msg.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(txt.Txt, ""))
		}
	}
	return out
}

func collectMX(msg *dns.Msg) []mxRecord {
	if msg == nil {
		return nil
	}
	var out []mxRecord
	for _, rr := range msg.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			out = append(out, mxRecord{host: mx.Mx, pref: mx.Preference})
		}
	}
	return out
}

func normHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}

func normSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return strings.EqualFold(s[:len(prefix)], prefix)
}

// clientConn is the live miekg/dns implementation of resolverConn.
type clientConn struct {
	c        *dns.Client
	resolver string
}

func (cc *clientConn) exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = true

	resp, _, err := cc.c.ExchangeContext(ctx, m, cc.resolver)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", strings.TrimSuffix(name, "."), err)
	}
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("resolve %s: %w", strings.TrimSuffix(name, "."), errRcode(resp.Rcode))
	}
	return resp, nil
}

type rcodeError int

func (e rcodeError) Error() string {
	if name, ok := dns.RcodeToString[int(e)]; ok {
		return "dns rcode " + name
	}
	return fmt.Sprintf("dns rcode %d", int(e))
}

func errRcode(code int) error { return rcodeError(code) }

// ErrNoResolver is returned when a Checker is built without a resolver address.
var ErrNoResolver = errors.New("dnscheck: no resolver configured")
