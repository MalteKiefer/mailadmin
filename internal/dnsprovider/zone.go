package dnsprovider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// PullAXFR fetches an entire zone from a nameserver via a DNS zone transfer
// (AXFR) and returns it as records relative to `domain`. Records that the target
// registrar manages itself or that cannot be re-created (SOA, apex NS, DNSSEC)
// are dropped — see keepRR. The nameserver is "host" or "host:port" (default 53).
func PullAXFR(ctx context.Context, domain, nameserver string) ([]Record, error) {
	if !strings.Contains(nameserver, ":") {
		nameserver += ":53"
	}
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))
	tr := &dns.Transfer{DialTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second}
	ch, err := tr.In(m, nameserver)
	if err != nil {
		return nil, fmt.Errorf("axfr %s @ %s: %w", domain, nameserver, err)
	}
	var out []Record
	for env := range ch {
		if env.Error != nil {
			return nil, fmt.Errorf("axfr %s: %w (does the nameserver allow transfers from this host?)", domain, env.Error)
		}
		for _, rr := range env.RR {
			if r, ok := rrToRecord(rr, domain); ok {
				out = append(out, r)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("axfr %s @ %s returned no usable records", domain, nameserver)
	}
	return out, nil
}

// ParseZonefile reads a BIND-format zone file and returns its records relative
// to `domain`.
func ParseZonefile(r io.Reader, domain string) ([]Record, error) {
	zp := dns.NewZoneParser(r, dns.Fqdn(domain), "")
	var out []Record
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if rec, keep := rrToRecord(rr, domain); keep {
			out = append(out, rec)
		}
	}
	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("parse zonefile: %w", err)
	}
	return out, nil
}

// keepRR reports whether a resource-record type should be migrated. SOA and
// DNSSEC records are provider-generated; apex NS is set by the registrar.
func keepRR(rr dns.RR, domain string) bool {
	h := rr.Header()
	switch h.Rrtype {
	case dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC, dns.TypeNSEC3,
		dns.TypeNSEC3PARAM, dns.TypeCDS, dns.TypeCDNSKEY, dns.TypeDS:
		return false
	case dns.TypeNS:
		// Keep delegations for subdomains, drop the apex NS (registrar-managed).
		return !strings.EqualFold(strings.TrimSuffix(h.Name, "."), strings.TrimSuffix(domain, "."))
	}
	return true
}

// inZone reports whether an owner name belongs to the zone (the apex itself or a
// subdomain of it). Records outside the zone — e.g. the external targets of a
// CNAME chain returned in an answer — are not part of the zone and must not be
// migrated.
func inZone(fqdn, domain string) bool {
	n := strings.TrimSuffix(strings.TrimSuffix(fqdn, "."), ".")
	d := strings.TrimSuffix(strings.TrimSuffix(domain, "."), ".")
	if strings.EqualFold(n, d) {
		return true
	}
	_, ok := cutSuffixFold(n, "."+d)
	return ok
}

// rrToRecord converts a miekg/dns RR into a provider Record with a name relative
// to domain ("@" for the apex). Returns ok=false for records to skip.
func rrToRecord(rr dns.RR, domain string) (Record, bool) {
	if !keepRR(rr, domain) {
		return Record{}, false
	}
	h := rr.Header()
	if !inZone(h.Name, domain) {
		return Record{}, false // out-of-zone (e.g. a CNAME chain's external targets)
	}
	name := relName(h.Name, domain)
	ttl := int(h.Ttl)
	switch v := rr.(type) {
	case *dns.A:
		return Record{Type: "A", Name: name, Content: v.A.String(), TTL: ttl}, true
	case *dns.AAAA:
		return Record{Type: "AAAA", Name: name, Content: v.AAAA.String(), TTL: ttl}, true
	case *dns.CNAME:
		return Record{Type: "CNAME", Name: name, Content: v.Target, TTL: ttl}, true
	case *dns.MX:
		return Record{Type: "MX", Name: name, Content: v.Mx, Prio: int(v.Preference), TTL: ttl}, true
	case *dns.TXT:
		return Record{Type: "TXT", Name: name, Content: strings.Join(v.Txt, ""), TTL: ttl}, true
	case *dns.SRV:
		return Record{Type: "SRV", Name: name, Content: v.Target, Prio: int(v.Priority), Weight: int(v.Weight), Port: int(v.Port), TTL: ttl}, true
	case *dns.NS:
		return Record{Type: "NS", Name: name, Content: v.Ns, TTL: ttl}, true
	case *dns.CAA:
		return Record{Type: "CAA", Name: name, Content: fmt.Sprintf("%d %s %q", v.Flag, v.Tag, v.Value), TTL: ttl}, true
	case *dns.PTR:
		return Record{Type: "PTR", Name: name, Content: v.Ptr, TTL: ttl}, true
	}
	return Record{}, false
}

// relName returns the record name relative to the zone: "@" for the apex,
// otherwise the sub-name without the trailing domain.
func relName(fqdn, domain string) string {
	n := strings.TrimSuffix(strings.TrimSuffix(fqdn, "."), ".")
	d := strings.TrimSuffix(strings.TrimSuffix(domain, "."), ".")
	if strings.EqualFold(n, d) {
		return "@"
	}
	if sub, ok := cutSuffixFold(n, "."+d); ok {
		return sub
	}
	return n
}

func cutSuffixFold(s, suffix string) (string, bool) {
	if len(s) >= len(suffix) && strings.EqualFold(s[len(s)-len(suffix):], suffix) {
		return s[:len(s)-len(suffix)], true
	}
	return "", false
}

// FailedRecord is a record whose creation at the target failed, with the reason.
type FailedRecord struct {
	Record
	Reason string `json:"reason"`
}

// MigrateResult reports the outcome of copying a zone to a target provider.
type MigrateResult struct {
	Created []Record       `json:"created"`
	Skipped []Record       `json:"skipped"` // already present at the target
	Failed  []FailedRecord `json:"failed"`
}

// Migrate creates every record from `records` at the target provider, skipping
// any that already exist there. NS/SOA are never copied — delegation belongs to
// the target zone. It never deletes. Returns per-record outcomes.
func Migrate(ctx context.Context, target Provider, domain string, records []Record) (MigrateResult, error) {
	live, err := target.ListRecords(ctx, domain)
	if err != nil {
		return MigrateResult{}, fmt.Errorf("list target %s: %w", domain, err)
	}
	present := make(map[string]struct{}, len(live))
	for _, r := range live {
		present[r.identity()+"\x00"+strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Content), "."))] = struct{}{}
	}
	var res MigrateResult
	for _, r := range records {
		if r.Type == "NS" || r.Type == "SOA" {
			continue
		}
		k := r.identity() + "\x00" + strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Content), "."))
		if _, ok := present[k]; ok {
			res.Skipped = append(res.Skipped, r)
			continue
		}
		if err := target.AddRecord(ctx, domain, r); err != nil {
			res.Failed = append(res.Failed, FailedRecord{Record: r, Reason: migrateFailReason(err)})
			continue
		}
		res.Created = append(res.Created, r)
		present[k] = struct{}{}
	}
	return res, nil
}

// migrateFailReason turns a provider error into a short, human-readable reason
// for the migrate result table (the raw error is verbose and hides the status).
func migrateFailReason(err error) string {
	var ae *apiError
	if errors.As(err, &ae) {
		switch ae.StatusCode {
		case http.StatusTooManyRequests:
			return "rate limited (HTTP 429) — retried and still throttled"
		case http.StatusUnprocessableEntity:
			return "rejected (HTTP 422)"
		default:
			return fmt.Sprintf("HTTP %d", ae.StatusCode)
		}
	}
	return err.Error()
}
