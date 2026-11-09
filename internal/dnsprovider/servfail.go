package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Servfail implements Provider against servfail.network, a hosted PowerDNS
// Authoritative service exposing the standard PowerDNS HTTP API. Auth is an
// X-API-Key header. The server id is the primary nameserver FQDN (with trailing
// dot) shown in the account/SOA; the zone id is the domain with a trailing dot.
//
// PowerDNS is RRset-oriented with no per-record ids: a PATCH with changetype
// REPLACE replaces the whole (name,type) set, DELETE removes it. This client
// synthesises record ids (see rrID) and does read-modify-write, mirroring the
// deSEC backend. All names carry trailing dots on the wire.
type Servfail struct {
	apiKey string
	server string // primary NS id, e.g. "ns1.servfail.network."
	client *http.Client
}

// NewServfail builds a client. apiKey and server (the primary-NS server id) must
// be non-empty.
func NewServfail(apiKey, server string) *Servfail {
	return &Servfail{apiKey: apiKey, server: withDot(server), client: newHTTPClient()}
}

func (*Servfail) Name() string { return "servfail" }

// servfailBase is servfail.network's PowerDNS API root.
const servfailBase = "https://beta.servfail.network/api/v1"

type pdnsRecord struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type pdnsRRset struct {
	Name       string       `json:"name"`
	Type       string       `json:"type"`
	TTL        int          `json:"ttl"`
	ChangeType string       `json:"changetype,omitempty"`
	Records    []pdnsRecord `json:"records"`
}

type pdnsZone struct {
	RRsets     []pdnsRRset `json:"rrsets"`
	DNSSEC     bool        `json:"dnssec"`
	APIRectify bool        `json:"api_rectify"`
}

// do performs a request. out (non-nil) receives the decoded JSON body; a >=400
// status is turned into an error carrying the PowerDNS "error" message.
func (s *Servfail) do(ctx context.Context, method, path string, body, out any) error {
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, servfailBase+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", s.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("servfail: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = json.Unmarshal(b, &e)
		if e.Error != "" {
			return fmt.Errorf("servfail %s: %s", resp.Status, e.Error)
		}
		return fmt.Errorf("servfail %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// zonePath is the PowerDNS zone URL for a domain (trailing dots preserved).
func (s *Servfail) zonePath(domain string) string {
	return "/servers/" + s.server + "/zones/" + withDot(domain)
}

func (s *Servfail) getZone(ctx context.Context, domain string) (pdnsZone, error) {
	var z pdnsZone
	err := s.do(ctx, http.MethodGet, s.zonePath(domain), nil, &z)
	return z, err
}

func (s *Servfail) ListRecords(ctx context.Context, domain string) ([]Record, error) {
	z, err := s.getZone(ctx, domain)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, rs := range z.RRsets {
		if servfailInfraType(rs.Type) {
			// Zone-infrastructure and DNSSEC records mailadmin never manages.
			continue
		}
		name := servfailRelative(rs.Name, domain)
		for _, rec := range rs.Records {
			if rec.Disabled {
				continue
			}
			r := Record{Type: strings.ToUpper(rs.Type), Name: name, TTL: rs.TTL, ID: rrID(rs.Name, rs.Type, rec.Content)}
			rrsetParse(&r, rec.Content)
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *Servfail) AddRecord(ctx context.Context, domain string, r Record) error {
	return s.writeSet(ctx, domain, servfailFQDN(r.Name, domain), r.Type, ttlOr(r.TTL), "", rrsetValue(r))
}

func (s *Servfail) EditRecord(ctx context.Context, domain string, r Record) error {
	slot, typ, oldVal, ok := parseRRID(r.ID)
	if !ok {
		return fmt.Errorf("servfail edit: bad record id")
	}
	if !strings.EqualFold(typ, r.Type) {
		return fmt.Errorf("servfail edit: id/type mismatch")
	}
	return s.writeSet(ctx, domain, slot, r.Type, ttlOr(r.TTL), oldVal, rrsetValue(r))
}

func (s *Servfail) RemoveRecord(ctx context.Context, domain, id string) error {
	slot, typ, val, ok := parseRRID(id)
	if !ok {
		return fmt.Errorf("servfail remove: bad record id")
	}
	return s.writeSet(ctx, domain, slot, typ, 0, val, "")
}

// writeSet applies a single-value change to the (fqdn,type) RRset via a REPLACE
// (or DELETE when the set becomes empty) PATCH. The DNSSEC rectify runs in Flush.
func (s *Servfail) writeSet(ctx context.Context, domain, fqdnName, typ string, ttl int, oldVal, newVal string) error {
	z, err := s.getZone(ctx, domain)
	if err != nil {
		return err
	}
	name := withDot(fqdnName)
	var values []string
	// disabled keeps the records the zone holds switched off. REPLACE sends the whole
	// set back, so a record missing from this map would be switched on again.
	disabled := map[string]bool{}
	curTTL := ttl
	for _, rs := range z.RRsets {
		if strings.EqualFold(rs.Name, name) && strings.EqualFold(rs.Type, typ) {
			for _, rec := range rs.Records {
				values = append(values, rec.Content)
				if rec.Disabled {
					disabled[contentKey(rec.Content)] = true
				}
			}
			if rs.TTL > 0 {
				curTTL = rs.TTL
			}
		}
	}
	if oldVal != "" {
		values = removeValue(values, oldVal)
	}
	// The value being published is enabled, even if the zone held it disabled.
	if newVal != "" {
		delete(disabled, contentKey(newVal))
	}
	if newVal != "" && !containsValue(values, newVal) {
		values = append(values, newVal)
	}

	rrset := pdnsRRset{Name: name, Type: strings.ToUpper(typ), TTL: ttlOr(curTTL)}
	if len(values) == 0 {
		rrset.ChangeType = "DELETE"
	} else {
		rrset.ChangeType = "REPLACE"
		for _, v := range values {
			rrset.Records = append(rrset.Records, pdnsRecord{Content: v, Disabled: disabled[contentKey(v)]})
		}
	}
	return s.do(ctx, http.MethodPatch, s.zonePath(domain), map[string]any{"rrsets": []pdnsRRset{rrset}}, nil)
}

// Flush rebuilds the NSEC/RRSIG chain of a DNSSEC zone that does not rectify
// through the API. The zone state is read on every call, so a rectify that
// failed earlier is retried on the next run even when no records changed.
func (s *Servfail) Flush(ctx context.Context, domain string) error {
	z, err := s.getZone(ctx, domain)
	if err != nil {
		return err
	}
	if !z.DNSSEC || z.APIRectify {
		return nil
	}
	if err := s.do(ctx, http.MethodPut, s.zonePath(domain)+"/rectify", nil, nil); err != nil {
		return fmt.Errorf("rectify: %w", err)
	}
	return nil
}

// servfailFQDN converts a relative name ("@"/label) to a trailing-dot FQDN.
func servfailFQDN(name, domain string) string {
	n := strings.TrimSpace(name)
	if n == "" || n == "@" {
		return withDot(domain)
	}
	return withDot(n + "." + domain)
}

// servfailRelative converts a PowerDNS FQDN back to mailadmin's "@"/label form.
func servfailRelative(name, domain string) string {
	n := strings.TrimSuffix(strings.TrimSpace(name), ".")
	if strings.EqualFold(n, domain) {
		return "@"
	}
	if rel, ok := strings.CutSuffix(n, "."+domain); ok {
		return rel
	}
	return n
}

// servfailInfraType reports whether a record type is zone infrastructure or
// DNSSEC material that mailadmin never manages (and must not reconcile away).
func servfailInfraType(t string) bool {
	switch strings.ToUpper(t) {
	case "SOA", "NS", "DNSKEY", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "CDS", "CDNSKEY":
		return true
	}
	return false
}

// withDot ensures a trailing dot (PowerDNS canonical form).
func withDot(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// compile-time assertion.
var _ Provider = (*Servfail)(nil)

// contentKey normalises record content the way containsValue and removeValue compare
// it (case and surrounding space), so a disabled record is found whatever its spelling.
func contentKey(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
