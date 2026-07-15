// Package dnsprovider manages authoritative DNS records for mail-related
// entries on domains whose zone is hosted at a supported registrar.
//
// It lets mailadmin PUBLISH the record-set it already computes (MX, SPF, DKIM,
// DMARC, MTA-STS, TLS-RPT, host A/AAAA) instead of the operator copy-pasting
// them. Verification stays with internal/dnscheck; this package is write-side.
//
// Provider is an interface so more registrars can be added; Njalla is the first
// implementation (see njalla.go).
package dnsprovider

import (
	"context"
	"fmt"
	"strings"
)

// Record is a single DNS resource record. ID is the provider-assigned id
// (empty for a desired record that does not exist yet). Prio == 0 means "none".
// Weight and Port apply to SRV records only (Content then holds the target host).
type Record struct {
	ID      string
	Type    string // A, AAAA, MX, TXT, CNAME, SRV, ...
	Name    string // subdomain part; "@" or "" for apex
	Content string
	TTL     int
	Prio    int
	Weight  int // SRV only
	Port    int // SRV only
}

// identity groups records that occupy the same logical slot, so reconciliation
// treats each slot as a set. A zone may legitimately hold several records with
// the same name+type (multiple MX, several TXT at the apex), so name+type alone
// is not enough: for TXT we further discriminate by scheme (SPF, DMARC, DKIM,
// TLS-RPT, MTA-STS), and any other TXT is keyed by its full content so an
// unrelated verification TXT is never collapsed into — or clobbered by — an SPF
// change. MX/A/AAAA/CNAME group by type+name (the mail set is authoritative for
// all records of that type at that name).
func (r Record) identity() string {
	t := strings.ToUpper(strings.TrimSpace(r.Type))
	base := t + "\x00" + strings.ToLower(normName(r.Name))
	if t == "TXT" {
		return base + "\x00" + txtScheme(r.Content)
	}
	return base
}

// txtScheme classifies a TXT value so single-valued mail policies (SPF, DMARC,
// DKIM, TLS-RPT, MTA-STS) each own exactly one slot. Anything else is keyed by
// its full content and thus left untouched by mail reconciliation.
func txtScheme(content string) string {
	c := strings.ToLower(strings.TrimSpace(strings.Trim(content, `"`)))
	switch {
	case strings.HasPrefix(c, "v=spf1"):
		return "spf"
	case strings.HasPrefix(c, "v=dmarc1"):
		return "dmarc"
	case strings.HasPrefix(c, "v=dkim1"):
		return "dkim"
	case strings.HasPrefix(c, "v=tlsrptv1"):
		return "tlsrpt"
	case strings.HasPrefix(c, "v=stsv1"):
		return "mtasts"
	default:
		return "other:" + c
	}
}

func normName(n string) string {
	n = strings.TrimSpace(n)
	if n == "" {
		return "@"
	}
	return n
}

func sameContent(a, b Record) bool {
	// Target-host records (MX/CNAME/SRV/NS) are FQDNs; compare with the trailing
	// dot normalised away so "host" and "host." are treated as equal regardless
	// of how the registrar stores them.
	if !strings.EqualFold(normContent(a), normContent(b)) || a.Prio != b.Prio {
		return false
	}
	if strings.EqualFold(a.Type, "SRV") {
		return a.Weight == b.Weight && a.Port == b.Port
	}
	return true
}

// isHostTarget reports whether a record type's content is a hostname (FQDN).
func isHostTarget(t string) bool {
	switch strings.ToUpper(t) {
	case "MX", "CNAME", "SRV", "NS", "PTR":
		return true
	}
	return false
}

// normContent trims a trailing dot from host-target record content for
// comparison; other types are compared verbatim (trimmed of surrounding space).
func normContent(r Record) string {
	c := strings.TrimSpace(r.Content)
	if isHostTarget(r.Type) {
		c = strings.TrimSuffix(c, ".")
	}
	return c
}

// fqdn appends a trailing dot to a hostname if missing (registrars that require
// fully-qualified targets, e.g. Njalla, reject bare names for MX/CNAME/SRV).
func fqdn(host string) string {
	host = strings.TrimSpace(host)
	if host == "" || strings.HasSuffix(host, ".") {
		return host
	}
	return host + "."
}

// Provider is a registrar DNS backend.
type Provider interface {
	Name() string
	ListRecords(ctx context.Context, domain string) ([]Record, error)
	AddRecord(ctx context.Context, domain string, r Record) error
	EditRecord(ctx context.Context, domain string, r Record) error // r.ID required
	RemoveRecord(ctx context.Context, domain, id string) error
}

// ZoneInfo describes a hosted zone after creation: the nameservers to delegate
// to at the registrar, and the DNSSEC DS records to publish at the parent.
type ZoneInfo struct {
	Created     bool     `json:"created"` // true if this call created the zone
	Nameservers []string `json:"nameservers"`
	DS          []string `json:"ds"`
}

// ZoneManager is implemented by providers that can host a zone (create the DNS
// zone, not register the domain). deSEC supports this; registrar-only backends
// where the domain must already exist in the account do not.
type ZoneManager interface {
	// EnsureZone creates the zone if it does not exist and returns its
	// delegation info. Created is false when the zone was already present.
	EnsureZone(ctx context.Context, domain string) (ZoneInfo, error)
}

// Change operations.
const (
	OpAdd       = "add"       // desired record absent live
	OpEdit      = "edit"      // one live record updated to the desired value
	OpUnchanged = "unchanged" // live already equals desired
	OpDelete    = "delete"    // superfluous live record in a managed slot (e.g. a
	// second MX, a duplicate SPF) that must be removed so the slot exactly
	// matches the desired set
)

// Change is one reconciliation action (for preview + audit). Record is the
// desired record (empty for delete); Current is the live record (set for
// edit/unchanged/delete, nil for add) so callers can show an old→new diff.
type Change struct {
	Op      string
	Record  Record
	Current *Record
}

// Plan reconciles, per managed slot (see Record.identity), the live records
// against the desired set. Within a slot it keeps exact matches, edits a
// leftover live record to each remaining desired value, adds when live runs
// short, and DELETES any live record left over — so a slot ends up holding
// exactly the desired records (e.g. two stale MX collapse to the one wanted).
// Slots not present in `desired` are untouched here (see Stale for those).
func Plan(live, desired []Record) []Change {
	liveByID := groupByIdentity(live)
	seen := make(map[string]bool, len(desired))
	var out []Change
	for _, group := range groupOrder(desired) {
		if seen[group] {
			continue
		}
		seen[group] = true
		out = append(out, reconcileSlot(liveByID[group], desiredOf(desired, group))...)
	}
	return out
}

// reconcileSlot makes the live list equal the desired list for one identity.
func reconcileSlot(live, desired []Record) []Change {
	usedLive := make([]bool, len(live))
	pendingDesired := make([]bool, len(desired))
	out := make([]Change, 0, len(desired))

	// 1) exact content matches stay unchanged.
	for j, d := range desired {
		for i, l := range live {
			if usedLive[i] || !sameContent(l, d) {
				continue
			}
			l := l
			usedLive[i] = true
			pendingDesired[j] = true
			out = append(out, Change{Op: OpUnchanged, Record: d, Current: &l})
			break
		}
	}
	// 2) remaining desired: reuse a leftover live record (edit) or add.
	nextFree := func() int {
		for i := range live {
			if !usedLive[i] {
				return i
			}
		}
		return -1
	}
	for j, d := range desired {
		if pendingDesired[j] {
			continue
		}
		if i := nextFree(); i >= 0 {
			cur := live[i]
			usedLive[i] = true
			d.ID = cur.ID
			out = append(out, Change{Op: OpEdit, Record: d, Current: &cur})
		} else {
			out = append(out, Change{Op: OpAdd, Record: d})
		}
	}
	// 3) any live record still unused in this managed slot is superfluous → delete.
	for i, l := range live {
		if usedLive[i] {
			continue
		}
		l := l
		out = append(out, Change{Op: OpDelete, Current: &l, Record: l})
	}
	return out
}

// Stale returns live records whose identity is NOT in the desired set — records
// the mail set does not manage at all (old host A/AAAA, foreign CNAMEs,
// unrelated verification TXT). These are deletion candidates surfaced for
// interactive review. Superfluous records WITHIN a managed slot are not here;
// they are OpDelete changes in Plan. When protectApexWeb is true, apex/www
// A/AAAA/CNAME are excluded.
func Stale(live, desired []Record, protectApexWeb bool) []Record {
	want := make(map[string]struct{}, len(desired))
	for _, d := range desired {
		want[d.identity()] = struct{}{}
	}
	var out []Record
	for _, r := range live {
		if _, ok := want[r.identity()]; ok {
			continue
		}
		if protectApexWeb && isApexWeb(r) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// Reconcile applies a Plan via the provider, returning the mutating changes for
// the audit log. Deletes run last so a slot is never briefly empty.
func Reconcile(ctx context.Context, p Provider, domain string, desired []Record) ([]Change, error) {
	live, err := p.ListRecords(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", domain, err)
	}
	plan := Plan(live, desired)
	var applied []Change
	apply := func(only string) error {
		for _, c := range plan {
			if c.Op != only {
				continue
			}
			switch c.Op {
			case OpAdd:
				if err := p.AddRecord(ctx, domain, c.Record); err != nil {
					return fmt.Errorf("add %s %s: %w", c.Record.Type, c.Record.Name, err)
				}
			case OpEdit:
				if err := p.EditRecord(ctx, domain, c.Record); err != nil {
					return fmt.Errorf("edit %s %s: %w", c.Record.Type, c.Record.Name, err)
				}
			case OpDelete:
				if c.Current != nil && c.Current.ID != "" {
					if err := p.RemoveRecord(ctx, domain, c.Current.ID); err != nil {
						return fmt.Errorf("delete %s %s: %w", c.Current.Type, c.Current.Name, err)
					}
				}
			}
			applied = append(applied, c)
		}
		return nil
	}
	for _, op := range []string{OpAdd, OpEdit, OpDelete} {
		if err := apply(op); err != nil {
			return applied, err
		}
	}
	return applied, nil
}

// groupByIdentity buckets records by their managed-slot identity.
func groupByIdentity(recs []Record) map[string][]Record {
	m := make(map[string][]Record)
	for _, r := range recs {
		id := r.identity()
		m[id] = append(m[id], r)
	}
	return m
}

// groupOrder returns identities in first-seen order (stable, deterministic).
func groupOrder(recs []Record) []string {
	seen := make(map[string]bool, len(recs))
	var order []string
	for _, r := range recs {
		id := r.identity()
		if !seen[id] {
			seen[id] = true
			order = append(order, id)
		}
	}
	return order
}

// desiredOf returns the desired records belonging to one identity.
func desiredOf(desired []Record, id string) []Record {
	var out []Record
	for _, d := range desired {
		if d.identity() == id {
			out = append(out, d)
		}
	}
	return out
}

// MailRecordOpts carries the values needed to build the desired mail record-set.
type MailRecordOpts struct {
	MailHost   string // e.g. mail.kiefer-networks.de
	IPv4       string
	IPv6       string
	Selector   string // DKIM selector, e.g. mail2026
	DKIMValue  string // full "v=DKIM1; k=rsa; p=..." string
	TTL        int    // default 3600
	ReportTo   string // rua/ruf localpart target domain (usually the primary domain)
	WithMTASTS bool   // publish _mta-sts + mta-sts host — only once the vhost+cert are live (enforce mode!)
}

// DesiredMailRecords builds the standard mail record-set for a domain. This
// mirrors what `mailadmin dns <domain>` prints. Host A/AAAA for MailHost are
// emitted only when MailHost sits inside `domain`'s zone.
func DesiredMailRecords(domain string, o MailRecordOpts) []Record {
	if o.TTL == 0 {
		o.TTL = 3600
	}
	rt := o.ReportTo
	if rt == "" {
		rt = domain
	}
	recs := []Record{
		{Type: "MX", Name: "@", Content: fqdn(o.MailHost), Prio: 10, TTL: o.TTL},
		{Type: "TXT", Name: "@", Content: "v=spf1 mx -all", TTL: o.TTL},
		{Type: "TXT", Name: "_dmarc", TTL: o.TTL,
			Content: fmt.Sprintf("v=DMARC1; p=quarantine; rua=mailto:dmarc@%s; ruf=mailto:dmarc@%s; fo=1; adkim=s; aspf=s; pct=100", rt, rt)},
		{Type: "TXT", Name: o.Selector + "._domainkey", Content: o.DKIMValue, TTL: o.TTL},
		{Type: "TXT", Name: "_smtp._tls", Content: "v=TLSRPTv1; rua=mailto:tlsrpt@" + rt, TTL: o.TTL},
	}
	// Client autodiscovery. SRV records (RFC 6186) let IMAP/submission-capable
	// clients find the server with no web server involved. autoconfig
	// (Thunderbird) and autodiscover (Outlook) are CNAMEs to the canonical mail
	// host — like mailbox.org — so there is no per-domain A/AAAA to maintain and
	// a single Caddy on-demand-TLS endpoint serves the generic config XML for
	// every hosted domain.
	recs = append(recs,
		Record{Type: "SRV", Name: "_imaps._tcp", Content: fqdn(o.MailHost), Prio: 0, Weight: 1, Port: 993, TTL: o.TTL},
		Record{Type: "SRV", Name: "_submissions._tcp", Content: fqdn(o.MailHost), Prio: 0, Weight: 1, Port: 465, TTL: o.TTL},
		Record{Type: "SRV", Name: "_autodiscover._tcp", Content: fqdn(o.MailHost), Prio: 0, Weight: 1, Port: 443, TTL: o.TTL},
		Record{Type: "CNAME", Name: "autoconfig", Content: fqdn(o.MailHost), TTL: o.TTL},
		Record{Type: "CNAME", Name: "autodiscover", Content: fqdn(o.MailHost), TTL: o.TTL},
	)

	// The mta-sts host records only point a name at the mail server — harmless on
	// their own, and required so Caddy can obtain the policy-endpoint cert. They
	// are always part of the desired set. The _mta-sts TXT is what actually
	// switches senders into MTA-STS policy lookups, so it stays behind the
	// readiness guard (WithMTASTS) to avoid advertising an enforce policy before
	// the HTTPS endpoint is live.
	if o.IPv4 != "" {
		recs = append(recs, Record{Type: "A", Name: "mta-sts", Content: o.IPv4, TTL: o.TTL})
	}
	if o.IPv6 != "" {
		recs = append(recs, Record{Type: "AAAA", Name: "mta-sts", Content: o.IPv6, TTL: o.TTL})
	}
	if o.WithMTASTS {
		recs = append(recs, Record{Type: "TXT", Name: "_mta-sts", Content: "v=STSv1; id=" + mtaStsID(), TTL: o.TTL})
	}
	if host, ok := strings.CutSuffix(o.MailHost, "."+domain); ok && host != "" {
		if o.IPv4 != "" {
			recs = append(recs, Record{Type: "A", Name: host, Content: o.IPv4, TTL: o.TTL})
		}
		if o.IPv6 != "" {
			recs = append(recs, Record{Type: "AAAA", Name: host, Content: o.IPv6, TTL: o.TTL})
		}
	}
	return recs
}
