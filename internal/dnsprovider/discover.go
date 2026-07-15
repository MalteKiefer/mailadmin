package dnsprovider

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// commonSubnames is a best-effort wordlist of hostnames probed when no zone
// transfer or zonefile is available. It cannot find arbitrary custom names, but
// catches the records a mail/web setup usually has.
var commonSubnames = []string{
	"", "www", "mail", "smtp", "imap", "pop", "webmail", "autoconfig", "autodiscover",
	"mta-sts", "cal", "caldav", "carddav", "calendars", "contacts", "dav",
	"ns1", "ns2", "ns3", "ns", "mx", "mx1", "mx2", "relay",
	"vpn", "remote", "ftp", "sftp", "ssh", "git", "cloud", "drive", "files",
	"api", "cdn", "static", "assets", "img", "media", "admin", "portal", "panel",
	"dev", "staging", "test", "beta", "demo", "app", "apps", "blog", "shop", "store",
	"wiki", "docs", "status", "monitor", "grafana", "metrics", "auth", "sso", "id",
	"m", "mobile", "home", "office", "intranet", "gateway", "proxy",
	// Microsoft 365 / Exchange Online / Intune MDM enrollment.
	"enterpriseenrollment", "enterpriseregistration", "lyncdiscover", "msoid",
	"sip", "owa", "exchange", "email", "mailserver", "manage", "mdm", "enroll",
	// Google Workspace legacy service addresses (CNAME -> ghs.googlehosted.com).
	"calendar", "sites", "groups", "start", "video", "meet", "chat",
}

// commonSRV are service SRV names probed at the apex.
var commonSRV = []string{
	"_imaps._tcp", "_imap._tcp", "_submission._tcp", "_submissions._tcp",
	"_pop3s._tcp", "_pop3._tcp", "_sieve._tcp", "_autodiscover._tcp",
	"_caldav._tcp", "_caldavs._tcp", "_carddav._tcp", "_carddavs._tcp",
	"_sip._tls", "_sips._tcp", "_xmpp-client._tcp", "_xmpp-server._tcp",
}

// commonSelectors are DKIM selectors probed under _domainkey (in addition to
// any caller-supplied selectors).
var commonSelectors = []string{
	"default", "mail", "dkim", "google", "selector1", "selector2", "k1", "k2",
	"s1", "s2", "mandrill", "mailjet", "sendgrid", "amazonses", "protonmail",
	// Apple iCloud custom domain: sig1._domainkey CNAME -> ...icloudmailadmin.com.
	"sig1", "sig2",
	// Fastmail, Proton, Zoho, common ESPs.
	"fm1", "fm2", "fm3", "protonmail2", "protonmail3", "zoho", "zmail",
}

// commonTXTNames are policy/verification TXT owners probed at the apex.
var commonTXTNames = []string{
	"", "_dmarc", "_mta-sts", "_smtp._tls", "_domainkey", "_acme-challenge",
}

// Discover probes public DNS (via resolver "host:port") for the records a zone
// commonly holds and returns whatever resolves — a fallback when AXFR and
// zonefiles are unavailable. extraSelectors are DKIM selectors to add to the
// probe set (e.g. the domain's configured selector). Best-effort: it cannot
// enumerate arbitrary custom names.
func Discover(ctx context.Context, resolver, domain string, extraSelectors []string) []Record {
	type query struct {
		name  string
		qtype uint16
	}
	var queries []query
	add := func(sub string, types ...uint16) {
		full := domain
		if sub != "" {
			full = sub + "." + domain
		}
		for _, t := range types {
			queries = append(queries, query{dns.Fqdn(full), t})
		}
	}

	// Host records + web/mail hostnames.
	for _, s := range commonSubnames {
		add(s, dns.TypeA, dns.TypeAAAA, dns.TypeCNAME)
	}
	// Apex-level records.
	add("", dns.TypeMX, dns.TypeNS, dns.TypeCAA)
	// Policy/verification TXT.
	for _, s := range commonTXTNames {
		add(s, dns.TypeTXT)
	}
	// DKIM selectors — probe TXT (self-hosted) and CNAME (delegated, e.g. M365
	// uses selector1/selector2._domainkey CNAMEs).
	sel := append(append([]string{}, commonSelectors...), extraSelectors...)
	for _, s := range sel {
		if s == "" {
			continue
		}
		add(s+"._domainkey", dns.TypeTXT, dns.TypeCNAME)
	}
	// SRV services.
	for _, s := range commonSRV {
		add(s, dns.TypeSRV)
	}

	if !strings.Contains(resolver, ":") {
		resolver += ":53"
	}
	client := &dns.Client{Net: "udp", Timeout: 4 * time.Second}
	resolve := func(name string, qtype uint16) []dns.RR {
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		m.RecursionDesired = true
		resp, _, err := client.ExchangeContext(ctx, m, resolver)
		if err != nil || resp == nil || resp.Rcode != dns.RcodeSuccess {
			return nil
		}
		return resp.Answer
	}

	// Wildcard detection: a made-up label that cannot exist. Whatever it returns
	// is the zone's wildcard (*), per type. Probed names that only match the
	// wildcard value are not real explicit records and must not be migrated as
	// such — a single "*" record is emitted instead.
	const wildProbe = "zzq9x7-mailadmin-wildcard-probe"
	wildValues := map[uint16]map[string]struct{}{}
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeTXT, dns.TypeSRV, dns.TypeCAA} {
		for _, rr := range resolve(dns.Fqdn(wildProbe+"."+domain), t) {
			if rec, ok := rrToRecord(rr, domain); ok {
				if wildValues[t] == nil {
					wildValues[t] = map[string]struct{}{}
				}
				wildValues[t][normContent(rec)] = struct{}{}
			}
		}
	}
	isWildcard := func(rec Record, qtype uint16) bool {
		if rec.Name == "@" {
			return false // wildcards never cover the apex
		}
		vals := wildValues[qtype]
		if vals == nil {
			return false
		}
		_, ok := vals[normContent(rec)]
		return ok
	}

	var (
		mu   sync.Mutex
		out  []Record
		seen = map[string]struct{}{}
	)
	addRec := func(rec Record) {
		key := rec.identity() + "\x00" + normContent(rec)
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		out = append(out, rec)
	}

	sem := make(chan struct{}, 16) // bound concurrency
	var wg sync.WaitGroup
	for _, q := range queries {
		wg.Add(1)
		sem <- struct{}{}
		go func(name string, qtype uint16) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, rr := range resolve(name, qtype) {
				rec, ok := rrToRecord(rr, domain)
				if !ok || isWildcard(rec, qtype) {
					continue // skip wildcard-covered names
				}
				mu.Lock()
				addRec(rec)
				mu.Unlock()
			}
		}(q.name, q.qtype)
	}
	wg.Wait()

	// Emit the wildcard record(s) themselves.
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCAA} {
		typ := map[uint16]string{dns.TypeA: "A", dns.TypeAAAA: "AAAA", dns.TypeCAA: "CAA"}[t]
		for v := range wildValues[t] {
			addRec(Record{Type: typ, Name: "*", Content: v})
		}
	}
	return out
}
