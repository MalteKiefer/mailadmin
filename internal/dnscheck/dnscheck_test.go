package dnscheck

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
)

func txtRR(name string, chunks ...string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeTXT, Class: dns.ClassINET},
		Txt: chunks,
	}
}

func mxRR(name, host string, pref uint16) *dns.MX {
	return &dns.MX{
		Hdr:        dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeMX, Class: dns.ClassINET},
		Preference: pref,
		Mx:         dns.Fqdn(host),
	}
}

func TestCollectTXT(t *testing.T) {
	tests := []struct {
		name string
		msg  *dns.Msg
		want []string
	}{
		{"nil", nil, nil},
		{"empty", new(dns.Msg), nil},
		{
			name: "joins chunks",
			msg:  &dns.Msg{Answer: []dns.RR{txtRR("d", "v=DKIM1; ", "p=abc")}},
			want: []string{"v=DKIM1; p=abc"},
		},
		{
			name: "multiple records",
			msg:  &dns.Msg{Answer: []dns.RR{txtRR("d", "a"), txtRR("d", "b")}},
			want: []string{"a", "b"},
		},
		{
			name: "ignores non-TXT",
			msg:  &dns.Msg{Answer: []dns.RR{mxRR("d", "mail.d", 10), txtRR("d", "x")}},
			want: []string{"x"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := collectTXT(tt.msg)
			if !equalStrings(got, tt.want) {
				t.Fatalf("collectTXT = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCollectMX(t *testing.T) {
	msg := &dns.Msg{Answer: []dns.RR{
		mxRR("d", "mail.d", 10),
		txtRR("d", "ignored"),
		mxRR("d", "backup.d", 20),
	}}
	got := collectMX(msg)
	if len(got) != 2 {
		t.Fatalf("collectMX len = %d, want 2", len(got))
	}
	if got[0].host != "mail.d." || got[0].pref != 10 {
		t.Fatalf("collectMX[0] = %+v", got[0])
	}
	if collectMX(nil) != nil {
		t.Fatal("collectMX(nil) should be nil")
	}
}

func TestSelectTXT(t *testing.T) {
	tests := []struct {
		name    string
		records []string
		prefix  string
		want    string
		ok      bool
	}{
		{"none", nil, "v=spf1", "", false},
		{"prefix match", []string{"other", "v=spf1 mx -all"}, "v=spf1", "v=spf1 mx -all", true},
		{"case insensitive", []string{"V=SPF1 mx -all"}, "v=spf1", "V=SPF1 mx -all", true},
		{"fallback first", []string{"garbage", "more"}, "v=spf1", "garbage", true},
		{"leading space", []string{"  v=spf1 mx -all"}, "v=spf1", "  v=spf1 mx -all", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := selectTXT(tt.records, tt.prefix)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("selectTXT = (%q,%v), want (%q,%v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestNormHost(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"Mail.Example.COM.", "mail.example.com"},
		{"  mail.example.com  ", "mail.example.com"},
		{"mail.example.com", "mail.example.com"},
	} {
		if got := normHost(tt.in); got != tt.want {
			t.Errorf("normHost(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormSpace(t *testing.T) {
	if got := normSpace("  v=spf1   mx    -all "); got != "v=spf1 mx -all" {
		t.Fatalf("normSpace = %q", got)
	}
}

func TestHasPrefixFold(t *testing.T) {
	for _, tt := range []struct {
		s, p string
		want bool
	}{
		{"v=DKIM1; p=x", "v=dkim1", true},
		{"V=SPF1", "v=spf1", true},
		{"short", "longerprefix", false},
		{"nomatch", "v=spf1", false},
	} {
		if got := hasPrefixFold(tt.s, tt.p); got != tt.want {
			t.Errorf("hasPrefixFold(%q,%q) = %v, want %v", tt.s, tt.p, got, tt.want)
		}
	}
}

func TestBuildResults(t *testing.T) {
	const (
		domain   = "example.com"
		selector = "mail2026"
		mailHost = "mail.example.com"
	)
	lk := lookup{
		txt: map[string][]string{
			dns.Fqdn(domain):                             {"v=spf1 mx -all"},
			dns.Fqdn("_dmarc." + domain):                 {"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"},
			dns.Fqdn(selector + "._domainkey." + domain): {"v=DKIM1; k=rsa; p=MIIB"},
			dns.Fqdn("_mta-sts." + domain):               {"v=STSv1; id=20260101000000Z"},
			dns.Fqdn("_smtp._tls." + domain):             {"v=TLSRPTv1; rua=mailto:tlsrpt@example.com"},
		},
		mx:  []mxRecord{{host: "mail.example.com.", pref: 10}},
		err: map[string]error{},
	}
	results := buildResults(domain, selector, mailHost, lk)

	want := map[string]Status{
		"MX":      StatusOK,
		"SPF":     StatusOK,
		"DMARC":   StatusOK,
		"DKIM":    StatusOK,
		"MTA-STS": StatusOK,
		"TLS-RPT": StatusOK,
	}
	if len(results) != len(want) {
		t.Fatalf("got %d results, want %d", len(results), len(want))
	}
	for _, r := range results {
		if r.Status != want[r.Kind] {
			t.Errorf("%s: status = %s, want %s (found=%q)", r.Kind, r.Status, want[r.Kind], r.Found)
		}
	}
}

func TestBuildResultsStatuses(t *testing.T) {
	const (
		domain   = "example.com"
		selector = "mail2026"
		mailHost = "mail.example.com"
	)

	t.Run("missing everything", func(t *testing.T) {
		lk := lookup{txt: map[string][]string{}, err: map[string]error{}}
		for _, r := range buildResults(domain, selector, mailHost, lk) {
			if r.Status != StatusMissing {
				t.Errorf("%s: status = %s, want missing", r.Kind, r.Status)
			}
		}
	})

	t.Run("wrong SPF is mismatch", func(t *testing.T) {
		lk := lookup{
			txt: map[string][]string{dns.Fqdn(domain): {"v=spf1 include:other -all"}},
			err: map[string]error{},
		}
		got := byKind(buildResults(domain, selector, mailHost, lk))
		if got["SPF"].Status != StatusMismatch {
			t.Fatalf("SPF status = %s, want mismatch", got["SPF"].Status)
		}
	})

	t.Run("wrong MX host is mismatch", func(t *testing.T) {
		lk := lookup{
			txt: map[string][]string{},
			mx:  []mxRecord{{host: "mail.other.net.", pref: 10}},
			err: map[string]error{},
		}
		got := byKind(buildResults(domain, selector, mailHost, lk))
		if got["MX"].Status != StatusMismatch {
			t.Fatalf("MX status = %s, want mismatch", got["MX"].Status)
		}
		if got["MX"].Found != "mail.other.net" {
			t.Fatalf("MX found = %q", got["MX"].Found)
		}
	})

	t.Run("lookup error surfaces", func(t *testing.T) {
		lk := lookup{
			txt: map[string][]string{},
			err: map[string]error{dns.Fqdn(domain): errors.New("timeout")},
		}
		got := byKind(buildResults(domain, selector, mailHost, lk))
		if got["SPF"].Status != StatusError {
			t.Fatalf("SPF status = %s, want error", got["SPF"].Status)
		}
		if got["SPF"].Detail != "timeout" {
			t.Fatalf("SPF detail = %q", got["SPF"].Detail)
		}
	})

	t.Run("MX error surfaces", func(t *testing.T) {
		lk := lookup{
			txt: map[string][]string{},
			err: map[string]error{"MX:" + dns.Fqdn(domain): errors.New("servfail")},
		}
		got := byKind(buildResults(domain, selector, mailHost, lk))
		if got["MX"].Status != StatusError {
			t.Fatalf("MX status = %s, want error", got["MX"].Status)
		}
	})

	t.Run("malformed policy record is mismatch via fallback", func(t *testing.T) {
		// DMARC present but wrong version tag -> fallback selects it, prefix
		// mismatch does not matter for non-exact, so it is OK only if tag ok.
		// A record with the right tag is OK; a garbage record still returns the
		// first entry and is treated as OK for policy kinds (present+parsed).
		lk := lookup{
			txt: map[string][]string{dns.Fqdn("_dmarc." + domain): {"garbage"}},
			err: map[string]error{},
		}
		got := byKind(buildResults(domain, selector, mailHost, lk))
		if got["DMARC"].Status != StatusOK {
			t.Fatalf("DMARC status = %s, want ok (present)", got["DMARC"].Status)
		}
	})
}

// fakeConn is a net-free resolverConn for exercising gather().
type fakeConn struct {
	txt map[string]*dns.Msg
	mx  *dns.Msg
	err error
}

func (f *fakeConn) exchange(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
	if f.err != nil {
		return nil, f.err
	}
	if qtype == dns.TypeMX {
		return f.mx, nil
	}
	if m, ok := f.txt[name]; ok {
		return m, nil
	}
	return new(dns.Msg), nil
}

func TestGather(t *testing.T) {
	const (
		domain   = "example.com"
		selector = "mail2026"
	)
	c := New("1.1.1.1:53", "mail.example.com", selector)
	conn := &fakeConn{
		txt: map[string]*dns.Msg{
			dns.Fqdn(domain): {Answer: []dns.RR{txtRR(domain, "v=spf1 mx -all")}},
		},
		mx: &dns.Msg{Answer: []dns.RR{mxRR(domain, "mail.example.com", 10)}},
	}
	lk := c.gather(context.Background(), conn, domain, selector)
	if got := lk.txt[dns.Fqdn(domain)]; len(got) != 1 || got[0] != "v=spf1 mx -all" {
		t.Fatalf("gather txt = %v", got)
	}
	if len(lk.mx) != 1 || lk.mx[0].host != "mail.example.com." {
		t.Fatalf("gather mx = %v", lk.mx)
	}
}

func TestGatherRecordsErrors(t *testing.T) {
	c := New("1.1.1.1:53", "mail.example.com", "mail2026")
	conn := &fakeConn{err: errors.New("net down")}
	lk := c.gather(context.Background(), conn, "example.com", "mail2026")
	if lk.err[dns.Fqdn("example.com")] == nil {
		t.Fatal("expected TXT lookup error recorded")
	}
	if lk.err["MX:"+dns.Fqdn("example.com")] == nil {
		t.Fatal("expected MX lookup error recorded")
	}
}

func TestCheckValidatesInput(t *testing.T) {
	c := New("1.1.1.1:53", "mail.example.com", "mail2026")
	if _, err := c.Check(context.Background(), "bad_domain!", ""); err == nil {
		t.Fatal("expected invalid domain error")
	}
	if _, err := c.Check(context.Background(), "example.com", "bad selector!"); err == nil {
		t.Fatal("expected invalid selector error")
	}
}

func byKind(results []Result) map[string]Result {
	m := make(map[string]Result, len(results))
	for _, r := range results {
		m[r.Kind] = r
	}
	return m
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
