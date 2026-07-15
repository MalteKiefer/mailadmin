package dnsprovider

import (
	"strings"
	"testing"
)

func TestDesecFormatParse(t *testing.T) {
	cases := []Record{
		{Type: "MX", Name: "@", Content: "mail.example.com", Prio: 10},
		{Type: "SRV", Name: "_imaps._tcp", Content: "mail.example.com", Prio: 0, Weight: 1, Port: 993},
		{Type: "CNAME", Name: "autoconfig", Content: "mail.example.com"},
		{Type: "A", Name: "mta-sts", Content: "203.0.113.1"},
		{Type: "TXT", Name: "@", Content: "v=spf1 mx -all"},
	}
	for _, r := range cases {
		val := desecFormat(r)
		rs := desecRRset{Subname: desecSubname(r.Name), Type: r.Type, Records: []string{val}}
		got := desecToRecord(rs, val)
		if !strings.EqualFold(strings.TrimSuffix(got.Content, "."), strings.TrimSuffix(r.Content, ".")) {
			t.Errorf("%s content round-trip: got %q want %q (val=%q)", r.Type, got.Content, r.Content, val)
		}
		if r.Type == "MX" && got.Prio != 10 {
			t.Errorf("MX prio lost: %+v", got)
		}
		if r.Type == "SRV" && (got.Port != 993 || got.Weight != 1) {
			t.Errorf("SRV weight/port lost: %+v", got)
		}
	}
}

func TestDesecTXTChunking(t *testing.T) {
	// A long DKIM value must be split into <=255-char quoted chunks and rejoin
	// cleanly.
	long := "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 400)
	q := quoteTXT(long)
	if !strings.HasPrefix(q, `"`) || strings.Count(q, `"`) < 4 {
		t.Fatalf("expected multiple quoted chunks, got %q", q)
	}
	for _, chunk := range splitQuoted(q) {
		if len(chunk) > 255 {
			t.Fatalf("chunk exceeds 255 chars: %d", len(chunk))
		}
	}
	if unquoteTXT(q) != long {
		t.Fatalf("TXT round-trip mismatch")
	}
}

func TestDesecID(t *testing.T) {
	id := desecID("mta-sts", "A", "203.0.113.1")
	sub, typ, val, ok := parseDesecID(id)
	if !ok || sub != "mta-sts" || typ != "A" || val != "203.0.113.1" {
		t.Fatalf("id round-trip failed: %q %q %q %v", sub, typ, val, ok)
	}
}

func TestDesecApexSubname(t *testing.T) {
	if desecSubname("@") != "" || desecSubname("") != "" {
		t.Fatal("apex must map to empty subname")
	}
	if desecURLSub("") != "@" {
		t.Fatal("empty subname must map to @ in URL")
	}
}
