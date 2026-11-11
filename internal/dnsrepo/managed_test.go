package dnsrepo

import (
	"strings"
	"testing"

	"mailadmin/internal/dnsprovider"
)

const zone = `var DSP = NewDnsProvider("desec");

D("pinlo.me", REG, DnsProvider(DSP),
    DefaultTTL(3600),

    CNAME("*", "eu1.netbird.services."),
    A("@", "192.0.2.10"),

    MX("@", 10, "mxext1.mailbox.org."),
    TXT("@", "v=spf1 include:mailbox.org -all"),
    CNAME("mbo0001._domainkey", "mbo0001._domainkey.mailbox.org.")
);
`

func TestMailScopeClassification(t *testing.T) {
	cases := map[string]bool{
		`MX("@", 10, "x.")`:                         true,
		`TXT("@", "v=spf1 mx -all")`:                true,
		`TXT("_dmarc", "v=DMARC1; p=none")`:         true,
		`CNAME("mbo0001._domainkey", "x.")`:         true,
		`A("mail", "192.0.2.1")`:                    true,
		`CNAME("*", "eu1.netbird.services.")`:       false,
		`A("@", "192.0.2.10")`:                      false,
		`TXT("_github-pages-challenge", "abc")`:     false,
		`TXT("@", "apple-domain-verification=abc")`: false,
	}
	for line, want := range cases {
		st, ok := parseStatement(line)
		if !ok {
			t.Fatalf("not parsed: %s", line)
		}
		if got := MailScope(st); got != want {
			t.Errorf("MailScope(%s)=%v want %v", line, got, want)
		}
	}
}

func TestSetManagedReplacesMailKeepsWeb(t *testing.T) {
	lines := []string{`MX("@", 10, "mail.kiefer-networks.de.")`, `TXT("@", "v=spf1 mx -all")`}
	out, removed, err := SetManaged(zone, "pinlo.me", lines, func(s Statement) bool { return MailScope(s) })
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 3 {
		t.Fatalf("removed = %v, want MX, SPF and DKIM", removed)
	}
	for _, gone := range []string{"mxext1.mailbox.org", "v=spf1 include:mailbox.org", "mbo0001._domainkey"} {
		if strings.Contains(out, gone) {
			t.Fatalf("%s still present:\n%s", gone, out)
		}
	}
	for _, keep := range []string{`CNAME("*", "eu1.netbird.services.")`, `A("@", "192.0.2.10")`} {
		if !strings.Contains(out, keep) {
			t.Fatalf("%s lost:\n%s", keep, out)
		}
	}
	if !strings.Contains(out, "    // BEGIN mailadmin-managed\n    MX(\"@\", 10, \"mail.kiefer-networks.de.\"),") {
		t.Fatalf("block missing:\n%s", out)
	}
	// a second run with the same lines changes nothing
	again, _, err := SetManaged(out, "pinlo.me", lines, func(s Statement) bool { return MailScope(s) })
	if err != nil || again != out {
		t.Fatalf("second run changed the file: %v\n%s", err, again)
	}
}

func TestSetManagedKeepsMailWhenNoDrop(t *testing.T) {
	out, removed, err := SetManaged(zone, "pinlo.me", nil, nil)
	if err != nil || len(removed) != 0 || !strings.Contains(out, "mxext1.mailbox.org") {
		t.Fatalf("no-drop run changed records: %v %v", removed, err)
	}
}

func TestRenderRecordSyntax(t *testing.T) {
	cases := []struct {
		rec  dnsprovider.Record
		want string
	}{
		{dnsprovider.Record{Type: "A", Name: "mta-sts", Content: "192.0.2.1"}, `A("mta-sts", "192.0.2.1")`},
		{dnsprovider.Record{Type: "MX", Name: "@", Content: "mail.example.com", Prio: 10}, `MX("@", 10, "mail.example.com.")`},
		{dnsprovider.Record{Type: "TXT", Name: "_dmarc", Content: `v=DMARC1; rua=mailto:"a"`}, `TXT("_dmarc", "v=DMARC1; rua=mailto:\"a\"")`},
		{dnsprovider.Record{Type: "SRV", Name: "_imaps._tcp", Content: "mail.example.com.", Prio: 0, Weight: 1, Port: 993}, `SRV("_imaps._tcp", 0, 1, 993, "mail.example.com.")`},
		{dnsprovider.Record{Type: "TLSA", Name: "_25._tcp.mail", Content: "3 1 1 ABCD"}, `TLSA("_25._tcp.mail", 3, 1, 1, "abcd")`},
	}
	for _, c := range cases {
		got, err := RenderRecord(c.rec)
		if err != nil || got != c.want {
			t.Errorf("RenderRecord(%+v) = %q, %v; want %q", c.rec, got, err, c.want)
		}
	}
}
