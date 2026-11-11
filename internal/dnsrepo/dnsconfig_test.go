package dnsrepo

import (
	"strings"
	"testing"
)

const sample = `var DSP = NewDnsProvider("desec");

D("kiefer-networks.de", REG, DnsProvider(DSP),
    DefaultTTL(86400),

    A("mail", "65.21.106.107"),

    // SRV
    SRV("_imaps._tcp", 0, 1, 993, "imap.mailbox.org.")
);

D("debgen.org", REG, DnsProvider(DSP),
    A("@", "192.0.2.1")
);
`

func TestSetTLSAInsertsOnceAndIsIdempotent(t *testing.T) {
	out, err := SetTLSA(sample, "kiefer-networks.de", "_25._tcp.mail", 3, 1, 1, "aa11")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `SRV("_imaps._tcp", 0, 1, 993, "imap.mailbox.org."),`+"\n"+"    // BEGIN mailadmin-tlsa") {
		t.Fatalf("comma or block position wrong:\n%s", out)
	}
	if !strings.Contains(out, `TLSA("_25._tcp.mail", 3, 1, 1, "aa11"),`) {
		t.Fatalf("record missing:\n%s", out)
	}
	if !strings.Contains(out, `D("debgen.org"`) || strings.Count(out, "mailadmin-tlsa") != 2 {
		t.Fatalf("other zone or markers changed:\n%s", out)
	}
	again, err := SetTLSA(out, "kiefer-networks.de", "_25._tcp.mail", 3, 1, 1, "bb22")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(again, "BEGIN mailadmin-tlsa") != 1 || !strings.Contains(again, `"bb22"`) || strings.Contains(again, `"aa11"`) {
		t.Fatalf("replace failed:\n%s", again)
	}
	same, _ := SetTLSA(again, "kiefer-networks.de", "_25._tcp.mail", 3, 1, 1, "bb22")
	if same != again {
		t.Fatal("same record must not change the file")
	}
}

func TestSetTLSAUnknownDomain(t *testing.T) {
	if _, err := SetTLSA(sample, "nope.example", "_25._tcp.mail", 3, 1, 1, "aa"); err == nil {
		t.Fatal("unknown domain must be refused")
	}
}
