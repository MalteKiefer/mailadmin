package install

import (
	"strings"
	"testing"
)

func TestNftTableDropsInputAndKeepsSSH(t *testing.T) {
	got := NftTableFile(DefaultTCPPorts, nil, []int{22, 2222})
	for _, want := range []string{"policy drop", "tcp dport { 22, 2222 } accept", "tcp dport @allowed_tcp accept", "25, 80, 443, 465, 587, 993"} {
		if !strings.Contains(got, want) {
			t.Fatalf("nft table missing %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "ipv6-icmp") {
		t.Fatal("ICMPv6 must stay open or IPv6 neighbour discovery breaks")
	}
}

func TestCaddyfileTLSInternalOnlyWhenRequested(t *testing.T) {
	if strings.Contains(CaddyfileMain("mx.example.com", false), "local_certs") {
		t.Fatal("acme mode must not enable local certs")
	}
	if !strings.Contains(CaddyfileMain("mx.example.com", true), "local_certs") {
		t.Fatal("internal mode must use the local CA for every site")
	}
}

func TestPostfixMapsNeverContainPasswords(t *testing.T) {
	for path, body := range PostfixPgsqlMaps() {
		if strings.Contains(strings.ToLower(body), "password") && !strings.Contains(body, "active") {
			t.Fatalf("%s selects password-like data without the active filter", path)
		}
		if !strings.Contains(body, "user = postfix") {
			t.Fatalf("%s must connect as the postfix role, not a password login", path)
		}
	}
}

func TestDovecotConfHasNoSystemPassdb(t *testing.T) {
	c := DovecotConf()
	if strings.Contains(c, "auth-system") || strings.Contains(c, "passwd") {
		t.Fatal("dovecot must not authenticate system accounts")
	}
	if !strings.Contains(c, "passdb mailbox {") {
		t.Fatal("dovecot must authenticate against the mailbox table")
	}
}

func TestHelpersRejectBadArguments(t *testing.T) {
	if !strings.Contains(FwPortHelper, `*[!0-9]*) echo "bad port"`) {
		t.Fatal("fw-port helper must reject non-numeric ports")
	}
	if !strings.Contains(DKIMGenHelper, `*[!a-z0-9.-]*`) {
		t.Fatal("dkim helper must validate the domain")
	}
	if !strings.Contains(CertSyncHelper, `*[!a-z0-9.-]*`) {
		t.Fatal("cert helper must validate the host")
	}
}

func TestNftEmptySetHasNoElementsLine(t *testing.T) {
	got := NftTableFile(DefaultTCPPorts, nil, []int{22})
	if strings.Contains(got, "elements = {  }") || strings.Contains(got, "elements = { }") {
		t.Fatalf("empty set rendered an elements line:\n%s", got)
	}
}
