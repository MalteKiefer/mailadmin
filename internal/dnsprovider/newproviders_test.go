package dnsprovider

import (
	"testing"
	"time"
)

func TestRRIDRoundTrip(t *testing.T) {
	id := rrID("mail", "MX", "10 mx.example.com.")
	slot, typ, val, ok := parseRRID(id)
	if !ok || slot != "mail" || typ != "MX" || val != "10 mx.example.com." {
		t.Fatalf("roundtrip failed: %q %q %q ok=%v", slot, typ, val, ok)
	}
	if _, _, _, ok := parseRRID("no-separators"); ok {
		t.Fatal("expected parse failure on malformed id")
	}
}

func TestRRsetValueAndParse(t *testing.T) {
	cases := []Record{
		{Type: "MX", Content: "mx.example.com", Prio: 10},
		{Type: "SRV", Content: "mail.example.com", Prio: 0, Weight: 1, Port: 993},
		{Type: "TXT", Content: "v=spf1 mx -all"},
		{Type: "A", Content: "203.0.113.10"},
		{Type: "CNAME", Content: "mail.example.com"},
	}
	for _, in := range cases {
		v := rrsetValue(in)
		got := Record{Type: in.Type}
		rrsetParse(&got, v)
		if got.Prio != in.Prio || got.Weight != in.Weight || got.Port != in.Port {
			t.Errorf("%s prio/weight/port mismatch: %+v vs %+v (value %q)", in.Type, got, in, v)
		}
		// Host targets round-trip without the trailing dot.
		if in.Type != "CNAME" && got.Content != in.Content && got.Content != in.Content+"." {
			t.Errorf("%s content mismatch: got %q want %q (value %q)", in.Type, got.Content, in.Content, v)
		}
	}
}

func TestCloudflareNameMapping(t *testing.T) {
	const d = "example.com"
	if got := cfFQDN("@", d); got != "example.com" {
		t.Errorf("apex FQDN = %q", got)
	}
	if got := cfFQDN("mail", d); got != "mail.example.com" {
		t.Errorf("label FQDN = %q", got)
	}
	if got := cfRelative("example.com.", d); got != "@" {
		t.Errorf("apex relative = %q", got)
	}
	if got := cfRelative("mail.example.com", d); got != "mail" {
		t.Errorf("label relative = %q", got)
	}
}

func TestServfailNameMapping(t *testing.T) {
	const d = "example.com"
	if got := servfailFQDN("@", d); got != "example.com." {
		t.Errorf("apex = %q", got)
	}
	if got := servfailFQDN("_dmarc", d); got != "_dmarc.example.com." {
		t.Errorf("label = %q", got)
	}
	if got := servfailRelative("example.com.", d); got != "@" {
		t.Errorf("apex relative = %q", got)
	}
	if got := servfailRelative("_dmarc.example.com.", d); got != "_dmarc" {
		t.Errorf("label relative = %q", got)
	}
	if got := withDot("ns1.example.com"); got != "ns1.example.com." {
		t.Errorf("withDot = %q", got)
	}
	if !servfailInfraType("SOA") || servfailInfraType("MX") {
		t.Error("infra type classification wrong")
	}
}

func TestServercowValue(t *testing.T) {
	if got := servercowValue(Record{Type: "MX", Content: "mx.example.com.", Prio: 10}); got != "10 mx.example.com" {
		t.Errorf("MX value = %q", got)
	}
	if got := servercowValue(Record{Type: "TXT", Content: "v=spf1 -all"}); got != "v=spf1 -all" {
		t.Errorf("TXT value = %q", got)
	}
	if got := servercowName("@"); got != "" {
		t.Errorf("apex name = %q", got)
	}
	single := servercowContent([]string{"a"})
	if s, ok := single.(string); !ok || s != "a" {
		t.Errorf("single content = %v", single)
	}
	if _, ok := servercowContent([]string{"a", "b"}).([]string); !ok {
		t.Error("multi content should be a slice")
	}
}

func TestINWXContentAndName(t *testing.T) {
	if got := inwxContent(Record{Type: "SRV", Content: "mail.example.com", Weight: 1, Port: 993}); got != "1 993 mail.example.com" {
		t.Errorf("SRV content = %q", got)
	}
	if got := inwxContent(Record{Type: "MX", Content: "mx.example.com"}); got != "mx.example.com" {
		t.Errorf("MX content = %q", got)
	}
	if got := inwxName("@"); got != "" {
		t.Errorf("apex name = %q", got)
	}
	if got := inwxRelative("_dmarc.example.com", "example.com"); got != "_dmarc" {
		t.Errorf("relative = %q", got)
	}
}

// TestTOTP checks the RFC 6238 SHA-1 test vector (T=59 -> 94287082 -> 287082).
func TestTOTP(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // base32("12345678901234567890")
	got, err := totp(secret, time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got != "287082" {
		t.Errorf("TOTP = %q, want 287082", got)
	}
}
