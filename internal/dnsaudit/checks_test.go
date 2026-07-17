package dnsaudit

import (
	"context"
	"fmt"
	"testing"
)

func TestEvalSPF(t *testing.T) {
	cases := []struct {
		name    string
		records []string
		want    Status
	}{
		{"missing", nil, Fail},
		{"hardfail", []string{"v=spf1 mx -all"}, Pass},
		{"softfail", []string{"v=spf1 include:_spf.google.com ~all"}, Pass},
		{"neutral", []string{"v=spf1 ?all"}, Warn},
		{"plusall", []string{"v=spf1 +all"}, Fail},
		{"noall", []string{"v=spf1 mx"}, Warn},
		{"multiple", []string{"v=spf1 mx -all", "v=spf1 a -all"}, Fail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evalSPF(c.records)[0].Status
			if got != c.want {
				t.Errorf("evalSPF(%v) = %s, want %s", c.records, got, c.want)
			}
		})
	}
}

func TestSpfAllQualifier(t *testing.T) {
	q, ok := spfAllQualifier("v=spf1 include:x ~all")
	if !ok || q != "~" {
		t.Errorf("got %q,%v want ~,true", q, ok)
	}
	if _, ok := spfAllQualifier("v=spf1 mx"); ok {
		t.Error("expected no all qualifier")
	}
}

func TestSpfMechanism(t *testing.T) {
	cases := []struct{ in, mech, arg string }{
		{"include:_spf.google.com", "include", "_spf.google.com"},
		{"-all", "all", ""},
		{"redirect=example.com.", "redirect", "example.com"},
		{"~mx", "mx", ""},
		{"a:mail.example.com.", "a", "mail.example.com"},
	}
	for _, c := range cases {
		m, a := spfMechanism(c.in)
		if m != c.mech || a != c.arg {
			t.Errorf("spfMechanism(%q) = %q,%q want %q,%q", c.in, m, a, c.mech, c.arg)
		}
	}
}

func TestSpfLookupFinding(t *testing.T) {
	if spfLookupFinding(3, false).Status != Pass {
		t.Error("3 lookups should pass")
	}
	if spfLookupFinding(9, false).Status != Warn {
		t.Error("9 lookups should warn")
	}
	if spfLookupFinding(11, false).Status != Fail {
		t.Error("11 lookups should fail")
	}
	if spfLookupFinding(5, true).Status != Fail {
		t.Error("capped should fail")
	}
}

func TestEvalDKIM(t *testing.T) {
	if f, found := evalDKIM("s1", nil); f.Status != Warn || found {
		t.Error("missing selector should warn and report found=false")
	}
	if f, _ := evalDKIM("s1", []string{"v=DKIM1; k=rsa; p="}); f.Status != Fail {
		t.Error("revoked (empty p) should fail")
	}
	if f, found := evalDKIM("s1", []string{"v=DKIM1; k=ed25519; p=abc"}); f.Status != Pass || !found {
		t.Error("ed25519 should pass and report found=true")
	}
	// 2048-bit RSA key (real, generated for the test).
	if f, _ := evalDKIM("s1", []string{"v=DKIM1; k=rsa; p=" + rsa2048}); f.Status != Pass {
		t.Errorf("2048-bit rsa should pass, got %s (%s)", f.Status, f.Detail)
	}
}

func TestEvalDMARC(t *testing.T) {
	p, f := evalDMARC([]string{"v=DMARC1; p=reject; rua=mailto:x@y.z"})
	if p != "reject" || f[0].Status != Pass {
		t.Errorf("reject+rua should pass, got %s %s", p, f[0].Status)
	}
	_, f = evalDMARC([]string{"v=DMARC1; p=none"})
	if f[0].Status != Warn {
		t.Error("p=none should warn")
	}
	_, f = evalDMARC(nil)
	if f[0].Status != Fail {
		t.Error("missing DMARC should fail")
	}
}

func TestEvalMTASTSRecord(t *testing.T) {
	if evalMTASTSRecord(nil).Status != Info {
		t.Error("missing STS record should be info")
	}
	if evalMTASTSRecord([]string{"v=STSv1; id=1", "v=STSv1; id=2"}).Status != Fail {
		t.Error("duplicate STS records should fail")
	}
	if evalMTASTSRecord([]string{"v=STSv1; id=20260101"}).Status != Pass {
		t.Error("single STS record with id should pass")
	}
}

func TestEvalMTASTSPolicy(t *testing.T) {
	enforce := "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n"
	if evalMTASTSPolicy(enforce).Status != Pass {
		t.Error("enforce policy should pass")
	}
	if evalMTASTSPolicy("version: STSv1\nmode: testing\nmx: m\n").Status != Warn {
		t.Error("testing mode should warn")
	}
	if evalMTASTSPolicy("version: STSv1\nmode: enforce\n").Status != Fail {
		t.Error("enforce with no mx should fail")
	}
	if evalMTASTSPolicy("garbage").Status != Fail {
		t.Error("invalid body should fail")
	}
}

func TestEvalBIMI(t *testing.T) {
	if evalBIMI(nil, "reject").Status != Info {
		t.Error("no BIMI should be info")
	}
	if evalBIMI([]string{"v=BIMI1; l=https://x/logo.svg; a=https://x/vmc.pem"}, "reject").Status != Pass {
		t.Error("logo+VMC with enforcing DMARC should pass")
	}
	if evalBIMI([]string{"v=BIMI1; l=https://x/logo.svg"}, "none").Status != Warn {
		t.Error("BIMI with p=none should warn")
	}
}

func TestDaneMatch(t *testing.T) {
	live := "3 1 1 abc123"
	cases := []struct {
		name      string
		published []string
		want      bool
	}{
		{"exact", []string{"3 1 1 abc123"}, true},
		{"case-insensitive", []string{"3 1 1 ABC123"}, true},
		{"rollover overlap", []string{"3 1 1 old000", "3 1 1 abc123"}, true},
		{"stale only", []string{"3 1 1 old000"}, false},
		{"empty", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := daneMatch(tc.published, live); got != tc.want {
				t.Fatalf("daneMatch(%v,%q)=%v want %v", tc.published, live, got, tc.want)
			}
		})
	}
}

type daneFakeConn struct {
	hosts    []string
	tlsaVals []string
	ad       bool
}

func (f daneFakeConn) txt(context.Context, string) ([]string, error) { return nil, nil }
func (f daneFakeConn) dnssec(context.Context, string) (bool, bool, bool, error) {
	return false, false, false, nil
}
func (f daneFakeConn) mx(context.Context, string) ([]string, error) { return f.hosts, nil }
func (f daneFakeConn) tlsa(context.Context, string) ([]string, bool, error) {
	return f.tlsaVals, f.ad, nil
}

func TestEvalDANEMatch(t *testing.T) {
	base := daneFakeConn{hosts: []string{"mx.example."}, tlsaVals: []string{"3 1 1 abc"}, ad: true}
	cases := []struct {
		name       string
		probe      func(context.Context, string) (string, error)
		wantStatus Status
	}{
		{"match", func(context.Context, string) (string, error) { return "3 1 1 abc", nil }, Pass},
		{"mismatch", func(context.Context, string) (string, error) { return "3 1 1 zzz", nil }, Fail},
		{"unreachable", func(context.Context, string) (string, error) { return "", fmt.Errorf("dial timeout") }, Warn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Auditor{conn: base, probeCert: tc.probe}
			f := a.evalDANE(context.Background(), "example.com")
			if f.Status != tc.wantStatus {
				t.Fatalf("status=%s want %s (detail %q)", f.Status, tc.wantStatus, f.Detail)
			}
		})
	}
}

func TestEvalDANENon311SkipsMatch(t *testing.T) {
	conn := daneFakeConn{hosts: []string{"mx.example."}, tlsaVals: []string{"2 0 1 abc"}, ad: true}
	probed := false
	a := &Auditor{conn: conn, probeCert: func(context.Context, string) (string, error) {
		probed = true
		return "3 1 1 abc", nil
	}}
	f := a.evalDANE(context.Background(), "example.com")
	if f.Status != Pass {
		t.Fatalf("status=%s want Pass", f.Status)
	}
	if probed {
		t.Fatal("probeCert should not be called for non-3-1-1 TLSA")
	}
}

// rsa2048 is the base64 SubjectPublicKeyInfo of a 2048-bit RSA key (test-only).
const rsa2048 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAutMr4fhaKrvoRdnSkQ50wUvakIxhyJEydgP3bXfmuCJ0bcGuHJ3EZQZkDcUV4g2t04rF7x+XdE1cTDAVm7hCH1sTsOxKm9CW039ApesPZNNMVr5kdECfBSFdY/Q264UPForgcGhseB4o7FVv15N2LF01FglRI5JQSvBQ+gQCOYoVOTtfxxE/C5gAu69fycqEyYQsJTx2GOCaa9jIika1DYjr5PHeJn/8UVOuairQCMX2oOkfPGsZQgOzaTv+ep81TFrV0VhphU55CE9taiovu7Gsu1kDQIxHkeiyKVJMBxK+WXywdV7q2qJhVhBOHM9vo/alBsSoIN+5DGg0BY+6lwIDAQAB"
