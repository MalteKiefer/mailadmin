package cli

import (
	"path/filepath"
	"testing"

	"mailadmin/internal/dnsrepo"
)

func TestParseTLSA(t *testing.T) {
	u, s, m, d, err := parseTLSA("3 1 1 ABCDEF")
	if err != nil || u != 3 || s != 1 || m != 1 || d != "abcdef" {
		t.Fatalf("parseTLSA = %d %d %d %q %v", u, s, m, d, err)
	}
	if _, _, _, _, err := parseTLSA("3 1 1"); err == nil {
		t.Fatal("short value must be refused")
	}
}

func TestSameTLSAIgnoresCaseAndSpacing(t *testing.T) {
	if !sameTLSA("3  1 1 ABCD", "3 1 1 abcd") {
		t.Fatal("same record must match")
	}
	if sameTLSA("3 1 1 abcd", "3 1 1 abce") {
		t.Fatal("different digest must not match")
	}
}

func TestPendingStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if _, ok, err := dnsrepo.LoadState(path); err != nil || ok {
		t.Fatalf("missing state: ok=%v err=%v", ok, err)
	}
	want := dnsrepo.State{Domain: "example.com", PR: "42", Branch: "b", TLSA: "3 1 1 aa"}
	if err := dnsrepo.SaveState(path, want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := dnsrepo.LoadState(path)
	if err != nil || !ok || got.PR != "42" || got.TLSA != want.TLSA {
		t.Fatalf("round trip: %+v ok=%v err=%v", got, ok, err)
	}
	if err := dnsrepo.ClearState(path); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := dnsrepo.LoadState(path); ok {
		t.Fatal("state not cleared")
	}
}
