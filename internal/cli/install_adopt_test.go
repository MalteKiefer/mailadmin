package cli

import "testing"

// Flags win over the config; the config fills only what the flags leave empty.
func TestApplyAdoptDefaultsFillsOnlyEmptyInputs(t *testing.T) {
	in := installInputs{hostname: "flag.example.com"}
	applyAdoptDefaults(&in, adoptDefaults{
		hostname: "cfg.example.com", domain: "example.com", ipv4: "192.0.2.1",
		pgdg: "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8",
	})
	if in.hostname != "flag.example.com" {
		t.Fatalf("hostname = %q, the flag must win", in.hostname)
	}
	if in.domain != "example.com" || in.ipv4 != "192.0.2.1" || in.pgdgFingerprint == "" {
		t.Fatalf("config values not applied: %+v", in)
	}
}
