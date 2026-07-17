package cli

import (
	"strings"
	"testing"
)

func TestClassifyResolver(t *testing.T) {
	cases := []struct {
		name, conf string
		want       checkStatus
	}{
		{"loopback v4", "nameserver 127.0.0.1\n", statusOK},
		{"loopback v6", "nameserver ::1\n", statusOK},
		{"remote", "nameserver 8.8.8.8\n", statusWarn},
		{"none", "# comment only\n", statusWarn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyResolver(tc.conf); got.Status != tc.want {
				t.Fatalf("status=%s want %s (detail %q)", got.Status, tc.want, got.Detail)
			}
		})
	}
}

func TestClassifyDANEOutbound(t *testing.T) {
	cases := []struct {
		name, level, support string
		want                 checkStatus
	}{
		{"dane+dnssec", "dane", "dnssec", statusOK},
		{"dane-only+dnssec", "dane-only", "dnssec", statusOK},
		{"dane without dnssec", "dane", "enabled", statusFail},
		{"not enabled", "may", "enabled", statusWarn},
		{"empty", "", "", statusWarn},
		// Regression: empty level + dnssec support must not be misread as
		// level="dnssec" (the bug that occurred when splitNonEmptyLines
		// collapsed a blank postconf line into position 0).
		{"empty level dnssec support", "", "dnssec", statusWarn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyDANEOutbound(tc.level, tc.support)
			if got.Status != tc.want {
				t.Fatalf("status=%s want %s (detail %q)", got.Status, tc.want, got.Detail)
			}
		})
	}

	// Regression guard: when smtp_tls_security_level is unset (empty) and
	// smtp_dns_support_level=dnssec, the old positional parse collapsed
	// "dnssec" into lines[0], producing a false level of "dnssec" and an OK
	// result. The detail must not treat "dnssec" as the level value.
	t.Run("empty level detail must not show dnssec as level", func(t *testing.T) {
		got := classifyDANEOutbound("", "dnssec")
		if got.Status != statusWarn {
			t.Fatalf("status=%s want WARN (detail %q)", got.Status, got.Detail)
		}
		if strings.Contains(got.Detail, "smtp_tls_security_level=dnssec") {
			t.Fatalf("detail %q incorrectly treats dnssec as smtp_tls_security_level — positional parse bug", got.Detail)
		}
	})
}
