package cli

import "testing"

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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyDANEOutbound(tc.level, tc.support); got.Status != tc.want {
				t.Fatalf("status=%s want %s (detail %q)", got.Status, tc.want, got.Detail)
			}
		})
	}
}
