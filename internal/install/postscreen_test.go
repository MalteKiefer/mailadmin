package install

import (
	"strings"
	"testing"
)

func TestPostscreenTakesPort25AndKeepsSubmission(t *testing.T) {
	var smtp, pass bool
	for _, a := range PostfixPostscreenServices() {
		j := strings.Join(a, " ")
		if strings.Contains(j, "smtp/inet=smtp inet") && strings.Contains(j, "postscreen") {
			smtp = true
		}
		if strings.Contains(j, "smtpd/pass=smtpd pass") {
			pass = true
		}
		if strings.Contains(j, "submission") || strings.Contains(j, "smtps/") {
			t.Fatalf("postscreen must not touch submission: %s", j)
		}
	}
	if !smtp || !pass {
		t.Fatal("postscreen service or smtpd pass entry missing")
	}
}

func TestPostscreenSettingsEnforceGreetAndBareNewline(t *testing.T) {
	want := map[string]string{
		"postscreen_greet_action":        "enforce",
		"postscreen_bare_newline_action": "enforce",
		"postscreen_pipelining_action":   "enforce",
	}
	got := map[string]string{}
	for _, s := range PostfixSettings("mail.example.org", nil) {
		got[s.Key] = s.Value
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["postscreen_dnsbl_sites"]; ok {
		t.Fatal("no external DNS blocklist must be queried by default")
	}
}
