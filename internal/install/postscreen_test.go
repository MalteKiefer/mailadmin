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

func TestVRFYStaysDisabled(t *testing.T) {
	for _, s := range PostfixSettings("mail.example.org", nil) {
		if s.Key == "disable_vrfy_command" {
			if s.Value != "yes" {
				t.Fatalf("disable_vrfy_command = %q, want yes", s.Value)
			}
			return
		}
	}
	t.Fatal("disable_vrfy_command missing: VRFY would reveal user names")
}

func TestCaddyAdminAPIIsOff(t *testing.T) {
	for _, internal := range []bool{false, true} {
		out := CaddyfileMain("mail.example.org", internal)
		if !strings.Contains(out, "admin off") {
			t.Fatalf("admin api not off (tlsInternal=%v):\n%s", internal, out)
		}
	}
	if !strings.Contains(CaddyfileMain("mail.example.org", true), "local_certs") {
		t.Fatal("local_certs lost in test mode")
	}
}

func TestHSTSIncludesSubdomainsAndPreload(t *testing.T) {
	if !strings.Contains(CaddyfileMain("mail.example.org", false), "includeSubDomains; preload") {
		t.Fatal("mail vhost must send includeSubDomains and preload")
	}
	if !strings.Contains(CaddyWebmailFile(testWebmail()), "includeSubDomains; preload") {
		t.Fatal("webmail vhost must send includeSubDomains and preload")
	}
}

func TestMilterFailureDefersMail(t *testing.T) {
	for _, s := range PostfixSettings("mail.example.org", nil) {
		if s.Key == "milter_default_action" {
			if s.Value != "tempfail" {
				t.Fatalf("milter_default_action = %q: mail would pass unscanned when rspamd is down", s.Value)
			}
			return
		}
	}
	t.Fatal("milter_default_action missing")
}

func TestCaddyWritesAccessLog(t *testing.T) {
	if !strings.Contains(CaddyfileMain("mail.example.org", false), "output stdout") {
		t.Fatal("mail vhost has no access log")
	}
	if !strings.Contains(CaddyWebmailFile(testWebmail()), "output stdout") {
		t.Fatal("webmail vhost has no access log")
	}
}

func TestCaddyfileHasNoSlashComments(t *testing.T) {
	out := CaddyfileMain("mail.example.org", false)
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "//") {
			t.Fatalf("Caddyfile does not accept // comments: %q", l)
		}
	}
}
