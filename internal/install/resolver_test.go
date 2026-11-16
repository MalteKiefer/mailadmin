package install

import (
	"strings"
	"testing"
)

func TestUnboundOnlyForwardsOverTLSAndValidates(t *testing.T) {
	c := UnboundConf()
	for _, want := range []string{"forward-tls-upstream: yes", "val-permissive-mode: no", "harden-dnssec-stripped: yes"} {
		if !strings.Contains(c, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(c, "@53") {
		t.Fatal("plain DNS upstream must not be configured")
	}
}

func TestResolvconfHasNoUnvalidatedFallback(t *testing.T) {
	h := ResolvconfHead()
	if strings.Contains(h, "2a01:4ff") || strings.Contains(h, "185.12.64.1") {
		t.Fatal("resolv.conf must not fall back to unvalidated upstream resolvers")
	}
}

func TestConfigSetLineReplacesKey(t *testing.T) {
	in := "log_file = /var/log/audit/audit.log\nmax_log_file = 8\nnum_logs = 5\n"
	got := ConfigSetLine(ConfigSetLine(in, "max_log_file", "50"), "num_logs", "10")
	if !strings.Contains(got, "max_log_file = 50") || !strings.Contains(got, "num_logs = 10") || !strings.Contains(got, "log_file = /var/log/audit/audit.log") {
		t.Fatalf("got:\n%s", got)
	}
	if ConfigSetLine(got, "num_logs", "10") != got {
		t.Fatal("not idempotent")
	}
}

func TestMailScenariosListedForInstall(t *testing.T) {
	want := map[string]bool{"Guezli/postfix-sasl-bf": true, "melite/dovecot-time-based-bf": true, "melite/dovecot-slow-bf": true}
	for _, s := range CrowdSecMailScenarios {
		delete(want, s)
	}
	if len(want) != 0 {
		t.Fatalf("missing scenarios: %v", want)
	}
}
