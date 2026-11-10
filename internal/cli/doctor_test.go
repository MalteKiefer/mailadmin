package cli

import (
	"strings"
	"testing"

	"mailadmin/internal/notify"
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
			t.Fatalf("detail %q incorrectly treats dnssec as smtp_tls_security_level, positional parse bug", got.Detail)
		}
	})
}

func TestDoctorNotifyMessage(t *testing.T) {
	healthy := []checkResult{
		{Name: "service:postfix", Status: statusOK, Detail: "active/running (enabled)"},
		{Name: "tls-cert", Status: statusWarn, Detail: "no readable certificate"}, // WARN must never trigger a page
	}
	failing := []checkResult{
		{Name: "service:postfix", Status: statusFail, Detail: "inactive/dead (disabled)"},
		{Name: "ports", Status: statusFail, Detail: "not listening: 25"},
		{Name: "tls-cert", Status: statusWarn, Detail: "no readable certificate"},
	}

	t.Run("healthy, no heartbeat: nothing to send", func(t *testing.T) {
		_, ok := doctorNotifyMessage(healthy, false, "host1")
		if ok {
			t.Fatal("expected ok=false (silence is the success signal)")
		}
	})

	t.Run("healthy, heartbeat: low-priority OK ping", func(t *testing.T) {
		msg, ok := doctorNotifyMessage(healthy, true, "host1")
		if !ok {
			t.Fatal("expected ok=true with heartbeat requested")
		}
		if msg.Priority != notify.PriorityLow {
			t.Errorf("priority = %q, want low", msg.Priority)
		}
		if !strings.Contains(msg.Title, "OK") {
			t.Errorf("title = %q, want an OK heartbeat title", msg.Title)
		}
		if !strings.Contains(msg.Body, "host1") {
			t.Errorf("body = %q, want it to mention the host", msg.Body)
		}
	})

	t.Run("failing: exactly one high-priority notification naming only the FAILs", func(t *testing.T) {
		msg, ok := doctorNotifyMessage(failing, false, "mailhost")
		if !ok {
			t.Fatal("expected ok=true when checks are failing")
		}
		if msg.Priority != notify.PriorityHigh {
			t.Errorf("priority = %q, want high", msg.Priority)
		}
		if !strings.Contains(msg.Title, "2 check(s) failing") {
			t.Errorf("title = %q, want it to count exactly the 2 FAILs (not the WARN)", msg.Title)
		}
		if !strings.Contains(msg.Body, "service:postfix") || !strings.Contains(msg.Body, "ports") {
			t.Errorf("body = %q, want both failing check names", msg.Body)
		}
		if strings.Contains(msg.Body, "tls-cert") {
			t.Errorf("body = %q, WARN row must not be included", msg.Body)
		}
	})

	t.Run("failing with heartbeat: still exactly one failure notification, not a heartbeat", func(t *testing.T) {
		msg, ok := doctorNotifyMessage(failing, true, "mailhost")
		if !ok || msg.Priority != notify.PriorityHigh {
			t.Fatalf("heartbeat flag must not soften a failing run: msg=%+v ok=%v", msg, ok)
		}
	})
}
