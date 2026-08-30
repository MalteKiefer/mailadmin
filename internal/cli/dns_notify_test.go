package cli

import (
	"strings"
	"testing"

	"mailadmin/internal/notify"
)

func TestDriftCheckNotifyMessage(t *testing.T) {
	clean := []dnsCheckResult{
		{Domain: "a.example", Total: 10, Matched: 10, Drift: 0},
		{Domain: "b.example", Total: 8, Matched: 8, Drift: 0},
	}
	withDrift := []dnsCheckResult{
		{Domain: "a.example", Total: 10, Matched: 10, Drift: 0},
		{Domain: "b.example", Total: 8, Matched: 6, Drift: 2},
	}

	t.Run("clean, no heartbeat: nothing to send", func(t *testing.T) {
		_, ok := driftCheckNotifyMessage(clean, nil, 0, false, "host1")
		if ok {
			t.Fatal("expected ok=false (silence is the success signal)")
		}
	})

	t.Run("clean, heartbeat: low-priority OK ping", func(t *testing.T) {
		msg, ok := driftCheckNotifyMessage(clean, nil, 0, true, "host1")
		if !ok {
			t.Fatal("expected ok=true with heartbeat requested")
		}
		if msg.Priority != notify.PriorityLow {
			t.Errorf("priority = %q, want low", msg.Priority)
		}
		if !strings.Contains(msg.Body, "2 domain(s) checked") {
			t.Errorf("body = %q, want the domain count", msg.Body)
		}
	})

	t.Run("drift: one high-priority notification naming only the drifted domain", func(t *testing.T) {
		msg, ok := driftCheckNotifyMessage(withDrift, nil, 1, false, "mailhost")
		if !ok {
			t.Fatal("expected ok=true when a domain drifted")
		}
		if msg.Priority != notify.PriorityHigh {
			t.Errorf("priority = %q, want high", msg.Priority)
		}
		if !strings.Contains(msg.Title, "1 issue(s)") {
			t.Errorf("title = %q, want it to count the one issue", msg.Title)
		}
		if !strings.Contains(msg.Body, "b.example") {
			t.Errorf("body = %q, want the drifted domain name", msg.Body)
		}
		if strings.Contains(msg.Body, "a.example") {
			t.Errorf("body = %q, must not mention the clean domain", msg.Body)
		}
	})

	t.Run("domain that could not be checked also triggers a notification", func(t *testing.T) {
		failed := []string{"c.example: dns: no such host"}
		msg, ok := driftCheckNotifyMessage(clean, failed, 0, false, "mailhost")
		if !ok {
			t.Fatal("expected ok=true when a domain could not be checked")
		}
		if !strings.Contains(msg.Body, "could not check c.example") {
			t.Errorf("body = %q, want the failed domain surfaced", msg.Body)
		}
	})

	t.Run("drift with heartbeat: still exactly one failure notification, not a heartbeat", func(t *testing.T) {
		msg, ok := driftCheckNotifyMessage(withDrift, nil, 1, true, "mailhost")
		if !ok || msg.Priority != notify.PriorityHigh {
			t.Fatalf("heartbeat flag must not soften a drifted run: msg=%+v ok=%v", msg, ok)
		}
	})
}
