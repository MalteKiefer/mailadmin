package install

import (
	"strings"
	"testing"
)

func TestDoctorTimerRunsDailyWithNotify(t *testing.T) {
	if !strings.Contains(DoctorTimerContent(), "OnCalendar=*-*-* 07:00:00") {
		t.Fatal("doctor timer must run daily")
	}
	if !strings.Contains(DoctorServiceContent(), "doctor --notify") {
		t.Fatal("doctor service must notify on failure")
	}
}

func TestOnFailureHooksEveryMailService(t *testing.T) {
	for _, want := range []string{"postfix", "dovecot", "rspamd", "caddy", "postgresql", "unbound"} {
		found := false
		for _, u := range AlertedUnits {
			if u == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s has no failure hook", want)
		}
	}
	if !strings.Contains(OnFailureDropIn(), "mailadmin-failure@%N.service") {
		t.Fatal("drop-in must start the failure unit")
	}
}
