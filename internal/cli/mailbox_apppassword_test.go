package cli

import (
	"testing"
	"time"

	"mailadmin/internal/db"
)

// TestAppPasswordLastUsedLabelIsHonest guards against the label silently
// drifting back into looking like a real timestamp (e.g. "-" or "").
// See docs/SECURITY-AUDIT.md ("app_password.last_used never populated") for
// why this must never look like live data.
func TestAppPasswordLastUsedLabelIsHonest(t *testing.T) {
	if appPasswordLastUsedLabel == "" || appPasswordLastUsedLabel == "-" {
		t.Fatalf("appPasswordLastUsedLabel = %q; must not look like a real value", appPasswordLastUsedLabel)
	}
}

func TestAppPasswordAge(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name      string
		createdAt time.Time
		want      string
	}{
		{"just created", now, "0d"},
		{"one day old", now.Add(-24 * time.Hour), "1d"},
		{"thirty days old", now.Add(-30 * 24 * time.Hour), "30d"},
		{"clock skew (future createdAt)", now.Add(time.Hour), "0d"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := appPasswordAge(tc.createdAt, now); got != tc.want {
				t.Fatalf("appPasswordAge() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFilterAppPasswordsByAge(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	pws := []db.AppPassword{
		{Label: "new", CreatedAt: now.Add(-1 * time.Hour)},
		{Label: "week-old", CreatedAt: now.Add(-7 * 24 * time.Hour)},
		{Label: "year-old", CreatedAt: now.Add(-365 * 24 * time.Hour)},
	}

	t.Run("zero stale duration returns everything unfiltered", func(t *testing.T) {
		got := filterAppPasswordsByAge(pws, 0, now)
		if len(got) != len(pws) {
			t.Fatalf("got %d passwords, want %d (no filtering)", len(got), len(pws))
		}
	})

	t.Run("filters by age since created_at, not usage", func(t *testing.T) {
		got := filterAppPasswordsByAge(pws, 30*24*time.Hour, now)
		if len(got) != 1 || got[0].Label != "year-old" {
			t.Fatalf("filterAppPasswordsByAge(30d) = %+v, want only [year-old]", got)
		}
	})

	t.Run("boundary is inclusive", func(t *testing.T) {
		got := filterAppPasswordsByAge(pws, 7*24*time.Hour, now)
		if len(got) != 2 {
			t.Fatalf("filterAppPasswordsByAge(7d) = %+v, want [week-old, year-old]", got)
		}
	})
}
