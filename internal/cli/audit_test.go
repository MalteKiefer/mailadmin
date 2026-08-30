package cli

import (
	"errors"
	"testing"
	"time"
)

func TestAuditFilter(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

	t.Run("no flags is unfiltered, backward compatible", func(t *testing.T) {
		f, limit, err := auditFilter(auditListArgs{lines: 200}, now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if limit != 200 {
			t.Fatalf("limit = %d, want 200", limit)
		}
		if f.Actor != "" || f.Action != "" || f.Target != "" || !f.Since.IsZero() || !f.Until.IsZero() {
			t.Fatalf("expected zero-value filter, got %+v", f)
		}
	})

	t.Run("lines <= 0 is a usage error", func(t *testing.T) {
		_, _, err := auditFilter(auditListArgs{lines: 0}, now)
		if !errors.Is(err, ErrUsage) {
			t.Fatalf("err = %v, want Is ErrUsage", err)
		}
	})

	t.Run("actor/action/target pass through", func(t *testing.T) {
		f, _, err := auditFilter(auditListArgs{
			lines:  50,
			actor:  "admin@example.com",
			action: "mailbox.disable",
			target: "alice@example.com",
		}, now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if f.Actor != "admin@example.com" || f.Action != "mailbox.disable" || f.Target != "alice@example.com" {
			t.Fatalf("filter = %+v, want passthrough of actor/action/target", f)
		}
	})

	t.Run("since accepts h/m/s/d units", func(t *testing.T) {
		for _, since := range []string{"24h", "30m", "45s", "7d"} {
			f, _, err := auditFilter(auditListArgs{lines: 200, since: since}, now)
			if err != nil {
				t.Fatalf("since=%q: unexpected error: %v", since, err)
			}
			if !f.Since.Before(now) {
				t.Fatalf("since=%q: Since = %v, want before %v", since, f.Since, now)
			}
		}
	})

	t.Run("since 7d resolves to exactly 7*24h before now", func(t *testing.T) {
		f, _, err := auditFilter(auditListArgs{lines: 200, since: "7d"}, now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := now.Add(-7 * 24 * time.Hour)
		if !f.Since.Equal(want) {
			t.Fatalf("Since = %v, want %v", f.Since, want)
		}
	})

	t.Run("bad since is a usage error", func(t *testing.T) {
		_, _, err := auditFilter(auditListArgs{lines: 200, since: "not-a-duration"}, now)
		if !errors.Is(err, ErrUsage) {
			t.Fatalf("err = %v, want Is ErrUsage", err)
		}
	})

	t.Run("bad until is a usage error", func(t *testing.T) {
		_, _, err := auditFilter(auditListArgs{lines: 200, until: "3x"}, now)
		if !errors.Is(err, ErrUsage) {
			t.Fatalf("err = %v, want Is ErrUsage", err)
		}
	})

	t.Run("since 7d until 1d is a window between 7 and 1 days ago", func(t *testing.T) {
		f, _, err := auditFilter(auditListArgs{lines: 200, since: "7d", until: "1d"}, now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		wantSince := now.Add(-7 * 24 * time.Hour)
		wantUntil := now.Add(-1 * 24 * time.Hour)
		if !f.Since.Equal(wantSince) || !f.Until.Equal(wantUntil) {
			t.Fatalf("filter = %+v, want since=%v until=%v", f, wantSince, wantUntil)
		}
	})

	t.Run("since further forward than until is a usage error", func(t *testing.T) {
		// --since 1d --until 7d means "since 1 day ago, until 7 days ago" —
		// an inverted, empty window; reject it rather than silently
		// returning nothing.
		_, _, err := auditFilter(auditListArgs{lines: 200, since: "1d", until: "7d"}, now)
		if !errors.Is(err, ErrUsage) {
			t.Fatalf("err = %v, want Is ErrUsage", err)
		}
	})
}

func TestParseDurationAgo(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"30s", 30 * time.Second, false},
		{"5m", 5 * time.Minute, false},
		{"24h", 24 * time.Hour, false},
		{"2d", 48 * time.Hour, false},
		{"0d", 0, false},
		{"", 0, true},
		{"24", 0, true},
		{"24w", 0, true},
		{"-1h", 0, true},
	}
	for _, tt := range tests {
		got, err := parseDurationAgo(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseDurationAgo(%q) = %v, nil; want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDurationAgo(%q): unexpected error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseDurationAgo(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
