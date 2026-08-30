package db

import (
	"testing"
	"time"
)

// These cover the pure, DB-free logic in models.go. Everything else in this
// package requires a live Postgres connection (pgxpool) — see
// integration_test.go (build tag "integration") for CRUD coverage against a
// real database.

func TestMailboxAddress(t *testing.T) {
	cases := []struct {
		name string
		m    Mailbox
		want string
	}{
		{"simple", Mailbox{Username: "alice", Domain: "example.com"}, "alice@example.com"},
		{"empty username", Mailbox{Username: "", Domain: "example.com"}, "@example.com"},
		{"empty domain", Mailbox{Username: "alice", Domain: ""}, "alice@"},
		{"both empty", Mailbox{}, "@"},
		{"dotted local", Mailbox{Username: "first.last", Domain: "sub.example.com"}, "first.last@sub.example.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.m.Address(); got != c.want {
				t.Fatalf("Mailbox.Address() = %q; want %q", got, c.want)
			}
		})
	}
}

func TestAppPasswordAddress(t *testing.T) {
	cases := []struct {
		name string
		a    AppPassword
		want string
	}{
		{"simple", AppPassword{Username: "bob", Domain: "example.com"}, "bob@example.com"},
		{"with label ignored", AppPassword{Username: "bob", Domain: "example.com", Label: "phone"}, "bob@example.com"},
		{"empty username", AppPassword{Username: "", Domain: "example.com"}, "@example.com"},
		{"empty domain", AppPassword{Username: "bob", Domain: ""}, "bob@"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.a.Address(); got != c.want {
				t.Fatalf("AppPassword.Address() = %q; want %q", got, c.want)
			}
		})
	}
}

// TestAppPasswordLastUsedNilable is a light sanity check that LastUsed being a
// pointer (nil = never used) survives zero-value construction, since callers
// throughout internal/cli branch on this being nil.
func TestAppPasswordLastUsedNilable(t *testing.T) {
	var a AppPassword
	if a.LastUsed != nil {
		t.Fatalf("zero-value AppPassword.LastUsed = %v; want nil", a.LastUsed)
	}
	now := time.Now()
	a.LastUsed = &now
	if a.LastUsed == nil || !a.LastUsed.Equal(now) {
		t.Fatalf("AppPassword.LastUsed not set correctly")
	}
}
