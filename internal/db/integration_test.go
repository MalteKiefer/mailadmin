//go:build integration

// Package db integration tests exercise the pgx-based CRUD layer against a
// real PostgreSQL instance. They are excluded from the default `go test ./...`
// run (and therefore from CI unless a job opts in) because they need Docker
// or another reachable Postgres, see the package doc comment above for why.
//
// Run locally with Docker:
//
//	docker run --rm -e POSTGRES_PASSWORD=postgres -p 55432:5432 -d postgres:16
//	TEST_POSTGRES_DSN="postgres://postgres:postgres@localhost:55432/postgres?sslmode=disable" \
//	  go test -tags integration ./internal/db/...
//
// TEST_POSTGRES_DSN must point at a libpq-compatible DSN; the test creates
// and drops its own schema/tables so it is safe to point at a scratch
// database or a throwaway container. If TEST_POSTGRES_DSN is unset the whole
// file's tests are skipped (not failed), so `go test -tags integration ./...`
// is still safe to run in CI without a Postgres service configured.
//
// Schema: there is no schema/migration file in this repo for the base tables
// (only migrations/002_dns_provider.sql, an additive follow-up), the
// production schema lives on the server. The CREATE TABLE statements below
// are reconstructed from the columns db.go/apppw.go actually SELECT/INSERT,
// and are intentionally minimal (no FKs/indexes beyond what the queries need)
// , they exist to validate query correctness, not to be a schema reference.
package db

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const testSchemaDDL = `
CREATE TABLE domain (
	name         text PRIMARY KEY,
	active       boolean NOT NULL DEFAULT true,
	dkim_selector text,
	created_at   timestamptz NOT NULL DEFAULT now(),
	dns_provider text NOT NULL DEFAULT 'manual'
);

CREATE TABLE mailbox (
	username    text NOT NULL,
	domain      text NOT NULL REFERENCES domain(name),
	password    text NOT NULL,
	quota_bytes bigint NOT NULL DEFAULT 0,
	active      boolean NOT NULL DEFAULT true,
	created_at  timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (username, domain)
);

CREATE TABLE alias (
	source      text NOT NULL,
	destination text NOT NULL,
	active      boolean NOT NULL DEFAULT true,
	PRIMARY KEY (source, destination)
);

CREATE TABLE app_password (
	id          serial PRIMARY KEY,
	username    text NOT NULL,
	domain      text NOT NULL,
	label       text NOT NULL,
	password    text NOT NULL,
	active      boolean NOT NULL DEFAULT true,
	created_at  timestamptz NOT NULL DEFAULT now(),
	last_used   timestamptz,
	UNIQUE (username, domain, label)
);

CREATE TABLE audit_log (
	id         bigserial PRIMARY KEY,
	ts         timestamptz NOT NULL DEFAULT now(),
	actor      text NOT NULL,
	action     text NOT NULL,
	target     text NOT NULL,
	before     jsonb,
	after      jsonb,
	ip         inet,
	user_agent text
);
`

// openTestDB connects to TEST_POSTGRES_DSN, creates a fresh, uniquely-named
// schema with the tables above, and returns a *DB pointed at it plus a
// cleanup that drops the schema. Skips the test if TEST_POSTGRES_DSN is
// unset or unreachable.
func openTestDB(t *testing.T) *DB {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping Postgres integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Skipf("cannot connect to TEST_POSTGRES_DSN: %v", err)
	}

	schema := "mailadmin_test_" + time.Now().UTC().Format("20060102150405")
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		conn.Close(ctx)
		t.Fatalf("create schema: %v", err)
	}
	if _, err := conn.Exec(ctx, "SET search_path TO "+schema); err != nil {
		conn.Close(ctx)
		t.Fatalf("set search_path: %v", err)
	}
	if _, err := conn.Exec(ctx, testSchemaDDL); err != nil {
		conn.Close(ctx)
		t.Fatalf("create test schema tables: %v", err)
	}
	conn.Close(ctx)

	// Reopen through the pool with search_path baked into the DSN's options
	// so every pooled connection lands in the test schema.
	pooledDSN := dsn
	if len(pooledDSN) > 0 {
		sep := "?"
		if hasQuery(pooledDSN) {
			sep = "&"
		}
		pooledDSN += sep + "options=-c%20search_path%3D" + schema
	}
	d, err := Open(ctx, pooledDSN)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}

	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ccancel()
		d.Close()
		if conn, err := pgx.Connect(cctx, dsn); err == nil {
			_, _ = conn.Exec(cctx, "DROP SCHEMA "+schema+" CASCADE")
			conn.Close(cctx)
		}
	})

	return d
}

func hasQuery(dsn string) bool {
	for _, c := range dsn {
		if c == '?' {
			return true
		}
	}
	return false
}

func TestDomainCRUDAndUpsert(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	if err := d.CreateDomain(ctx, "example.com", "selector1"); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	got, err := d.GetDomain(ctx, "example.com")
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if got.Name != "example.com" || !got.Active || got.DKIMSelector != "selector1" {
		t.Fatalf("GetDomain returned %+v", got)
	}

	// A second insert for the same domain must fail with ErrExists and leave the row unchanged.
	// The duplicate insert must not overwrite the existing row.
	if err := d.SetDomainActive(ctx, "example.com", false); err != nil {
		t.Fatalf("SetDomainActive: %v", err)
	}
	if err := d.CreateDomain(ctx, "example.com", "selector2"); !errors.Is(err, ErrExists) {
		t.Fatalf("CreateDomain on existing row: want ErrExists, got %v", err)
	}
	got, err = d.GetDomain(ctx, "example.com")
	if err != nil {
		t.Fatalf("GetDomain after upsert: %v", err)
	}
	if got.DKIMSelector != "selector1" {
		t.Fatalf("duplicate insert changed dkim_selector: got %q", got.DKIMSelector)
	}
	if got.Active {
		t.Fatalf("duplicate insert re-activated the domain")
	}

	list, err := d.ListDomains(ctx)
	if err != nil {
		t.Fatalf("ListDomains: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ListDomains returned %d rows; want 1 (no duplicate from upsert)", len(list))
	}

	if err := d.SetDomainDNSProvider(ctx, "example.com", "njalla"); err != nil {
		t.Fatalf("SetDomainDNSProvider: %v", err)
	}
	got, _ = d.GetDomain(ctx, "example.com")
	if got.DNSProvider != "njalla" {
		t.Fatalf("DNSProvider = %q; want njalla", got.DNSProvider)
	}

	if err := d.DeleteDomain(ctx, "example.com"); err != nil {
		t.Fatalf("DeleteDomain: %v", err)
	}
	if _, err := d.GetDomain(ctx, "example.com"); err == nil {
		t.Fatalf("GetDomain after delete: want error, got nil")
	}
}

func TestMailboxCRUDAndUpsert(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	if err := d.CreateDomain(ctx, "example.com", "sel"); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}

	m := Mailbox{Username: "alice", Domain: "example.com", Password: "hash1", QuotaBytes: 1000}
	if err := d.CreateMailbox(ctx, m); err != nil {
		t.Fatalf("CreateMailbox: %v", err)
	}
	got, err := d.GetMailbox(ctx, "alice", "example.com")
	if err != nil {
		t.Fatalf("GetMailbox: %v", err)
	}
	if got.Password != "hash1" || got.QuotaBytes != 1000 || !got.Active {
		t.Fatalf("GetMailbox returned %+v", got)
	}

	// A second insert for the same (username, domain) must fail with ErrExists.
	// The existing row stays as it was.
	if err := d.SetMailboxActive(ctx, "alice", "example.com", false); err != nil {
		t.Fatalf("SetMailboxActive: %v", err)
	}
	m2 := Mailbox{Username: "alice", Domain: "example.com", Password: "hash2", QuotaBytes: 2000}
	if err := d.CreateMailbox(ctx, m2); !errors.Is(err, ErrExists) {
		t.Fatalf("CreateMailbox on existing row: want ErrExists, got %v", err)
	}
	got, err = d.GetMailbox(ctx, "alice", "example.com")
	if err != nil {
		t.Fatalf("GetMailbox after upsert: %v", err)
	}
	if got.Password != "hash1" || got.QuotaBytes != 1000 || got.Active {
		t.Fatalf("duplicate insert changed the mailbox: %+v", got)
	}

	n, err := d.CountMailboxesInDomain(ctx, "example.com")
	if err != nil {
		t.Fatalf("CountMailboxesInDomain: %v", err)
	}
	if n != 1 {
		t.Fatalf("CountMailboxesInDomain = %d; want 1", n)
	}

	if err := d.UpdateMailboxQuota(ctx, "alice", "example.com", 5000); err != nil {
		t.Fatalf("UpdateMailboxQuota: %v", err)
	}
	if err := d.UpdateMailboxPassword(ctx, "alice", "example.com", "hash3"); err != nil {
		t.Fatalf("UpdateMailboxPassword: %v", err)
	}
	got, _ = d.GetMailbox(ctx, "alice", "example.com")
	if got.QuotaBytes != 5000 || got.Password != "hash3" {
		t.Fatalf("update did not apply: %+v", got)
	}

	list, err := d.ListMailboxes(ctx, "example.com")
	if err != nil {
		t.Fatalf("ListMailboxes: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ListMailboxes returned %d; want 1", len(list))
	}

	if err := d.DeleteMailbox(ctx, "alice", "example.com"); err != nil {
		t.Fatalf("DeleteMailbox: %v", err)
	}
	if _, err := d.GetMailbox(ctx, "alice", "example.com"); err == nil {
		t.Fatalf("GetMailbox after delete: want error")
	}
}

// TestAliasDomainScopingLikePattern exercises the `LIKE '%@'||$1 OR
// source='@'||$1` domain filter in ListAliases: it must match both
// user@domain aliases and the @domain catch-all for the given domain, and
// must NOT match a similarly-named domain that merely shares a suffix (e.g.
// filtering "example.com" must not also return aliases on
// "notexample.com", a LIKE '%'||$1 pattern without the leading '@' would
// have that bug).
func TestAliasDomainScopingLikePattern(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	for _, dom := range []string{"example.com", "notexample.com"} {
		if err := d.CreateDomain(ctx, dom, "sel"); err != nil {
			t.Fatalf("CreateDomain(%s): %v", dom, err)
		}
	}

	cases := []struct{ source, dest string }{
		{"user@example.com", "alice@example.com"},
		{"@example.com", "catchall@example.com"},
		{"user@notexample.com", "bob@notexample.com"},
	}
	for _, c := range cases {
		if err := d.CreateAlias(ctx, c.source, c.dest); err != nil {
			t.Fatalf("CreateAlias(%s -> %s): %v", c.source, c.dest, err)
		}
	}

	got, err := d.ListAliases(ctx, "example.com")
	if err != nil {
		t.Fatalf("ListAliases: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListAliases(example.com) returned %d aliases (%+v); want 2 (must not match notexample.com)", len(got), got)
	}
	for _, a := range got {
		if a.Source == "user@notexample.com" {
			t.Fatalf("ListAliases(example.com) leaked alias from notexample.com: %+v", a)
		}
	}

	// Upsert on (source, destination) conflict.
	if err := d.DeleteAlias(ctx, "user@example.com", "alice@example.com"); err != nil {
		t.Fatalf("DeleteAlias: %v", err)
	}
	if err := d.CreateAlias(ctx, "user@example.com", "alice@example.com"); err != nil {
		t.Fatalf("CreateAlias (recreate): %v", err)
	}
	one, err := d.GetAlias(ctx, "user@example.com", "alice@example.com")
	if err != nil {
		t.Fatalf("GetAlias: %v", err)
	}
	if !one.Active {
		t.Fatalf("recreated alias not active: %+v", one)
	}

	if err := d.DeleteAliasesBySource(ctx, "@example.com"); err != nil {
		t.Fatalf("DeleteAliasesBySource: %v", err)
	}
	remaining, err := d.ListAliases(ctx, "example.com")
	if err != nil {
		t.Fatalf("ListAliases after DeleteAliasesBySource: %v", err)
	}
	for _, a := range remaining {
		if a.Source == "@example.com" {
			t.Fatalf("DeleteAliasesBySource did not remove catch-all: %+v", remaining)
		}
	}
}

func TestAppPasswordCRUD(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	if err := d.CreateDomain(ctx, "example.com", "sel"); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if err := d.CreateMailbox(ctx, Mailbox{Username: "alice", Domain: "example.com", Password: "h"}); err != nil {
		t.Fatalf("CreateMailbox: %v", err)
	}

	if err := d.CreateAppPassword(ctx, "alice", "example.com", "phone", "hash1"); err != nil {
		t.Fatalf("CreateAppPassword: %v", err)
	}
	list, err := d.ListAppPasswords(ctx, "alice", "example.com")
	if err != nil {
		t.Fatalf("ListAppPasswords: %v", err)
	}
	if len(list) != 1 || list[0].Label != "phone" || !list[0].Active {
		t.Fatalf("ListAppPasswords returned %+v", list)
	}

	// Upsert on (username, domain, label): re-creating refreshes the hash and
	// re-activates without a duplicate row.
	n, err := d.DeleteAppPassword(ctx, "alice", "example.com", "phone")
	if err != nil {
		t.Fatalf("DeleteAppPassword: %v", err)
	}
	if n != 1 {
		t.Fatalf("DeleteAppPassword rows affected = %d; want 1", n)
	}
	n, err = d.DeleteAppPassword(ctx, "alice", "example.com", "phone")
	if err != nil {
		t.Fatalf("DeleteAppPassword (already gone): %v", err)
	}
	if n != 0 {
		t.Fatalf("DeleteAppPassword rows affected = %d; want 0 for already-deleted row", n)
	}

	if err := d.CreateAppPassword(ctx, "alice", "example.com", "phone", "hash2"); err != nil {
		t.Fatalf("CreateAppPassword (recreate): %v", err)
	}
	if err := d.CreateAppPassword(ctx, "alice", "example.com", "laptop", "hash3"); err != nil {
		t.Fatalf("CreateAppPassword (second label): %v", err)
	}
	list, err = d.ListAppPasswords(ctx, "alice", "example.com")
	if err != nil {
		t.Fatalf("ListAppPasswords: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("ListAppPasswords returned %d; want 2", len(list))
	}

	if err := d.DeleteAppPasswordsByMailbox(ctx, "alice", "example.com"); err != nil {
		t.Fatalf("DeleteAppPasswordsByMailbox: %v", err)
	}
	list, err = d.ListAppPasswords(ctx, "alice", "example.com")
	if err != nil {
		t.Fatalf("ListAppPasswords after mailbox purge: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("ListAppPasswords after DeleteAppPasswordsByMailbox = %d; want 0", len(list))
	}
}

func TestAuditLog(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	before := map[string]string{"active": "true"}
	after := map[string]string{"active": "false"}
	if err := d.Log(ctx, "admin@example.com", "mailbox.disable", "alice@example.com", before, after, "203.0.113.5", "mailadmin-cli/1.0"); err != nil {
		t.Fatalf("Log: %v", err)
	}
	// nil before/after must not be marshaled as the JSON string "null".
	if err := d.Log(ctx, "admin@example.com", "mailbox.add", "bob@example.com", nil, nil, "", ""); err != nil {
		t.Fatalf("Log (nil before/after, no ip): %v", err)
	}

	entries, err := d.ListAudit(ctx, 10, AuditFilter{})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("ListAudit returned %d entries; want 2", len(entries))
	}
	// ORDER BY ts DESC, most recent (mailbox.add) first.
	if entries[0].Action != "mailbox.add" {
		t.Fatalf("ListAudit not ordered ts DESC: %+v", entries)
	}
	if entries[0].Before != nil {
		t.Fatalf("nil before was persisted as non-nil JSON: %q", entries[0].Before)
	}
	if entries[0].IP != "" {
		t.Fatalf("empty ip arg produced non-empty IP: %q", entries[0].IP)
	}

	second := entries[1]
	if second.Action != "mailbox.disable" || second.Target != "alice@example.com" || second.IP != "203.0.113.5" {
		t.Fatalf("audit entry mismatch: %+v", second)
	}

	limited, err := d.ListAudit(ctx, 1, AuditFilter{})
	if err != nil {
		t.Fatalf("ListAudit(limit=1): %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("ListAudit(limit=1) returned %d; want 1", len(limited))
	}

	// limit<=0 defaults to 200 rather than returning everything unbounded or
	// erroring.
	all, err := d.ListAudit(ctx, 0, AuditFilter{})
	if err != nil {
		t.Fatalf("ListAudit(limit=0): %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("ListAudit(limit=0) returned %d; want 2 (default limit not hit)", len(all))
	}

	// ---- filters -----------------------------------------------------
	byActor, err := d.ListAudit(ctx, 10, AuditFilter{Actor: "admin@example.com"})
	if err != nil {
		t.Fatalf("ListAudit(actor): %v", err)
	}
	if len(byActor) != 2 {
		t.Fatalf("ListAudit(actor=admin@example.com) returned %d; want 2", len(byActor))
	}
	if none, err := d.ListAudit(ctx, 10, AuditFilter{Actor: "nobody"}); err != nil {
		t.Fatalf("ListAudit(actor=nobody): %v", err)
	} else if len(none) != 0 {
		t.Fatalf("ListAudit(actor=nobody) returned %d; want 0", len(none))
	}

	byAction, err := d.ListAudit(ctx, 10, AuditFilter{Action: "mailbox.add"})
	if err != nil {
		t.Fatalf("ListAudit(action): %v", err)
	}
	if len(byAction) != 1 || byAction[0].Action != "mailbox.add" {
		t.Fatalf("ListAudit(action=mailbox.add) = %+v; want exactly the mailbox.add entry", byAction)
	}

	// Target matches exactly ("alice@example.com") and, per AuditFilter's
	// doc comment, as an address at a bare-domain target, but here both
	// recorded targets already are full addresses, so a domain-only filter
	// like "example.com" should NOT match them (that suffix rule anchors on
	// '@', it does not substring-match the domain out of an address).
	byTargetExact, err := d.ListAudit(ctx, 10, AuditFilter{Target: "alice@example.com"})
	if err != nil {
		t.Fatalf("ListAudit(target exact): %v", err)
	}
	if len(byTargetExact) != 1 || byTargetExact[0].Target != "alice@example.com" {
		t.Fatalf("ListAudit(target=alice@example.com) = %+v; want exactly one matching entry", byTargetExact)
	}
	if err := d.Log(ctx, "admin@example.com", "domain.note", "example.com", nil, nil, "", ""); err != nil {
		t.Fatalf("Log (domain-target entry): %v", err)
	}
	byTargetDomain, err := d.ListAudit(ctx, 10, AuditFilter{Target: "example.com"})
	if err != nil {
		t.Fatalf("ListAudit(target domain): %v", err)
	}
	if len(byTargetDomain) != 3 {
		t.Fatalf("ListAudit(target=example.com) returned %d; want 3 (bare domain + both @example.com addresses)", len(byTargetDomain))
	}

	future := time.Now().Add(time.Hour)
	if empty, err := d.ListAudit(ctx, 10, AuditFilter{Since: future}); err != nil {
		t.Fatalf("ListAudit(since=future): %v", err)
	} else if len(empty) != 0 {
		t.Fatalf("ListAudit(since=future) returned %d; want 0", len(empty))
	}
	past := time.Now().Add(-time.Hour)
	if all3, err := d.ListAudit(ctx, 10, AuditFilter{Since: past}); err != nil {
		t.Fatalf("ListAudit(since=past): %v", err)
	} else if len(all3) != 3 {
		t.Fatalf("ListAudit(since=past) returned %d; want 3", len(all3))
	}
	if empty, err := d.ListAudit(ctx, 10, AuditFilter{Until: past}); err != nil {
		t.Fatalf("ListAudit(until=past): %v", err)
	} else if len(empty) != 0 {
		t.Fatalf("ListAudit(until=past) returned %d; want 0", len(empty))
	}
}
