package db

import (
	"encoding/json"
	"time"
)

// Domain is a virtual mail domain (table: domain).
type Domain struct {
	Name         string
	Active       bool
	DKIMSelector string
	CreatedAt    time.Time
	// DNSProvider selects the registrar backend for automated DNS management:
	// "manual" (default, no automation) or "njalla". See internal/dnsprovider.
	DNSProvider string
}

// Mailbox is a virtual mailbox (table: mailbox).
type Mailbox struct {
	Username   string
	Domain     string
	Password   string // ARGON2ID hash (doveadm pw)
	QuotaBytes int64
	Active     bool
	CreatedAt  time.Time
}

// Address returns user@domain.
func (m Mailbox) Address() string { return m.Username + "@" + m.Domain }

// Alias maps a source address (or @domain catch-all) to a destination (table: alias).
type Alias struct {
	Source      string
	Destination string
	Active      bool
}

// AppPassword is a per-mailbox application password (table: app_password).
type AppPassword struct {
	ID        int
	Username  string
	Domain    string
	Label     string
	Password  string // hash; write-only from the UI
	Active    bool
	CreatedAt time.Time
	// LastUsed is a schema-only field: nothing in mailadmin or the deployed
	// Dovecot config currently writes it. Dovecot authenticates app passwords
	// directly against Postgres on the mail server (SQL passdb config kept
	// outside this repo), bypassing this CLI entirely, so mailadmin has no
	// path by which it could observe a successful use. It is always nil in
	// practice today. The CLI (internal/cli/mailbox.go, appPasswordList)
	// deliberately does not render this field as if it were live data — see
	// docs/SECURITY-AUDIT.md ("app-password last_used") for the investigation
	// that established this and the closest available workaround. Kept (not
	// dropped via migration) so a future post-auth write mechanism, if one is
	// ever added on the Dovecot side, has somewhere to land without a schema
	// change.
	LastUsed *time.Time
}

// Address returns user@domain for the owning mailbox.
func (a AppPassword) Address() string { return a.Username + "@" + a.Domain }

// AuditEntry is an append-only audit-log row (table: audit_log).
type AuditEntry struct {
	ID        int64
	TS        time.Time
	Actor     string
	Action    string
	Target    string
	Before    json.RawMessage
	After     json.RawMessage
	IP        string // host(ip)::text
	UserAgent string
}
