// Package db is the PostgreSQL data-access layer for the mail-admin backend.
//
// Connection uses libpq service files (PGSERVICEFILE / PG_SERVICE) so that the
// process authenticates to Postgres via the unix socket with peer auth as the
// `mailadmin` role. All statements are parameterized ($1, $2, ...) — lookup
// input (local-parts, domains) is never string-interpolated.
package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps a pgx connection pool.
type DB struct {
	pool *pgxpool.Pool
}

// Open connects using the given libpq DSN or `service=...` string.
func Open(ctx context.Context, dsn string) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgxpool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &DB{pool: pool}, nil
}

// Close releases the pool.
func (d *DB) Close() { d.pool.Close() }

// ---- domains -------------------------------------------------------------

const domainCols = `name, active, COALESCE(dkim_selector, ''), created_at, COALESCE(dns_provider, 'manual')`

func (d *DB) ListDomains(ctx context.Context) ([]Domain, error) {
	rows, err := d.pool.Query(ctx, `SELECT `+domainCols+` FROM domain ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		var x Domain
		if err := rows.Scan(&x.Name, &x.Active, &x.DKIMSelector, &x.CreatedAt, &x.DNSProvider); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (d *DB) GetDomain(ctx context.Context, name string) (Domain, error) {
	var x Domain
	err := d.pool.QueryRow(ctx, `SELECT `+domainCols+` FROM domain WHERE name=$1`, name).
		Scan(&x.Name, &x.Active, &x.DKIMSelector, &x.CreatedAt, &x.DNSProvider)
	return x, err
}

// SetDomainDNSProvider sets the registrar backend for a domain ("manual"|"njalla").
func (d *DB) SetDomainDNSProvider(ctx context.Context, name, provider string) error {
	_, err := d.pool.Exec(ctx, `UPDATE domain SET dns_provider=$1 WHERE name=$2`, provider, name)
	return err
}

func (d *DB) CreateDomain(ctx context.Context, name, selector string) error {
	_, err := d.pool.Exec(ctx,
		`INSERT INTO domain (name, active, dkim_selector) VALUES ($1, true, $2)
		 ON CONFLICT (name) DO UPDATE SET dkim_selector = EXCLUDED.dkim_selector, active = true`,
		name, selector)
	return err
}

func (d *DB) SetDomainActive(ctx context.Context, name string, active bool) error {
	_, err := d.pool.Exec(ctx, `UPDATE domain SET active=$1 WHERE name=$2`, active, name)
	return err
}

func (d *DB) SetDKIMSelector(ctx context.Context, name, selector string) error {
	_, err := d.pool.Exec(ctx, `UPDATE domain SET dkim_selector=$1 WHERE name=$2`, selector, name)
	return err
}

func (d *DB) DeleteDomain(ctx context.Context, name string) error {
	_, err := d.pool.Exec(ctx, `DELETE FROM domain WHERE name=$1`, name)
	return err
}

func (d *DB) CountMailboxesInDomain(ctx context.Context, domain string) (int, error) {
	var n int
	err := d.pool.QueryRow(ctx, `SELECT count(*) FROM mailbox WHERE domain=$1`, domain).Scan(&n)
	return n, err
}

// ---- mailboxes -----------------------------------------------------------

const mailboxCols = `username, domain, quota_bytes, active, created_at`

func scanMailbox(rows pgx.Rows) (Mailbox, error) {
	var m Mailbox
	err := rows.Scan(&m.Username, &m.Domain, &m.QuotaBytes, &m.Active, &m.CreatedAt)
	return m, err
}

func (d *DB) ListMailboxes(ctx context.Context, domain string) ([]Mailbox, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if domain != "" {
		rows, err = d.pool.Query(ctx,
			`SELECT `+mailboxCols+` FROM mailbox WHERE domain=$1 ORDER BY username`, domain)
	} else {
		rows, err = d.pool.Query(ctx,
			`SELECT `+mailboxCols+` FROM mailbox ORDER BY domain, username`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Mailbox
	for rows.Next() {
		m, err := scanMailbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (d *DB) GetMailbox(ctx context.Context, username, domain string) (Mailbox, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT `+mailboxCols+` FROM mailbox WHERE username=$1 AND domain=$2`, username, domain)
	if err != nil {
		return Mailbox{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		return Mailbox{}, pgx.ErrNoRows
	}
	return scanMailbox(rows)
}

func (d *DB) CreateMailbox(ctx context.Context, m Mailbox) error {
	_, err := d.pool.Exec(ctx,
		`INSERT INTO mailbox (username, domain, password, quota_bytes, active)
		 VALUES ($1, $2, $3, $4, true)
		 ON CONFLICT (username, domain) DO UPDATE
		   SET password = EXCLUDED.password, quota_bytes = EXCLUDED.quota_bytes, active = true`,
		m.Username, m.Domain, m.Password, m.QuotaBytes)
	return err
}

func (d *DB) UpdateMailboxPassword(ctx context.Context, username, domain, hash string) error {
	_, err := d.pool.Exec(ctx,
		`UPDATE mailbox SET password=$1 WHERE username=$2 AND domain=$3`, hash, username, domain)
	return err
}

func (d *DB) UpdateMailboxQuota(ctx context.Context, username, domain string, quotaBytes int64) error {
	_, err := d.pool.Exec(ctx,
		`UPDATE mailbox SET quota_bytes=$1 WHERE username=$2 AND domain=$3`, quotaBytes, username, domain)
	return err
}

func (d *DB) SetMailboxActive(ctx context.Context, username, domain string, active bool) error {
	_, err := d.pool.Exec(ctx,
		`UPDATE mailbox SET active=$1 WHERE username=$2 AND domain=$3`, active, username, domain)
	return err
}

func (d *DB) DeleteMailbox(ctx context.Context, username, domain string) error {
	_, err := d.pool.Exec(ctx, `DELETE FROM mailbox WHERE username=$1 AND domain=$2`, username, domain)
	return err
}

// ---- aliases -------------------------------------------------------------

func (d *DB) ListAliases(ctx context.Context, domain string) ([]Alias, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if domain != "" {
		rows, err = d.pool.Query(ctx,
			`SELECT source, destination, active FROM alias
			 WHERE source LIKE '%@'||$1 OR source='@'||$1 ORDER BY source, destination`, domain)
	} else {
		rows, err = d.pool.Query(ctx,
			`SELECT source, destination, active FROM alias ORDER BY source, destination`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alias
	for rows.Next() {
		var a Alias
		if err := rows.Scan(&a.Source, &a.Destination, &a.Active); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (d *DB) GetAlias(ctx context.Context, source, dest string) (Alias, error) {
	var a Alias
	err := d.pool.QueryRow(ctx,
		`SELECT source, destination, active FROM alias WHERE source=$1 AND destination=$2`,
		source, dest).Scan(&a.Source, &a.Destination, &a.Active)
	return a, err
}

func (d *DB) CreateAlias(ctx context.Context, source, dest string) error {
	_, err := d.pool.Exec(ctx,
		`INSERT INTO alias (source, destination, active) VALUES ($1, $2, true)
		 ON CONFLICT (source, destination) DO UPDATE SET active = true`, source, dest)
	return err
}

func (d *DB) DeleteAlias(ctx context.Context, source, dest string) error {
	_, err := d.pool.Exec(ctx, `DELETE FROM alias WHERE source=$1 AND destination=$2`, source, dest)
	return err
}

func (d *DB) DeleteAliasesBySource(ctx context.Context, source string) error {
	_, err := d.pool.Exec(ctx, `DELETE FROM alias WHERE source=$1`, source)
	return err
}

// ---- app passwords -------------------------------------------------------

const appPwCols = `id, username, domain, label, active, created_at, last_used`

func (d *DB) ListAppPasswords(ctx context.Context, username, domain string) ([]AppPassword, error) {
	var (
		rows pgx.Rows
		err  error
	)
	switch {
	case username != "" && domain != "":
		rows, err = d.pool.Query(ctx,
			`SELECT `+appPwCols+` FROM app_password WHERE username=$1 AND domain=$2 ORDER BY created_at DESC`,
			username, domain)
	case domain != "":
		rows, err = d.pool.Query(ctx,
			`SELECT `+appPwCols+` FROM app_password WHERE domain=$1 ORDER BY username, created_at DESC`, domain)
	default:
		rows, err = d.pool.Query(ctx,
			`SELECT `+appPwCols+` FROM app_password ORDER BY domain, username, created_at DESC`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppPassword
	for rows.Next() {
		var a AppPassword
		if err := rows.Scan(&a.ID, &a.Username, &a.Domain, &a.Label, &a.Active, &a.CreatedAt, &a.LastUsed); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (d *DB) GetAppPassword(ctx context.Context, id int) (AppPassword, error) {
	var a AppPassword
	err := d.pool.QueryRow(ctx,
		`SELECT `+appPwCols+` FROM app_password WHERE id=$1`, id).
		Scan(&a.ID, &a.Username, &a.Domain, &a.Label, &a.Active, &a.CreatedAt, &a.LastUsed)
	return a, err
}

// ---- audit log -----------------------------------------------------------

// Log writes an append-only audit entry. before/after may be nil.
func (d *DB) Log(ctx context.Context, actor, action, target string, before, after any, ip, ua string) error {
	bj, _ := json.Marshal(before)
	aj, _ := json.Marshal(after)
	if before == nil {
		bj = nil
	}
	if after == nil {
		aj = nil
	}
	var ipArg any
	if ip != "" {
		ipArg = ip
	}
	_, err := d.pool.Exec(ctx,
		`INSERT INTO audit_log (actor, action, target, before, after, ip, user_agent)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		actor, action, target, bj, aj, ipArg, ua)
	return err
}

func (d *DB) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := d.pool.Query(ctx,
		`SELECT id, ts, actor, action, target, before, after, host(ip)::text, user_agent
		 FROM audit_log ORDER BY ts DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ip *string
		if err := rows.Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.Target, &e.Before, &e.After, &ip, &e.UserAgent); err != nil {
			return nil, err
		}
		if ip != nil {
			e.IP = *ip
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
