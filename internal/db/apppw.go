package db

import "context"

// CreateAppPassword inserts (or refreshes) a per-mailbox application password.
// hash is an ARGON2ID modular-crypt string produced by doveadm; the plaintext
// is never handled here. On a (username, domain, label) conflict the row is
// re-activated and its hash/created_at refreshed, mirroring the legacy CLI.
func (d *DB) CreateAppPassword(ctx context.Context, username, domain, label, hash string) error {
	_, err := d.pool.Exec(ctx,
		`INSERT INTO app_password (username, domain, label, password, active)
		 VALUES ($1, $2, $3, $4, true)
		 ON CONFLICT (username, domain, label) DO UPDATE
		   SET password = EXCLUDED.password, active = true, created_at = now()`,
		username, domain, label, hash)
	return err
}

// DeleteAppPassword removes a single application password by owner + label. It
// reports how many rows were removed so callers can distinguish not-found.
func (d *DB) DeleteAppPassword(ctx context.Context, username, domain, label string) (int64, error) {
	tag, err := d.pool.Exec(ctx,
		`DELETE FROM app_password WHERE username=$1 AND domain=$2 AND label=$3`,
		username, domain, label)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteAppPasswordsByMailbox removes every application password owned by a
// mailbox (used when the mailbox itself is deleted).
func (d *DB) DeleteAppPasswordsByMailbox(ctx context.Context, username, domain string) error {
	_, err := d.pool.Exec(ctx,
		`DELETE FROM app_password WHERE username=$1 AND domain=$2`, username, domain)
	return err
}
