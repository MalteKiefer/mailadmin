package backup

import (
	"fmt"
	"os"
	"strings"
)

// Absolute paths to the Postgres client binaries, matching the internal/sys
// convention: argv[0] must be absolute (no PATH lookup, no shell).
const (
	PgDumpBin    = "/usr/bin/pg_dump"
	PgRestoreBin = "/usr/bin/pg_restore"
)

// PgDumpArgs builds the argv for a custom-format dump of the given libpq
// service to outPath, suitable for pg_restore.
//
// Custom format (--format=custom, pg_dump's "-Fc") is chosen over plain SQL
// because it lets `backup restore --dry-run` preview a bundle read-only via
// `pg_restore --list` (a table-of-contents dump) without touching a live
// database, and because pg_restore --clean --if-exists gives a clean,
// idempotent replacement on restore. The tradeoff: a plain-SQL dump would be
// human-diffable with a text tool, which --format=custom is not — if that
// matters more than the dry-run preview and clean restore, switch to
// --format=plain and pg_restore's counterpart to `psql < dump`.
func PgDumpArgs(service, outPath string) []string {
	return []string{PgDumpBin, "--format=custom", "--file=" + outPath, "--dbname=service=" + service}
}

// PgRestoreListArgs builds the argv for a read-only table-of-contents listing
// of a dump file (`pg_restore --list`), used to preview a restore under
// --dry-run without connecting to any database.
func PgRestoreListArgs(dumpPath string) []string {
	return []string{PgRestoreBin, "--list", dumpPath}
}

// RunuserBin runs pg_restore as the postgres superuser: the migrations create
// every table and sequence as postgres, so the mailadmin role cannot drop,
// recreate or re-own them.
const RunuserBin = "/usr/sbin/runuser"

// PgRestoreArgs builds the argv to restore a custom-format dump, read from
// stdin, into database dbname as postgres. --clean --if-exists drops existing
// objects captured in the dump before recreating them, so the restore is a
// clean replacement rather than a merge with whatever is currently live.
// --single-transaction makes it all or nothing: a failure leaves the live
// database as it was instead of half replaced.
func PgRestoreArgs(dbname string) []string {
	return []string{
		RunuserBin, "-u", "postgres", "--",
		PgRestoreBin,
		"--format=custom",
		"--single-transaction",
		"--clean",
		"--if-exists",
		"--dbname=" + dbname,
	}
}

// ServiceDBName returns the dbname of service in a libpq service file.
func ServiceDBName(path, service string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator configured service file
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	in := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			in = line == "["+service+"]"
			continue
		}
		if k, v, ok := strings.Cut(line, "="); in && ok && strings.TrimSpace(k) == "dbname" {
			if v = strings.TrimSpace(v); v != "" {
				return v, nil
			}
		}
	}
	return "", fmt.Errorf("no dbname for service %q in %s", service, path)
}
