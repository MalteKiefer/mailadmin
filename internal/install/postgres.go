package install

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"mailadmin/migrations"
)

// PgDatabase is the mail database, and PgService the libpq service name the
// config references. Both match the documented layout in ARCHITECTURE.md.
const (
	PgDatabase    = "mail"
	PgService     = "mail-admin"
	PgServiceFile = "/var/lib/mailadmin/.pg_service.conf"
)

// PgRoles are the roles that connect to the mail database. mailadmin, postfix
// and dovecot each use their own role, so grants stay separate.
var PgRoles = []string{"mailadmin", "postfix", "dovecot"}

// identRe limits names that are interpolated into SQL and argv to plain
// lowercase identifiers. Every name here is a constant, the check is defence in depth.
var identRe = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

func checkIdent(name string) error {
	if !identRe.MatchString(name) {
		return fmt.Errorf("invalid postgres identifier %q", name)
	}
	return nil
}

// asPostgres runs a command as the postgres OS user, which has peer-auth access
// to the cluster through the unix socket.
func asPostgres(argv ...string) []string {
	return append([]string{"runuser", "-u", "postgres", "--"}, argv...)
}

// psqlScalar runs a query against database db as postgres and returns the
// trimmed single value.
func psqlScalar(ctx context.Context, x Exec, db, query string) (string, error) {
	res, err := x.Run(ctx, nil, asPostgres("psql", "-XtA", "-d", db, "-c", query)...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

// EnsureRole creates a login role when it does not exist.
func EnsureRole(ctx context.Context, x Exec, name string) error {
	if err := checkIdent(name); err != nil {
		return err
	}
	got, err := psqlScalar(ctx, x, "postgres", fmt.Sprintf("SELECT 1 FROM pg_roles WHERE rolname = '%s'", name))
	if err != nil {
		return fmt.Errorf("check role %s: %w", name, err)
	}
	if got == "1" {
		return nil
	}
	if _, err := x.Run(ctx, nil, asPostgres("createuser", "--login", name)...); err != nil {
		return fmt.Errorf("create role %s: %w", name, err)
	}
	return nil
}

// EnsureDatabase creates the mail database owned by owner when it does not exist.
func EnsureDatabase(ctx context.Context, x Exec, name, owner string) error {
	if err := checkIdent(name); err != nil {
		return err
	}
	if err := checkIdent(owner); err != nil {
		return err
	}
	got, err := psqlScalar(ctx, x, "postgres", fmt.Sprintf("SELECT 1 FROM pg_database WHERE datname = '%s'", name))
	if err != nil {
		return fmt.Errorf("check database %s: %w", name, err)
	}
	if got == "1" {
		return nil
	}
	if _, err := x.Run(ctx, nil, asPostgres("createdb", "--owner="+owner, name)...); err != nil {
		return fmt.Errorf("create database %s: %w", name, err)
	}
	return nil
}

// ApplyMigrations applies every migration not yet recorded in schema_migrations.
// Each file runs as its own psql invocation with ON_ERROR_STOP, and its row is
// written right after it, so a failed file stops the run and a re-run resumes.
//
// adopt marks the baseline (001) as applied when the schema already exists, for
// hosts whose database predates this installer. Later migrations still run.
func ApplyMigrations(ctx context.Context, x Exec, adopt bool) error {
	all, err := migrations.All()
	if err != nil {
		return err
	}
	const ddl = "CREATE TABLE IF NOT EXISTS schema_migrations (" +
		"version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
	if _, err := x.Run(ctx, nil, asPostgres("psql", "-XqAt", "-v", "ON_ERROR_STOP=1", "-d", PgDatabase, "-c", ddl)...); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	for _, m := range all {
		applied, err := psqlScalar(ctx, x, PgDatabase, fmt.Sprintf(
			"SELECT 1 FROM schema_migrations WHERE version = '%s'", m.Name))
		if err != nil {
			return fmt.Errorf("check migration %s: %w", m.Name, err)
		}
		if applied == "1" {
			continue
		}
		if adopt && strings.HasPrefix(m.Name, "001_") {
			exists, err := psqlScalar(ctx, x, PgDatabase, "SELECT to_regclass('domain') IS NOT NULL")
			if err != nil {
				return fmt.Errorf("check existing schema: %w", err)
			}
			if exists == "t" {
				if _, err := psqlScalar(ctx, x, PgDatabase, fmt.Sprintf(
					"INSERT INTO schema_migrations (version) VALUES ('%s') RETURNING version", m.Name)); err != nil {
					return fmt.Errorf("record adopted %s: %w", m.Name, err)
				}
				continue
			}
		}
		script := m.SQL + fmt.Sprintf("\nINSERT INTO schema_migrations (version) VALUES ('%s');\n", m.Name)
		if _, err := x.Run(ctx, []byte(script), asPostgres(
			"psql", "-XqA", "-v", "ON_ERROR_STOP=1", "-d", PgDatabase, "-f", "-")...); err != nil {
			return fmt.Errorf("apply migration %s: %w", m.Name, err)
		}
	}
	return nil
}

// PgServiceFileContent is the libpq service entry: peer authentication as the
// mailadmin OS user, so no password is stored anywhere.
func PgServiceFileContent() []byte {
	return []byte(fmt.Sprintf("# Managed by mailadmin install.\n[%s]\ndbname=%s\nuser=mailadmin\n", PgService, PgDatabase))
}

// WritePgServiceFile writes the service file mode 0600, owned by mailadmin. It is
// renamed into place, so a planted symlink at path is replaced and never followed.
func WritePgServiceFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil { // #nosec G301 -- mailadmin state dir
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	return writeAtomicOwned(path, PgServiceFileContent(), 0o600, "mailadmin", "mailadmin")
}

// PeerMapName is the pg_ident map that lets OS user root reach the mailadmin
// role. The mailadmin CLI runs as root, and its service file connects as the
// mailadmin role. Peer authentication needs the OS user to match, so this map
// does the match explicitly, and only for database mail.
const PeerMapName = "mailadmin_root"

// EnablePeerMap adds the root-to-mailadmin ident mapping and a peer rule for the
// mail database at the top of pg_hba.conf, then reloads the cluster config.
// Both edits are idempotent. The files are rewritten in place so the owner and
// mode the distribution set stay as they are.
func EnablePeerMap(ctx context.Context, x Exec) error {
	hbaPath, err := psqlScalar(ctx, x, "postgres", "SHOW hba_file")
	if err != nil {
		return fmt.Errorf("locate pg_hba.conf: %w", err)
	}
	identPath, err := psqlScalar(ctx, x, "postgres", "SHOW ident_file")
	if err != nil {
		return fmt.Errorf("locate pg_ident.conf: %w", err)
	}
	// root for the CLI, mailadmin for the libpq service file (PgServiceFile).
	if err := ensureLine(identPath, fmt.Sprintf("%s root mailadmin", PeerMapName), false); err != nil {
		return err
	}
	if err := ensureLine(identPath, fmt.Sprintf("%s mailadmin mailadmin", PeerMapName), false); err != nil {
		return err
	}
	if err := ensureLine(hbaPath, fmt.Sprintf("local   %s   mailadmin   peer map=%s", PgDatabase, PeerMapName), true); err != nil {
		return err
	}
	if _, err := psqlScalar(ctx, x, "postgres", "SELECT pg_reload_conf()"); err != nil {
		return fmt.Errorf("reload postgres config: %w", err)
	}
	return nil
}

// ensureLine adds line to path unless it is already there. With prepend the line
// goes first, which matters for pg_hba.conf where the first matching rule wins.
func ensureLine(path, line string, prepend bool) error {
	data, err := os.ReadFile(path) // #nosec G304 -- path from SHOW hba_file / ident_file
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if strings.Contains(string(data), line) {
		return nil
	}
	var out string
	if prepend {
		out = line + "\n" + string(data)
	} else {
		out = string(data)
		if !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		out += line + "\n"
	}
	// The file is replaced through a temp file, never truncated in place: a kill or a full
	// disk midway must not leave the live auth file empty. Owner and mode are kept.
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("stat %s: no owner information", path)
	}
	if err := writeAtomicOwned(path, []byte(out), fi.Mode().Perm(), strconv.Itoa(int(st.Uid)), strconv.Itoa(int(st.Gid))); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
