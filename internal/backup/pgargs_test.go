package backup

import (
	"reflect"
	"testing"
)

func TestPgDumpArgs(t *testing.T) {
	got := PgDumpArgs("mail-admin", "/var/lib/mailadmin/backups/x/db.dump")
	want := []string{
		PgDumpBin,
		"--format=custom",
		"--file=/var/lib/mailadmin/backups/x/db.dump",
		"--dbname=service=mail-admin",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PgDumpArgs = %v, want %v", got, want)
	}
	if got[0][0] != '/' {
		t.Fatalf("argv[0] must be an absolute path (sys.Runner requirement): %q", got[0])
	}
}

func TestPgRestoreListArgs(t *testing.T) {
	got := PgRestoreListArgs("/tmp/db.dump")
	want := []string{PgRestoreBin, "--list", "/tmp/db.dump"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PgRestoreListArgs = %v, want %v", got, want)
	}
}

func TestPgRestoreArgs(t *testing.T) {
	got := PgRestoreArgs("mail", "/var/run/postgresql", 5433)
	want := []string{
		RunuserBin, "-u", "postgres", "--",
		PgRestoreBin,
		"--format=custom",
		"--single-transaction",
		"--clean",
		"--if-exists",
		"--dbname=mail",
		"--host=/var/run/postgresql",
		"--port=5433",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PgRestoreArgs = %v, want %v", got, want)
	}
}
