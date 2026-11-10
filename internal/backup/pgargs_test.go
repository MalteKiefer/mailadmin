package backup

import (
	"os"
	"path/filepath"
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
	got := PgRestoreArgs("mail")
	want := []string{
		RunuserBin, "-u", "postgres", "--",
		PgRestoreBin,
		"--format=custom",
		"--single-transaction",
		"--clean",
		"--if-exists",
		"--dbname=mail",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PgRestoreArgs = %v, want %v", got, want)
	}
}

func TestServiceDBName(t *testing.T) {
	p := filepath.Join(t.TempDir(), "svc.conf")
	_ = os.WriteFile(p, []byte("# x\n[other]\ndbname=nope\n[mail-admin]\ndbname = mail\nuser=mailadmin\n"), 0o600)
	if got, err := ServiceDBName(p, "mail-admin"); err != nil || got != "mail" {
		t.Fatalf("ServiceDBName = %q, %v", got, err)
	}
	if _, err := ServiceDBName(p, "missing"); err == nil {
		t.Fatal("an unknown service must fail")
	}
}
