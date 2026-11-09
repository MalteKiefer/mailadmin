package install

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestNftTableStartsWithDestroy(t *testing.T) {
	got := NftTableFile(DefaultTCPPorts, nil, []int{22})
	if !strings.HasPrefix(got, "destroy table inet mailadmin\n") || !strings.Contains(got, "\ntable inet mailadmin {") {
		t.Fatalf("nft table must start with destroy so a reload replaces it:\n%s", got)
	}
	if !strings.Contains(FwPortHelper, "echo 'destroy table inet mailadmin'") {
		t.Fatal("fw-port helper must write the destroy line into the persisted table")
	}
}

func TestWriteManagedKeepsOrigOnlyForForeignFiles(t *testing.T) {
	dir := t.TempDir()

	foreign := filepath.Join(dir, "distro.cf")
	if err := os.WriteFile(foreign, []byte("distribution default\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeManaged(foreign, []byte("# Managed by mailadmin install.\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(foreign + ".mailadmin-orig"); err != nil {
		t.Fatalf("distribution file must be kept as orig: %v", err)
	}

	managed := filepath.Join(dir, "managed.cf")
	if err := writeManaged(managed, []byte("# Managed by mailadmin install.\nv1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := writeManaged(managed, []byte("# Managed by mailadmin install.\nv2\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(managed + ".mailadmin-orig"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a file with the marker must not get an orig backup, stat err: %v", err)
	}
}

func TestWriteAtomicOwnedAcceptsNumericOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned.map")
	uid, gid := strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())
	if err := writeAtomicOwned(path, []byte("x\n"), 0o640, uid, gid); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode %o, want 640", info.Mode().Perm())
	}
}

func TestRefuseSymlinkNamesThePath(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := refuseSymlink(link); err == nil || !strings.Contains(err.Error(), link) {
		t.Fatalf("symlink must be refused with its path in the error, got %v", err)
	}
	if err := refuseSymlink(dir); err != nil {
		t.Fatalf("plain directory refused: %v", err)
	}
}

func TestCertSyncPassesDomainAndValidatesIt(t *testing.T) {
	service, _ := CertSyncUnits("mx.example.com", "example.com")
	if !strings.Contains(service, CertSyncHelperPath+" mx.example.com example.com") {
		t.Fatalf("cert sync unit must pass host and domain:\n%s", service)
	}
	if !strings.Contains(CertSyncHelper, `echo "bad domain"`) {
		t.Fatal("cert sync helper must validate the domain")
	}
	if !strings.Contains(CertSyncHelper, "dns publish") || !strings.Contains(CertSyncHelper, "since") {
		t.Fatal("cert sync helper must use the two-phase DANE swap")
	}
}

func TestNftTableDropsInputAndKeepsSSH(t *testing.T) {
	got := NftTableFile(DefaultTCPPorts, nil, []int{22, 2222})
	for _, want := range []string{"policy drop", "tcp dport { 22, 2222 } accept", "tcp dport @allowed_tcp accept", "25, 80, 443, 465, 587, 993"} {
		if !strings.Contains(got, want) {
			t.Fatalf("nft table missing %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "ipv6-icmp") {
		t.Fatal("ICMPv6 must stay open or IPv6 neighbour discovery breaks")
	}
}

func TestCaddyfileTLSInternalOnlyWhenRequested(t *testing.T) {
	if strings.Contains(CaddyfileMain("mx.example.com", false), "local_certs") {
		t.Fatal("acme mode must not enable local certs")
	}
	if !strings.Contains(CaddyfileMain("mx.example.com", true), "local_certs") {
		t.Fatal("internal mode must use the local CA for every site")
	}
}

func TestPostfixMapsNeverContainPasswords(t *testing.T) {
	for path, body := range PostfixPgsqlMaps() {
		if strings.Contains(strings.ToLower(body), "password") && !strings.Contains(body, "active") {
			t.Fatalf("%s selects password-like data without the active filter", path)
		}
		if !strings.Contains(body, "user = postfix") {
			t.Fatalf("%s must connect as the postfix role, not a password login", path)
		}
	}
}

func TestDovecotConfHasNoSystemPassdb(t *testing.T) {
	c := DovecotConf()
	if strings.Contains(c, "auth-system") || strings.Contains(c, "passwd") {
		t.Fatal("dovecot must not authenticate system accounts")
	}
	if !strings.Contains(c, "passdb mailbox {") {
		t.Fatal("dovecot must authenticate against the mailbox table")
	}
}

func TestHelpersRejectBadArguments(t *testing.T) {
	if !strings.Contains(FwPortHelper, `*[!0-9]*) echo "bad port"`) {
		t.Fatal("fw-port helper must reject non-numeric ports")
	}
	if !strings.Contains(DKIMGenHelper, `*[!a-z0-9.-]*`) {
		t.Fatal("dkim helper must validate the domain")
	}
	if !strings.Contains(CertSyncHelper, `*[!a-z0-9.-]*`) {
		t.Fatal("cert helper must validate the host")
	}
}

func TestNftEmptySetHasNoElementsLine(t *testing.T) {
	got := NftTableFile(DefaultTCPPorts, nil, []int{22})
	if strings.Contains(got, "elements = {  }") || strings.Contains(got, "elements = { }") {
		t.Fatalf("empty set rendered an elements line:\n%s", got)
	}
}
