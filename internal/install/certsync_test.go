package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The helper is a shell script embedded in Go. It must parse, and it must renew only
// when the live certificate is near expiry or the domain changed.
func TestCertSyncHelperParsesAndRenewsOnlyWhenDue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.sh")
	if err := os.WriteFile(path, []byte(CertSyncHelper), 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("sh -n: %v\n%s", err, out)
	}
	for _, must := range []string{"-checkend 604800", `"$prev" != "$domain"`, `reason=expiring`, `domainfile=/var/lib/mailadmin/.cert-domain`} {
		if !strings.Contains(CertSyncHelper, must) {
			t.Fatalf("helper lacks %q", must)
		}
	}
}

// Repository mode: the helper must ask mailadmin for the proposal and the status, and
// must keep the staged pair until the record is live.
func TestCertSyncHelperRepoMode(t *testing.T) {
	for _, must := range []string{"dns tlsa-pr", "dns tlsa-status", "repo_mode=1", "case \"$rc\" in"} {
		if !strings.Contains(CertSyncHelper, must) {
			t.Fatalf("helper lacks %q", must)
		}
	}
}
