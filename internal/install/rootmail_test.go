package install

import (
	"strings"
	"testing"
)

func TestRootAliasConfReplacesOnlyRoot(t *testing.T) {
	in := "# comment\npostmaster: root\nroot: someone@example.org\nmailer-daemon: postmaster\n"
	got := RootAliasConf(in, "sysadmin@kiefer-networks.de")
	if strings.Count(got, "root:") != 1 || !strings.Contains(got, "root: sysadmin@kiefer-networks.de") {
		t.Fatalf("root alias = %q", got)
	}
	if !strings.Contains(got, "postmaster: root") || !strings.Contains(got, "# comment") {
		t.Fatalf("other lines changed: %q", got)
	}
	if RootAliasConf(got, "sysadmin@kiefer-networks.de") != got {
		t.Fatal("not idempotent")
	}
}

func TestAideMailConfSetsMailto(t *testing.T) {
	in := "#MAILTO=root\nREPORT_URL=stdout\n"
	got := AideMailConf(in, "sysadmin@kiefer-networks.de")
	if !strings.Contains(got, "MAILTO=sysadmin@kiefer-networks.de") || strings.Contains(got, "#MAILTO") {
		t.Fatalf("aide conf = %q", got)
	}
	if !strings.Contains(got, "REPORT_URL=stdout") {
		t.Fatalf("other settings dropped: %q", got)
	}
}

func TestUnattendedMailConfRoutesReports(t *testing.T) {
	got := UnattendedMailConf("sysadmin@kiefer-networks.de")
	if !strings.Contains(got, `Unattended-Upgrade::Mail "sysadmin@kiefer-networks.de";`) ||
		!strings.Contains(got, `MailReport "on-change"`) {
		t.Fatalf("unattended conf = %q", got)
	}
}
