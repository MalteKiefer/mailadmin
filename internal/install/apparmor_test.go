package install

import (
	"strings"
	"testing"
)

func TestInsertProfileRulesAfterOpeningBrace(t *testing.T) {
	src := []byte("# header {\nprofile postfix-x /usr/lib/postfix/sbin/x flags=(complain) {\n  #include <abstractions/base>\n}\n")
	out, err := insertProfileRules(src, []byte("  /etc/machine-id r,\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	want := "flags=(complain) {\n  /etc/machine-id r,\n  #include"
	if !strings.Contains(got, want) {
		t.Fatalf("rules not inside profile block:\n%s", got)
	}
}

func TestInsertProfileRulesNoBrace(t *testing.T) {
	if _, err := insertProfileRules([]byte("no profile here\n"), []byte("x\n")); err == nil {
		t.Fatal("want error when no profile header")
	}
}

func TestOwnMailProfilesEmbedded(t *testing.T) {
	for _, name := range ownMailProfiles {
		data, err := appArmorFS.ReadFile("apparmor/" + name)
		if err != nil || len(data) == 0 {
			t.Fatalf("%s not embedded: %v", name, err)
		}
	}
}
