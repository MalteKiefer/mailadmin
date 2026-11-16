package install

import (
	"strings"
	"testing"
)

const testCommonAuth = "auth\t[success=1 default=ignore]\tpam_unix.so nullok\nauth\trequisite\t\t\tpam_deny.so\n"

func TestPamAuthAddsFaillockAndDropsNullok(t *testing.T) {
	got := PamCommonAuthWithFaillock(testCommonAuth)
	for _, want := range []string{"pam_faillock.so preauth", "pam_faillock.so authfail", "pam_faillock.so authsucc"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "nullok") {
		t.Fatal("nullok accepts empty passwords and must go")
	}
	if PamCommonAuthWithFaillock(got) != got {
		t.Fatal("not idempotent")
	}
}

func TestPamAccountFaillockBeforePamUnix(t *testing.T) {
	in := "account\t[success=1 default=ignore]\tpam_unix.so\naccount\trequisite\t\t\tpam_deny.so\n"
	got := PamCommonAccountWithFaillock(in)
	if strings.Index(got, "pam_faillock.so") > strings.Index(got, "pam_unix.so") {
		t.Fatalf("faillock must come before pam_unix:\n%s", got)
	}
	if PamCommonAccountWithFaillock(got) != got {
		t.Fatal("not idempotent")
	}
}
