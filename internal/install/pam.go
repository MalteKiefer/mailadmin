package install

import "strings"

// PAM paths and the faillock config mailadmin owns.
const (
	PamCommonAuthPath    = "/etc/pam.d/common-auth"
	PamCommonAccountPath = "/etc/pam.d/common-account"
	FaillockConfPath     = "/etc/security/faillock.conf"
)

// FaillockConf locks an account for 15 minutes after 5 failed logins. root is
// not locked out, so the console stays usable.
func FaillockConf() string {
	return "# Managed by mailadmin install. Lock an account after 5 failed logins for 15 min.\n" +
		"# root is not locked out, so the console stays usable.\n" +
		"deny = 5\nfail_interval = 900\nunlock_time = 900\n"
}

// PamCommonAuthWithFaillock wraps the pam_unix line of the auth stack with the
// faillock hooks and drops nullok, which would accept empty passwords. Existing
// faillock lines are removed first, so the result is stable on every run.
func PamCommonAuthWithFaillock(existing string) string {
	var out []string
	for _, l := range strings.Split(strings.TrimRight(existing, "\n"), "\n") {
		if strings.Contains(l, "pam_faillock.so") {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(l), "auth") && strings.Contains(l, "pam_unix.so") {
			out = append(out,
				"auth\trequired\t\t\tpam_faillock.so preauth",
				strings.Replace(l, " nullok", "", 1),
				"auth\t[default=die]\t\t\tpam_faillock.so authfail",
				"auth\tsufficient\t\t\tpam_faillock.so authsucc")
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n") + "\n"
}

// PamCommonAccountWithFaillock puts the faillock account check in front of
// pam_unix. Existing faillock lines are removed first.
func PamCommonAccountWithFaillock(existing string) string {
	var out []string
	inserted := false
	for _, l := range strings.Split(strings.TrimRight(existing, "\n"), "\n") {
		if strings.Contains(l, "pam_faillock.so") {
			continue
		}
		if !inserted && strings.HasPrefix(strings.TrimSpace(l), "account") && strings.Contains(l, "pam_unix.so") {
			out = append(out, "account\trequired\t\t\tpam_faillock.so")
			inserted = true
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n") + "\n"
}
