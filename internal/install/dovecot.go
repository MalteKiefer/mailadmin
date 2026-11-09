package install

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// CheckDovecotVersion refuses to continue unless the archive offers dovecot-core
// 2.4 or newer. mailadmin writes the 2.4 configuration syntax, which 2.3 rejects.
// It needs the package index, so call it after AptUpdate.
func CheckDovecotVersion(ctx context.Context, x Exec) error {
	res, err := x.Run(ctx, nil, "apt-cache", "policy", "dovecot-core")
	if err != nil {
		return fmt.Errorf("apt-cache policy dovecot-core: %w", err)
	}
	cand := candidateVersion(string(res.Stdout))
	if cand == "" {
		return fmt.Errorf("dovecot-core has no installable candidate in the archive")
	}
	if !dovecot24OrNewer(cand) {
		return fmt.Errorf("dovecot-core candidate %s is older than 2.4, which mailadmin requires", cand)
	}
	return nil
}

// candidateVersion extracts the Candidate version from apt-cache policy output.
func candidateVersion(policy string) string {
	for _, line := range strings.Split(policy, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Candidate:"); ok {
			v = strings.TrimSpace(v)
			if v == "(none)" {
				return ""
			}
			return v
		}
	}
	return ""
}

var dovecotVersionRe = regexp.MustCompile(`^(?:\d+:)?(\d+)\.(\d+)`)

func dovecot24OrNewer(v string) bool {
	m := dovecotVersionRe.FindStringSubmatch(v)
	if m == nil {
		return false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return major > 2 || (major == 2 && minor >= 4)
}
