package install

import "testing"

func TestDovecot24OrNewer(t *testing.T) {
	cases := map[string]bool{
		"2.4.1-3":      true,
		"1:2.4.0+x":    true,
		"3.0.0-1":      true,
		"2.3.19.1-2":   false,
		"2.3.16+dfsg1": false,
		"":             false,
	}
	for v, want := range cases {
		if got := dovecot24OrNewer(v); got != want {
			t.Errorf("dovecot24OrNewer(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestCandidateVersion(t *testing.T) {
	policy := "dovecot-core:\n  Installed: (none)\n  Candidate: 2.4.1-3\n  Version table:\n"
	if got := candidateVersion(policy); got != "2.4.1-3" {
		t.Fatalf("candidateVersion = %q", got)
	}
	if got := candidateVersion("dovecot-core:\n  Candidate: (none)\n"); got != "" {
		t.Fatalf("candidate (none) must be empty, got %q", got)
	}
}
