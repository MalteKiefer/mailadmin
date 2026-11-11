package install

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mailadmin/internal/sys"
)

// probeExec answers every command with a fixed exit code, for the policy probe.
type probeExec struct{ code int }

func (p probeExec) Run(_ context.Context, _ []byte, _ ...string) (sys.Result, error) {
	return sys.Result{ExitCode: p.code}, nil
}

func TestStatusInstalledReadsLastField(t *testing.T) {
	cases := map[string]bool{
		"install ok installed":       true,
		"hold ok installed":          true,
		"install ok half-configured": false,
		"deinstall ok config-files":  false,
		"":                           false,
	}
	for status, want := range cases {
		if got := statusInstalled(status); got != want {
			t.Errorf("statusInstalled(%q) = %v, want %v", status, got, want)
		}
	}
}

func TestDenyServiceStartsOwnsOnlyMarkedFiles(t *testing.T) {
	orig := PolicyRCPath
	t.Cleanup(func() { PolicyRCPath = orig })
	dir := t.TempDir()
	ctx := context.Background()

	PolicyRCPath = filepath.Join(dir, "absent")
	created, err := denyServiceStarts(ctx, probeExec{})
	if err != nil || !created {
		t.Fatalf("missing file: created=%v err=%v", created, err)
	}
	data, _ := os.ReadFile(PolicyRCPath)
	if !strings.Contains(string(data), "exit 101") || strings.Split(string(data), "\n")[1] != policyMarker {
		t.Fatalf("policy must carry the marker on line 2:\n%s", data)
	}

	// Our own file from an earlier run is taken over and rewritten.
	created, err = denyServiceStarts(ctx, probeExec{})
	if err != nil || !created {
		t.Fatalf("own file: created=%v err=%v", created, err)
	}

	foreign := filepath.Join(dir, "foreign")
	if err := os.WriteFile(foreign, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	PolicyRCPath = foreign

	// A foreign policy that lets starts through is refused, and it is not modified.
	if _, err := denyServiceStarts(ctx, probeExec{code: 0}); err == nil {
		t.Fatal("foreign policy that allows starts must be refused")
	}
	// A foreign policy that denies starts is accepted and left alone.
	created, err = denyServiceStarts(ctx, probeExec{code: policyDenied})
	if err != nil || created {
		t.Fatalf("foreign denying policy: created=%v err=%v, want false and nil", created, err)
	}
	after, _ := os.ReadFile(foreign)
	if string(after) != "#!/bin/sh\nexit 0\n" {
		t.Fatalf("foreign policy was modified:\n%s", after)
	}
}

// dns sync needs gh and git; backup.borg needs borgbackup; rclone copies borg repos to B2.
func TestDistroPackagesIncludeGitAndGH(t *testing.T) {
	have := map[string]bool{}
	for _, p := range DistroPackages() {
		have[p] = true
	}
	for _, want := range []string{"git", "gh", "borgbackup", "rclone"} {
		if !have[want] {
			t.Fatalf("%s missing from DistroPackages", want)
		}
	}
}
