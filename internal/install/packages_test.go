package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

	PolicyRCPath = filepath.Join(dir, "absent")
	created, err := denyServiceStarts()
	if err != nil || !created {
		t.Fatalf("missing file: created=%v err=%v", created, err)
	}
	data, _ := os.ReadFile(PolicyRCPath)
	if !strings.Contains(string(data), "exit 101") || strings.Split(string(data), "\n")[1] != policyMarker {
		t.Fatalf("policy must carry the marker on line 2:\n%s", data)
	}

	// Our own file from an earlier run is taken over and rewritten.
	created, err = denyServiceStarts()
	if err != nil || !created {
		t.Fatalf("own file: created=%v err=%v", created, err)
	}

	foreign := filepath.Join(dir, "foreign")
	if err := os.WriteFile(foreign, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	PolicyRCPath = foreign
	created, err = denyServiceStarts()
	if err != nil || created {
		t.Fatalf("foreign file: created=%v err=%v, want false and nil", created, err)
	}
	after, _ := os.ReadFile(foreign)
	if string(after) != "#!/bin/sh\nexit 0\n" {
		t.Fatalf("foreign policy was modified:\n%s", after)
	}
}
