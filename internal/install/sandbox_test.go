package install

import (
	"strings"
	"testing"
)

func TestSandboxDropInsForMailServices(t *testing.T) {
	for _, u := range SandboxedUnits {
		path, content := SandboxDropIn(u)
		if !strings.HasSuffix(path, "/"+u+".service.d/mailadmin-sandbox.conf") {
			t.Fatalf("%s: path %s", u, path)
		}
		for _, want := range []string{"[Service]", "ProtectSystem=full", "NoNewPrivileges=yes", "PrivateTmp=yes"} {
			if !strings.Contains(content, want) {
				t.Fatalf("%s: missing %q", u, want)
			}
		}
		if strings.Contains(content, "ProtectSystem=strict") {
			t.Fatalf("%s: strict would break writes outside ReadWritePaths", u)
		}
	}
}
