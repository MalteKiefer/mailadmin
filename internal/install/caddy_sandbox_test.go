package install

import (
	"strings"
	"testing"
)

func TestCaddySandboxKeepsCertStoreAndOnlyBindCapability(t *testing.T) {
	c := CaddySandboxConf()
	for _, want := range []string{"ProtectSystem=strict", "ReadWritePaths=/var/lib/caddy", "NoNewPrivileges=yes", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE"} {
		if !strings.Contains(c, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(c, "CAP_SYS_ADMIN") {
		t.Fatal("unexpected capability")
	}
}

func TestPgLoggingSQLSetsConnectionLogAndIdleTimeout(t *testing.T) {
	s := strings.Join(PgLoggingSQL(), "\n")
	for _, want := range []string{"log_connections = 'on'", "log_disconnections = 'on'", "idle_session_timeout = '10min'"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q", want)
		}
	}
}
