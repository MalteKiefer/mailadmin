package install

import (
	"strings"
	"testing"
)

func TestValkeyDisablesDefaultUserAndKeepsLocalOnly(t *testing.T) {
	c := ValkeyConf("abc123")
	for _, want := range []string{"bind 127.0.0.1 ::1", "user default off", "user rspamd on >abc123", "save \"\"", "protected-mode yes"} {
		if !strings.Contains(c, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(c, "-@dangerous") == false {
		t.Fatal("rspamd user must not get dangerous commands")
	}
}

func TestValkeyPasswordRoundTrip(t *testing.T) {
	if got := ValkeyPasswordFrom(ValkeyConf("deadbeef")); got != "deadbeef" {
		t.Fatalf("password = %q", got)
	}
}

func TestRspamdRedisUsesRspamdUser(t *testing.T) {
	f := RspamdLocalFiles("pw")
	if !strings.Contains(f["redis.conf"], `username = "rspamd"`) || !strings.Contains(f["redis.conf"], `servers = "127.0.0.1:6379"`) {
		t.Fatalf("redis.conf = %s", f["redis.conf"])
	}
	if !strings.Contains(f["greylist.conf"], "use_redis = true") {
		t.Fatal("greylisting must use the state store")
	}
	if !strings.Contains(f["dmarc.conf"], "enabled = true") {
		t.Fatal("inbound DMARC must be enabled")
	}
}

func TestValkeyDropInKeepsLogWritable(t *testing.T) {
	d := ValkeyDropInContent()
	if strings.Contains(d, "ProtectSystem=strict") || !strings.Contains(d, "ProtectSystem=full") {
		t.Fatal("valkey needs ProtectSystem=full so the log directory stays writable")
	}
}
