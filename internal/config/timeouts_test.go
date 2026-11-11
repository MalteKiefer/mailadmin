package config

import (
	"testing"
	"time"
)

func TestTimeoutsDefaults(t *testing.T) {
	var tm Timeouts
	if got := tm.CommandTimeout(); got != DefaultCommandTimeout {
		t.Fatalf("command = %s, want %s", got, DefaultCommandTimeout)
	}
	if got := tm.DBToolTimeout(); got != DefaultDBToolTimeout {
		t.Fatalf("db_tool = %s, want %s", got, DefaultDBToolTimeout)
	}
}

func TestTimeoutsValidate(t *testing.T) {
	ok := Timeouts{Command: "45s", DBTool: "1h"}
	if err := ok.validate(); err != nil {
		t.Fatalf("valid timeouts refused: %v", err)
	}
	if got := ok.DBToolTimeout(); got != time.Hour {
		t.Fatalf("db_tool = %s, want 1h", got)
	}
	for _, bad := range []Timeouts{{Command: "soon"}, {Command: "0s"}, {DBTool: "-1m"}, {DBTool: "3h"}} {
		if err := bad.validate(); err == nil {
			t.Fatalf("%+v must be refused", bad)
		}
	}
}

func TestMailDNSTTLRange(t *testing.T) {
	c := validConfig()
	c.Mail.DNSTTL = 30
	if err := c.Validate(); err == nil {
		t.Fatal("dns_ttl 30 must be refused")
	}
	c.Mail.DNSTTL = 300
	if err := c.Validate(); err != nil {
		t.Fatalf("dns_ttl 300 refused: %v", err)
	}
}
