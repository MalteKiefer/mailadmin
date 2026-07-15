package services

import (
	"errors"
	"testing"
)

// defaultUnits mirrors the locked allowlist the CLI configures.
var defaultUnits = []string{
	"postfix", "dovecot", "rspamd", "caddy", "crowdsec",
	"crowdsec-firewall-bouncer", "clamav-daemon", "postgresql",
	"redis-server", "nftables", "radicale", "php8.4-fpm",
}

func TestParseShow(t *testing.T) {
	tests := []struct {
		name string
		unit string
		out  string
		want Status
	}{
		{
			name: "full",
			unit: "postfix",
			out:  "ActiveState=active\nSubState=running\nUnitFileState=enabled\n",
			want: Status{Unit: "postfix", Active: "active", Sub: "running", Enabled: "enabled"},
		},
		{
			name: "crlf line endings",
			unit: "dovecot",
			out:  "ActiveState=active\r\nSubState=running\r\nUnitFileState=static\r\n",
			want: Status{Unit: "dovecot", Active: "active", Sub: "running", Enabled: "static"},
		},
		{
			name: "inactive dead",
			unit: "clamav-daemon",
			out:  "ActiveState=inactive\nSubState=dead\nUnitFileState=disabled\n",
			want: Status{Unit: "clamav-daemon", Active: "inactive", Sub: "dead", Enabled: "disabled"},
		},
		{
			name: "value contains equals sign",
			unit: "rspamd",
			out:  "ActiveState=active\nSubState=a=b\nUnitFileState=enabled",
			want: Status{Unit: "rspamd", Active: "active", Sub: "a=b", Enabled: "enabled"},
		},
		{
			name: "missing properties leave fields empty",
			unit: "caddy",
			out:  "ActiveState=failed\n",
			want: Status{Unit: "caddy", Active: "failed"},
		},
		{
			name: "unknown and blank lines ignored",
			unit: "nftables",
			out:  "\nLoadState=loaded\nActiveState=active\n\nSubState=exited\nUnitFileState=enabled\n",
			want: Status{Unit: "nftables", Active: "active", Sub: "exited", Enabled: "enabled"},
		},
		{
			name: "empty output",
			unit: "redis-server",
			out:  "",
			want: Status{Unit: "redis-server"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseShow(tt.unit, tt.out)
			if got != tt.want {
				t.Errorf("parseShow(%q, %q) = %+v, want %+v", tt.unit, tt.out, got, tt.want)
			}
		})
	}
}

func TestFirstLine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"single", "boom", "boom"},
		{"leading blank lines", "\n\n  actual error \n", "actual error"},
		{"multiline picks first non-empty", "\nFailed to start postfix.\nSee journal.\n", "Failed to start postfix."},
		{"whitespace only", "   \n\t\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstLine([]byte(tt.in)); got != tt.want {
				t.Errorf("firstLine(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNewFiltersInvalidUnits(t *testing.T) {
	s := New(nil, []string{"postfix", "", "  ", "bad name", "php8.4-fpm", "dovecot"})

	want := map[string]bool{"postfix": true, "php8.4-fpm": true, "dovecot": true}
	for u := range want {
		if !s.Allowed(u) {
			t.Errorf("expected %q to be allowed", u)
		}
	}
	for _, bad := range []string{"", "  ", "bad name"} {
		if s.Allowed(bad) {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
	if got := len(s.units()); got != len(want) {
		t.Errorf("units() len = %d, want %d", got, len(want))
	}
}

func TestAllowedTrimsWhitespace(t *testing.T) {
	s := New(nil, defaultUnits)
	if !s.Allowed(" postfix ") {
		t.Error("Allowed should trim surrounding whitespace")
	}
	if s.Allowed("sshd") {
		t.Error("sshd is not in the allowlist and must be rejected")
	}
}

func TestCheckUnit(t *testing.T) {
	s := New(nil, defaultUnits)

	tests := []struct {
		name    string
		unit    string
		want    string
		wantErr error
	}{
		{"allowed", "postfix", "postfix", nil},
		{"allowed dotted", "php8.4-fpm", "php8.4-fpm", nil},
		{"allowed trims", "  dovecot  ", "dovecot", nil},
		{"not allowed", "sshd", "", ErrUnitNotAllowed},
		{"not allowed wildcard", "*", "", nil}, // invalid unit -> valid.ErrInvalid
		{"empty invalid", "", "", nil},
		{"space invalid", "a b", "", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.checkUnit(tt.unit)
			if got != tt.want {
				t.Errorf("checkUnit(%q) name = %q, want %q", tt.unit, got, tt.want)
			}
			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("checkUnit(%q) err = %v, want Is %v", tt.unit, err, tt.wantErr)
				}
			case tt.want == "" && tt.wantErr == nil:
				// invalid-input cases: must error, and must NOT be ErrUnitNotAllowed
				if err == nil {
					t.Errorf("checkUnit(%q) expected an error", tt.unit)
				}
				if errors.Is(err, ErrUnitNotAllowed) {
					t.Errorf("checkUnit(%q) should fail validation, not allowlist", tt.unit)
				}
			default:
				if err != nil {
					t.Errorf("checkUnit(%q) unexpected err = %v", tt.unit, err)
				}
			}
		})
	}
}

func TestUnitsSorted(t *testing.T) {
	s := New(nil, []string{"rspamd", "caddy", "dovecot", "postfix"})
	got := s.units()
	want := []string{"caddy", "dovecot", "postfix", "rspamd"}
	if len(got) != len(want) {
		t.Fatalf("units() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("units()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
