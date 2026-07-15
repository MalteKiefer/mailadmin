package logs

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestFormatRealtime(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"epoch", "0", "1970-01-01T00:00:00Z"},
		{"whole second", "1000000", "1970-01-01T00:00:01Z"},
		{"known instant", "1700000000000000", "2023-11-14T22:13:20Z"},
		{"sub-second truncated by rfc3339", "1700000000500000", "2023-11-14T22:13:20Z"},
		{"empty", "", ""},
		{"non-numeric passthrough", "not-a-number", "not-a-number"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatRealtime(tt.in); got != tt.want {
				t.Errorf("formatRealtime(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestJSONField(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"string", `"hello"`, "hello"},
		{"empty raw", ``, ""},
		{"empty string", `""`, ""},
		{"byte array", `[104,105]`, "hi"},
		{"invalid", `{"x":1}`, ""},
		{"number is not a field", `123`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := jsonField([]byte(tt.in)); got != tt.want {
				t.Errorf("jsonField(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDecodeLine(t *testing.T) {
	tests := []struct {
		name         string
		raw          string
		fallbackUnit string
		wantOK       bool
		want         Line
	}{
		{
			name:         "full record",
			raw:          `{"__REALTIME_TIMESTAMP":"1700000000000000","_SYSTEMD_UNIT":"postfix.service","MESSAGE":"connect from x"}`,
			fallbackUnit: "postfix",
			wantOK:       true,
			want:         Line{Timestamp: "2023-11-14T22:13:20Z", Unit: "postfix.service", Message: "connect from x"},
		},
		{
			name:         "missing unit uses fallback",
			raw:          `{"__REALTIME_TIMESTAMP":"1700000000000000","MESSAGE":"hi"}`,
			fallbackUnit: "dovecot",
			wantOK:       true,
			want:         Line{Timestamp: "2023-11-14T22:13:20Z", Unit: "dovecot", Message: "hi"},
		},
		{
			name:         "binary message as byte array",
			raw:          `{"__REALTIME_TIMESTAMP":"0","_SYSTEMD_UNIT":"rspamd.service","MESSAGE":[104,105]}`,
			fallbackUnit: "rspamd",
			wantOK:       true,
			want:         Line{Timestamp: "1970-01-01T00:00:00Z", Unit: "rspamd.service", Message: "hi"},
		},
		{
			name:         "blank line skipped",
			raw:          "   ",
			fallbackUnit: "postfix",
			wantOK:       false,
		},
		{
			name:         "malformed json skipped",
			raw:          `{not json`,
			fallbackUnit: "postfix",
			wantOK:       false,
		},
		{
			name:         "leading and trailing whitespace tolerated",
			raw:          "  \t" + `{"__REALTIME_TIMESTAMP":"1000000","MESSAGE":"m"}` + "\r",
			fallbackUnit: "caddy",
			wantOK:       true,
			want:         Line{Timestamp: "1970-01-01T00:00:01Z", Unit: "caddy", Message: "m"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := decodeLine([]byte(tt.raw), tt.fallbackUnit)
			if ok != tt.wantOK {
				t.Fatalf("decodeLine ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if got != tt.want {
				t.Errorf("decodeLine = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseLines(t *testing.T) {
	input := strings.Join([]string{
		`{"__REALTIME_TIMESTAMP":"1000000","_SYSTEMD_UNIT":"postfix.service","MESSAGE":"first"}`,
		``,        // blank line ignored
		`garbage`, // malformed ignored
		`{"__REALTIME_TIMESTAMP":"2000000","_SYSTEMD_UNIT":"postfix.service","MESSAGE":"second"}`,
	}, "\n")

	got, err := parseLines(strings.NewReader(input), "postfix")
	if err != nil {
		t.Fatalf("parseLines: %v", err)
	}
	want := []Line{
		{Timestamp: "1970-01-01T00:00:01Z", Unit: "postfix.service", Message: "first"},
		{Timestamp: "1970-01-01T00:00:02Z", Unit: "postfix.service", Message: "second"},
	}
	if len(got) != len(want) {
		t.Fatalf("parseLines returned %d lines, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseLinesEmpty(t *testing.T) {
	got, err := parseLines(strings.NewReader(""), "postfix")
	if err != nil {
		t.Fatalf("parseLines empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no lines, got %+v", got)
	}
}

func TestAllowed(t *testing.T) {
	r := New(nil, []string{"postfix", "dovecot", "caddy"})
	tests := []struct {
		unit string
		want bool
	}{
		{"postfix", true},
		{"dovecot", true},
		{"caddy", true},
		{"crowdsec", false},
		{"", false},
		{"postfix.service", false}, // exact match only
	}
	for _, tt := range tests {
		if got := r.Allowed(tt.unit); got != tt.want {
			t.Errorf("Allowed(%q) = %v, want %v", tt.unit, got, tt.want)
		}
	}
}

func TestShowRejectsDisallowedUnit(t *testing.T) {
	r := New(nil, []string{"postfix"})
	// nil runner is never reached because the allowlist check fails first.
	_, err := r.Show(context.Background(), "crowdsec", 10)
	if !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("Show error = %v, want ErrNotAllowed", err)
	}
}

func TestTailRejectsDisallowedUnit(t *testing.T) {
	r := New(nil, []string{"postfix"})
	_, err := r.Tail(context.Background(), "sshd")
	if !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("Tail error = %v, want ErrNotAllowed", err)
	}
}

func TestNewEmptyAllowlist(t *testing.T) {
	r := New(nil, nil)
	if r.Allowed("postfix") {
		t.Error("empty allowlist should permit nothing")
	}
}
