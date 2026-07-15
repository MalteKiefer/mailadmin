package security

import (
	"errors"
	"testing"
	"time"
)

func TestParseDecisions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		want    []Decision
		wantErr error
	}{
		{
			name: "single ban with until",
			in: `[{"value":"1.2.3.4","scenario":"crowdsecurity/ssh-bf","type":"ban",
				"duration":"3h59m","origin":"crowdsec","scope":"Ip",
				"until":"2026-07-14T12:00:00Z"}]`,
			want: []Decision{{
				IP: "1.2.3.4", Scenario: "crowdsecurity/ssh-bf", Type: "ban",
				Duration: "3h59m", Origin: "crowdsec",
				Until: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC),
			}},
		},
		{
			name: "expiration fallback when until absent",
			in:   `[{"value":"5.6.7.8","type":"ban","expiration":"2026-07-14T12:00:00.5Z"}]`,
			want: []Decision{{
				IP: "5.6.7.8", Type: "ban",
				Until: time.Date(2026, 7, 14, 12, 0, 0, 500000000, time.UTC),
			}},
		},
		{
			name: "simulated decision dropped",
			in:   `[{"value":"9.9.9.9","type":"ban","simulated":true}]`,
			want: []Decision{},
		},
		{
			name: "empty value dropped",
			in:   `[{"value":"","type":"ban"},{"value":"2.2.2.2","type":"ban"}]`,
			want: []Decision{{IP: "2.2.2.2", Type: "ban"}},
		},
		{
			name: "unparseable timestamp yields zero until",
			in:   `[{"value":"3.3.3.3","type":"ban","until":"not-a-time"}]`,
			want: []Decision{{IP: "3.3.3.3", Type: "ban"}},
		},
		{
			name: "unknown fields ignored",
			in:   `[{"value":"4.4.4.4","type":"ban","country":"DE","as_name":"X","id":42}]`,
			want: []Decision{{IP: "4.4.4.4", Type: "ban"}},
		},
		{name: "null is empty", in: `null`, want: nil},
		{name: "empty is empty", in: ``, want: nil},
		{name: "whitespace only is empty", in: "  \n\t ", want: nil},
		{name: "empty array", in: `[]`, want: []Decision{}},
		{name: "malformed json errors", in: `[{`, wantErr: ErrInvalidResponse},
		{name: "object instead of array errors", in: `{"value":"1.1.1.1"}`, wantErr: ErrInvalidResponse},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseDecisions([]byte(tt.in))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			assertDecisions(t, got, tt.want)
		})
	}
}

func assertDecisions(t *testing.T, got, want []Decision) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d decisions, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].IP != want[i].IP || got[i].Scenario != want[i].Scenario ||
			got[i].Type != want[i].Type || got[i].Duration != want[i].Duration ||
			got[i].Origin != want[i].Origin || !got[i].Until.Equal(want[i].Until) {
			t.Fatalf("decision[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseAllowlist(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		want    []AllowEntry
		wantErr error
	}{
		{
			name: "items with description as comment",
			in:   `{"name":"mailadmin","items":[{"value":"10.0.0.1","description":"office"}]}`,
			want: []AllowEntry{{IP: "10.0.0.1", Comment: "office"}},
		},
		{
			name: "comment field preferred over description",
			in:   `{"items":[{"value":"10.0.0.2","comment":"c","description":"d"}]}`,
			want: []AllowEntry{{IP: "10.0.0.2", Comment: "c"}},
		},
		{
			name: "allowlist_items fallback key",
			in:   `{"allowlist_items":[{"value":"10.0.0.3"}]}`,
			want: []AllowEntry{{IP: "10.0.0.3"}},
		},
		{
			name: "empty value dropped",
			in:   `{"items":[{"value":""},{"value":"10.0.0.4"}]}`,
			want: []AllowEntry{{IP: "10.0.0.4"}},
		},
		{name: "empty items", in: `{"items":[]}`, want: []AllowEntry{}},
		{name: "null is empty", in: `null`, want: nil},
		{name: "empty is empty", in: ``, want: nil},
		{name: "malformed errors", in: `{`, wantErr: ErrInvalidResponse},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseAllowlist([]byte(tt.in))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d entries, want %d: %+v", len(got), len(tt.want), got)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("entry[%d] = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestIsFail2banPong(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want bool
	}{
		{"Server replied: pong\n", true},
		{"pong", true},
		{"PONG", true},
		{"", false},
		{"Failed to access socket path", false},
		{"ERROR   Unable to contact server", false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			if got := isFail2banPong([]byte(tt.in)); got != tt.want {
				t.Fatalf("isFail2banPong(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
