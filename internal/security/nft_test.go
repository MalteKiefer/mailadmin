package security

import (
	"errors"
	"testing"
)

func TestParseNftPorts(t *testing.T) {
	t.Parallel()

	// A realistic input-chain accept rule matching tcp dport 25.
	ruleTCP25 := `{"rule":{"expr":[
		{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":25}},
		{"accept":null}]}}`
	// udp dport 443 accept.
	ruleUDP443 := `{"rule":{"expr":[
		{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":443}},
		{"accept":null}]}}`
	// A drop rule on tcp dport 23 must NOT be reported as open.
	ruleDrop23 := `{"rule":{"expr":[
		{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":23}},
		{"drop":null}]}}`
	// A range match must be skipped (not a discrete managed port).
	ruleRange := `{"rule":{"expr":[
		{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"range":[8000,8100]}}},
		{"accept":null}]}}`
	// A set reference must be skipped.
	ruleSet := `{"rule":{"expr":[
		{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[22,80]}}},
		{"accept":null}]}}`
	// sport match must be ignored.
	ruleSport := `{"rule":{"expr":[
		{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"sport"}},"right":1234}},
		{"accept":null}]}}`
	// Non-rule members (table/chain/set/meta) are ignored.
	otherMembers := `{"table":{"family":"inet","name":"filter"}},{"chain":{"name":"input"}}`

	tests := []struct {
		name    string
		in      string
		want    []FirewallPort
		wantErr error
	}{
		{
			name: "tcp and udp accepts",
			in:   `{"nftables":[` + otherMembers + `,` + ruleTCP25 + `,` + ruleUDP443 + `]}`,
			want: []FirewallPort{{Proto: "tcp", Port: 25}, {Proto: "udp", Port: 443}},
		},
		{
			name: "drop rule not reported",
			in:   `{"nftables":[` + ruleDrop23 + `,` + ruleTCP25 + `]}`,
			want: []FirewallPort{{Proto: "tcp", Port: 25}},
		},
		{
			name: "range skipped",
			in:   `{"nftables":[` + ruleRange + `]}`,
			want: nil,
		},
		{
			name: "set reference skipped",
			in:   `{"nftables":[` + ruleSet + `]}`,
			want: nil,
		},
		{
			name: "sport ignored",
			in:   `{"nftables":[` + ruleSport + `]}`,
			want: nil,
		},
		{
			name: "duplicates collapsed",
			in:   `{"nftables":[` + ruleTCP25 + `,` + ruleTCP25 + `]}`,
			want: []FirewallPort{{Proto: "tcp", Port: 25}},
		},
		{
			name: "empty ruleset",
			in:   `{"nftables":[]}`,
			want: nil,
		},
		{
			name:    "empty output errors",
			in:      ``,
			wantErr: ErrInvalidResponse,
		},
		{
			name:    "malformed json errors",
			in:      `{"nftables":[`,
			wantErr: ErrInvalidResponse,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseNftPorts([]byte(tt.in))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !equalPorts(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func equalPorts(a, b []FirewallPort) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestScalarPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in       string
		wantPort int
		wantOK   bool
	}{
		{`25`, 25, true},
		{`65535`, 65535, true},
		{`1`, 1, true},
		{`0`, 0, false},
		{`70000`, 0, false},
		{`-1`, 0, false},
		{`{"range":[1,2]}`, 0, false},
		{`{"set":[22]}`, 0, false},
		{`"ssh"`, 0, false},
		{``, 0, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			port, ok := scalarPort([]byte(tt.in))
			if ok != tt.wantOK || (ok && port != tt.wantPort) {
				t.Fatalf("scalarPort(%q) = (%d,%v), want (%d,%v)",
					tt.in, port, ok, tt.wantPort, tt.wantOK)
			}
		})
	}
}
