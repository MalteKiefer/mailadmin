package security

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// nftRuleset is the top-level shape of `nft -j list ruleset`: a single object
// with an "nftables" array whose members are single-key objects ("rule",
// "table", "chain", "set", …). We only decode "rule" members; everything else
// is ignored via json.RawMessage.
type nftRuleset struct {
	Nftables []nftItem `json:"nftables"`
}

// nftItem is one member of the nftables array. Only the rule variant carries
// the port matches we surface.
type nftItem struct {
	Rule *nftRule `json:"rule"`
}

// nftRule holds a rule's expression list. accept-bearing rules that match a
// tcp/udp destination port are the "open ports".
type nftRule struct {
	Expr []nftExpr `json:"expr"`
}

// nftExpr is one expression in a rule. A rule that opens a port pairs a match
// on (tcp|udp) dport with a verdict; we look for the match expression and,
// conservatively, require the rule to also carry an accept verdict.
type nftExpr struct {
	Match  *nftMatch       `json:"match"`
	Accept json.RawMessage `json:"accept"`
}

// nftMatch is the payload of a match expression: left is what is compared
// (here, a payload reference to a header field such as tcp dport) and RawRight
// is the value, kept raw so a port can be a scalar number or a set/range
// without failing the decode.
type nftMatch struct {
	Left     nftMatchLeft    `json:"left"`
	RawRight json.RawMessage `json:"right"`
}

// nftMatchLeft references either a payload field ({"payload":{"protocol":"tcp",
// "field":"dport"}}) or meta l4proto. We use it to learn the protocol of a
// dport match.
type nftMatchLeft struct {
	Payload *nftPayload `json:"payload"`
}

// nftPayload describes a header field reference such as tcp dport.
type nftPayload struct {
	Protocol string `json:"protocol"` // "tcp" | "udp"
	Field    string `json:"field"`    // "dport" | "sport" | …
}

// parseNftPorts extracts distinct managed open ports from `nft -j list ruleset`.
// It reports (proto, port) for every accept rule that matches a single tcp/udp
// destination port. Port ranges and set references are intentionally skipped:
// mailadmin only ever opens discrete ports via the fw-port helper, so a range
// is not something this tool manages. Duplicates are collapsed.
func parseNftPorts(data []byte) ([]FirewallPort, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty nft output", ErrInvalidResponse)
	}
	var rs nftRuleset
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&rs); err != nil {
		return nil, fmt.Errorf("%w: decode nft ruleset: %v", ErrInvalidResponse, err)
	}
	seen := make(map[FirewallPort]struct{})
	var out []FirewallPort
	for _, item := range rs.Nftables {
		if item.Rule == nil {
			continue
		}
		if !ruleAccepts(item.Rule) {
			continue
		}
		for _, e := range item.Rule.Expr {
			proto, port, ok := dportMatch(e.Match)
			if !ok {
				continue
			}
			fp := FirewallPort{Proto: proto, Port: port}
			if _, dup := seen[fp]; dup {
				continue
			}
			seen[fp] = struct{}{}
			out = append(out, fp)
		}
	}
	return out, nil
}

// ruleAccepts reports whether any expression in the rule is an accept verdict.
// A "drop"/"reject" rule that references a dport is a closed port, not an open
// one, so we must not report it.
func ruleAccepts(r *nftRule) bool {
	for _, e := range r.Expr {
		if e.Accept != nil {
			return true
		}
	}
	return false
}

// dportMatch returns (proto, port, true) when the match expression compares a
// tcp/udp destination port against a single scalar. Anything else (sport,
// ranges, sets, missing payload) returns ok=false.
func dportMatch(m *nftMatch) (string, int, bool) {
	if m == nil || m.Left.Payload == nil {
		return "", 0, false
	}
	p := m.Left.Payload
	if p.Field != "dport" {
		return "", 0, false
	}
	if p.Protocol != "tcp" && p.Protocol != "udp" {
		return "", 0, false
	}
	port, ok := scalarPort(m.RawRight)
	if !ok {
		return "", 0, false
	}
	return p.Protocol, port, true
}

// scalarPort decodes an nft match right-hand side as a single port number.
// nft renders a discrete port as a JSON number; ranges ({"range":[…]}) and set
// references ({"set":[…]}, strings) decode to false so they are skipped.
func scalarPort(raw json.RawMessage) (int, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return 0, false
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, false
	}
	if n < 1 || n > 65535 {
		return 0, false
	}
	return n, true
}
