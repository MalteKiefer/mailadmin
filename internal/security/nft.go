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

// nftItem is one member of the nftables array. Rules carry the port matches;
// named sets carry the ports a rule references as @name.
type nftItem struct {
	Rule *nftRule `json:"rule"`
	Set  *nftSet  `json:"set"`
}

// nftRule holds a rule's expression list. accept-bearing rules that match a
// tcp/udp destination port are the "open ports".
type nftRule struct {
	Family string    `json:"family"`
	Table  string    `json:"table"`
	Expr   []nftExpr `json:"expr"`
}

// nftSet is a named set. install keeps the mail and web ports in the sets
// allowed_tcp and allowed_udp, and the fw-port helper adds and removes elements.
type nftSet struct {
	Family string            `json:"family"`
	Table  string            `json:"table"`
	Name   string            `json:"name"`
	Elem   []json.RawMessage `json:"elem"`
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
// destination port, and for every discrete port in a named set such a rule
// references (@allowed_tcp). Port ranges are skipped: mailadmin only ever opens
// discrete ports via the fw-port helper. Duplicates are collapsed.
func parseNftPorts(data []byte) ([]FirewallPort, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty nft output", ErrInvalidResponse)
	}
	var rs nftRuleset
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&rs); err != nil {
		return nil, fmt.Errorf("%w: decode nft ruleset: %w", ErrInvalidResponse, err)
	}
	sets := make(map[string][]int)
	for _, item := range rs.Nftables {
		if s := item.Set; s != nil {
			for _, e := range s.Elem {
				if port, ok := scalarPort(e); ok {
					sets[setKey(s.Family, s.Table, s.Name)] = append(sets[setKey(s.Family, s.Table, s.Name)], port)
				}
			}
		}
	}
	seen := make(map[FirewallPort]struct{})
	var out []FirewallPort
	add := func(fp FirewallPort) {
		if _, dup := seen[fp]; !dup {
			seen[fp] = struct{}{}
			out = append(out, fp)
		}
	}
	for _, item := range rs.Nftables {
		if item.Rule == nil {
			continue
		}
		if !ruleAccepts(item.Rule) {
			continue
		}
		for _, e := range item.Rule.Expr {
			if proto, port, ok := dportMatch(e.Match); ok {
				add(FirewallPort{Proto: proto, Port: port})
				continue
			}
			if proto, name, ok := dportSetMatch(e.Match); ok {
				for _, port := range sets[setKey(item.Rule.Family, item.Rule.Table, name)] {
					add(FirewallPort{Proto: proto, Port: port})
				}
			}
		}
	}
	return out, nil
}

func setKey(family, table, name string) string { return family + "/" + table + "/" + name }

// dportSetMatch returns (proto, set name, true) when the match compares a
// tcp/udp destination port against a named set reference such as "@allowed_tcp".
func dportSetMatch(m *nftMatch) (string, string, bool) {
	if m == nil || m.Left.Payload == nil || m.Left.Payload.Field != "dport" {
		return "", "", false
	}
	p := m.Left.Payload.Protocol
	if p != "tcp" && p != "udp" {
		return "", "", false
	}
	var ref string
	if err := json.Unmarshal(m.RawRight, &ref); err != nil || len(ref) < 2 || ref[0] != '@' {
		return "", "", false
	}
	return p, ref[1:], true
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
