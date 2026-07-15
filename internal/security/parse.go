package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// timeLayouts are accepted for CrowdSec expiration timestamps. cscli has
// emitted both RFC3339 and RFC3339Nano across versions; we try the richer one
// first and fall back. An unparseable timestamp is not fatal — the decision is
// still surfaced with a zero Until.
var timeLayouts = []string{time.RFC3339Nano, time.RFC3339}

// cscliDecision mirrors the subset of a CrowdSec decision object emitted by
// `cscli decisions list -o json`. Only fields we surface are decoded; unknown
// fields are ignored so the parser survives cscli version drift.
type cscliDecision struct {
	Value      string `json:"value"`
	Scenario   string `json:"scenario"`
	Type       string `json:"type"`
	Duration   string `json:"duration"`
	Origin     string `json:"origin"`
	Scope      string `json:"scope"`
	Expiration string `json:"expiration"`
	Until      string `json:"until"`
	Simulated  bool   `json:"simulated"`
}

// parseDecisions decodes `cscli decisions list -o json`. The command emits a
// JSON array (or the literal `null` when empty). Simulated decisions are
// dropped — they are not enforced and would mislead an operator reading a ban
// list. A malformed document fails closed.
func parseDecisions(data []byte) ([]Decision, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil, nil
	}
	var raw []cscliDecision
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: decode decisions: %v", ErrInvalidResponse, err)
	}
	out := make([]Decision, 0, len(raw))
	for _, d := range raw {
		if d.Simulated {
			continue
		}
		value := strings.TrimSpace(d.Value)
		if value == "" {
			continue
		}
		out = append(out, Decision{
			IP:       value,
			Scenario: strings.TrimSpace(d.Scenario),
			Type:     strings.TrimSpace(d.Type),
			Duration: strings.TrimSpace(d.Duration),
			Until:    parseExpiration(d),
			Origin:   strings.TrimSpace(d.Origin),
		})
	}
	return out, nil
}

// parseExpiration picks the best available absolute expiry from a decision,
// preferring the explicit until field and falling back to expiration. An
// unparseable value yields the zero time rather than an error.
func parseExpiration(d cscliDecision) time.Time {
	for _, s := range []string{d.Until, d.Expiration} {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		for _, layout := range timeLayouts {
			if t, err := time.Parse(layout, s); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}

// cscliAllowlist mirrors the subset of `cscli allowlists inspect <name> -o json`
// we consume. cscli has shipped the entry array under both "items" and
// "allowlist_items"; both are decoded and merged.
type cscliAllowlist struct {
	Items          []cscliAllowlistItem `json:"items"`
	AllowlistItems []cscliAllowlistItem `json:"allowlist_items"`
}

// cscliAllowlistItem is one allowlist entry. Both "value" and "description"
// have appeared as the entry/comment field across versions.
type cscliAllowlistItem struct {
	Value       string `json:"value"`
	Description string `json:"description"`
	Comment     string `json:"comment"`
}

// parseAllowlist decodes `cscli allowlists inspect -o json`. The document is a
// single object with an items array (or `null`/empty for an unpopulated list).
func parseAllowlist(data []byte) ([]AllowEntry, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil, nil
	}
	var doc cscliAllowlist
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: decode allowlist: %v", ErrInvalidResponse, err)
	}
	items := doc.Items
	if len(items) == 0 {
		items = doc.AllowlistItems
	}
	out := make([]AllowEntry, 0, len(items))
	for _, it := range items {
		value := strings.TrimSpace(it.Value)
		if value == "" {
			continue
		}
		comment := strings.TrimSpace(it.Comment)
		if comment == "" {
			comment = strings.TrimSpace(it.Description)
		}
		out = append(out, AllowEntry{IP: value, Comment: comment})
	}
	return out, nil
}

// isFail2banPong reports whether fail2ban-client's ping reply indicates a live
// server. fail2ban answers "Server replied: pong" on success.
func isFail2banPong(stdout []byte) bool {
	return strings.Contains(strings.ToLower(string(stdout)), "pong")
}
