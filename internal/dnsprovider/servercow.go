package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Servercow implements Provider against the Servercow DNS API v1
// (https://api.servercow.de/dns/v1). It authenticates with per-request
// X-Auth-Username / X-Auth-Password headers.
//
// The API is RRset-oriented and has no per-record ids: a POST replaces the whole
// value set for a (name, type), and a DELETE removes it. This client therefore
// synthesises a record id (see rrID) and implements add/edit/remove as
// read-modify-write over the (name, type) set. Names are host-relative with the
// apex represented as "". Servercow returns HTTP 200 even on failure, so the
// body's "error" field is always checked.
type Servercow struct {
	user, pass string
	client     *http.Client
}

// NewServercow builds a client. user and pass are the DNS-API credentials.
func NewServercow(user, pass string) *Servercow {
	return &Servercow{user: user, pass: pass, client: newHTTPClient()}
}

func (*Servercow) Name() string { return "servercow" }

const servercowBase = "https://api.servercow.de/dns/v1/domains/"

// scContent unmarshals Servercow's content, which is a string for single-valued
// records and an array for multi-valued ones (e.g. several TXT).
type scContent []string

func (c *scContent) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*c = scContent{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	*c = arr
	return nil
}

type servercowRec struct {
	Name    string    `json:"name"`
	Type    string    `json:"type"`
	TTL     int       `json:"ttl"`
	Content scContent `json:"content"`
}

// do performs a request. On GET, out (a *[]servercowRec) receives the record
// list; on POST/DELETE the status body is checked for an error.
func (s *Servercow) do(ctx context.Context, method, domain string, body, out any) error {
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, servercowBase+domain, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("X-Auth-Username", s.user)
	req.Header.Set("X-Auth-Password", s.pass)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("servercow: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("servercow: decode: %w", err)
		}
		return nil
	}
	// POST/DELETE: the API returns 200 even on error, so inspect the body.
	var status struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return fmt.Errorf("servercow: decode status: %w", err)
	}
	if status.Error != "" {
		return fmt.Errorf("servercow: %s", status.Error)
	}
	return nil
}

func (s *Servercow) ListRecords(ctx context.Context, domain string) ([]Record, error) {
	var recs []servercowRec
	if err := s.do(ctx, http.MethodGet, domain, nil, &recs); err != nil {
		return nil, err
	}
	var out []Record
	for _, sr := range recs {
		name := sr.Name
		if name == "" {
			name = "@"
		}
		for _, v := range sr.Content {
			r := Record{Type: strings.ToUpper(sr.Type), Name: name, TTL: sr.TTL, ID: rrID(sr.Name, sr.Type, v)}
			rrsetParse(&r, v)
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *Servercow) AddRecord(ctx context.Context, domain string, r Record) error {
	return s.writeSet(ctx, domain, servercowName(r.Name), r.Type, ttlOr(r.TTL), "", servercowValue(r))
}

func (s *Servercow) EditRecord(ctx context.Context, domain string, r Record) error {
	slot, typ, oldVal, ok := parseRRID(r.ID)
	if !ok {
		return fmt.Errorf("servercow edit: bad record id")
	}
	if !strings.EqualFold(typ, r.Type) {
		return fmt.Errorf("servercow edit: id/type mismatch")
	}
	return s.writeSet(ctx, domain, slot, r.Type, ttlOr(r.TTL), oldVal, servercowValue(r))
}

func (s *Servercow) RemoveRecord(ctx context.Context, domain, id string) error {
	slot, typ, val, ok := parseRRID(id)
	if !ok {
		return fmt.Errorf("servercow remove: bad record id")
	}
	return s.writeSet(ctx, domain, slot, typ, 0, val, "")
}

// writeSet reads the current (slot,type) value set, applies the change (remove
// oldVal, add newVal), and writes it back: POST with the remaining values, or
// DELETE when the set becomes empty.
func (s *Servercow) writeSet(ctx context.Context, domain, slot, typ string, ttl int, oldVal, newVal string) error {
	var recs []servercowRec
	if err := s.do(ctx, http.MethodGet, domain, nil, &recs); err != nil {
		return err
	}
	var values []string
	curTTL := ttl
	for _, sr := range recs {
		if sr.Name == slot && strings.EqualFold(sr.Type, typ) {
			values = append(values, sr.Content...)
			if sr.TTL > 0 {
				curTTL = sr.TTL
			}
		}
	}
	if oldVal != "" {
		values = removeValue(values, oldVal)
	}
	if newVal != "" && !containsValue(values, newVal) {
		values = append(values, newVal)
	}
	if len(values) == 0 {
		return s.do(ctx, http.MethodDelete, domain,
			map[string]any{"type": strings.ToUpper(typ), "name": slot}, nil)
	}
	body := map[string]any{
		"type":    strings.ToUpper(typ),
		"name":    slot,
		"ttl":     ttlOr(curTTL),
		"content": servercowContent(values),
	}
	return s.do(ctx, http.MethodPost, domain, body, nil)
}

// servercowContent sends a single value as a string and multiple as an array,
// matching how the API stores single- vs multi-valued records.
func servercowContent(values []string) any {
	if len(values) == 1 {
		return values[0]
	}
	return values
}

// servercowValue renders a Record as a Servercow content value. Unlike PowerDNS,
// Servercow stores raw (unquoted) TXT and has no priority field, so MX/SRV pack
// the priority into the content string.
func servercowValue(r Record) string {
	switch strings.ToUpper(r.Type) {
	case "MX":
		return fmt.Sprintf("%d %s", r.Prio, strings.TrimSuffix(r.Content, "."))
	case "SRV":
		return fmt.Sprintf("%d %d %d %s", r.Prio, r.Weight, r.Port, strings.TrimSuffix(r.Content, "."))
	default:
		return r.Content
	}
}

// servercowName maps mailadmin's apex "@" to the empty label Servercow expects.
func servercowName(name string) string {
	n := strings.TrimSpace(name)
	if n == "@" {
		return ""
	}
	return n
}

// compile-time assertion.
var _ Provider = (*Servercow)(nil)
