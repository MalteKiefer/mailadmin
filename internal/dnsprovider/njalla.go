package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Njalla implements Provider against the Njalla JSON API (https://njal.la/api/1/).
// Auth is an account API token (njal.la -> Settings -> API), sent as
// "Authorization: Njalla <token>".
type Njalla struct {
	token  string
	client *http.Client
}

// NewNjalla builds a client. token must be non-empty.
func NewNjalla(token string) *Njalla {
	return &Njalla{token: token, client: newHTTPClient()}
}

func (*Njalla) Name() string { return "njalla" }

const njallaEndpoint = "https://njal.la/api/1/"

type njallaReq struct {
	Method string `json:"method"`
	Params any    `json:"params"`
}

// rpc performs one JSON call and unmarshals result into out.
func (n *Njalla) rpc(ctx context.Context, method string, params any, out any) error {
	body, _ := json.Marshal(njallaReq{Method: method, Params: params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, njallaEndpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Njalla "+n.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("njalla %s: decode: %w", method, err)
	}
	if env.Error != nil {
		return fmt.Errorf("njalla %s: %d %s", method, env.Error.Code, env.Error.Message)
	}
	if out != nil && len(env.Result) > 0 {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// njallaRecord mirrors the API record shape; id/prio may arrive as number.
type njallaRecord struct {
	ID      json.Number `json:"id"`
	Name    string      `json:"name"`
	Type    string      `json:"type"`
	Content string      `json:"content"`
	TTL     int         `json:"ttl"`
	Prio    *int        `json:"prio"`
	Weight  *int        `json:"weight"`
	Port    *int        `json:"port"`
}

func (nr njallaRecord) toRecord() Record {
	r := Record{ID: nr.ID.String(), Name: normName(nr.Name), Type: nr.Type, Content: nr.Content, TTL: nr.TTL}
	if nr.Prio != nil {
		r.Prio = *nr.Prio
	}
	if nr.Weight != nil {
		r.Weight = *nr.Weight
	}
	if nr.Port != nil {
		r.Port = *nr.Port
	}
	return r
}

func (n *Njalla) ListRecords(ctx context.Context, domain string) ([]Record, error) {
	var res struct {
		Records []njallaRecord `json:"records"`
	}
	if err := n.rpc(ctx, "list-records", map[string]any{"domain": domain}, &res); err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(res.Records))
	for _, nr := range res.Records {
		out = append(out, nr.toRecord())
	}
	return out, nil
}

func (n *Njalla) AddRecord(ctx context.Context, domain string, r Record) error {
	return n.rpc(ctx, "add-record", recordParams(domain, r, false), nil)
}

func (n *Njalla) EditRecord(ctx context.Context, domain string, r Record) error {
	if r.ID == "" {
		return fmt.Errorf("edit-record: missing id")
	}
	return n.rpc(ctx, "edit-record", recordParams(domain, r, true), nil)
}

func (n *Njalla) RemoveRecord(ctx context.Context, domain, id string) error {
	// Njalla expects a numeric id (matches acme.sh dns_njalla.sh).
	var idVal any = id
	if num, err := strconv.Atoi(id); err == nil {
		idVal = num
	}
	return n.rpc(ctx, "remove-record", map[string]any{"domain": domain, "id": idVal}, nil)
}

func recordParams(domain string, r Record, withID bool) map[string]any {
	p := map[string]any{
		"domain":  domain,
		"content": r.Content,
		"ttl":     ttlOr(r.TTL),
	}
	// edit-record identifies the record by id; Njalla rejects type/name on edit
	// (400 Invalid DNS record). Only add-record carries type and name.
	if withID {
		if id, err := strconv.Atoi(r.ID); err == nil {
			p["id"] = id
		} else {
			p["id"] = r.ID
		}
	} else {
		p["type"] = r.Type
		p["name"] = apexToEmpty(r.Name)
	}
	if r.Prio != 0 || r.Type == "MX" || r.Type == "SRV" {
		p["prio"] = r.Prio
	}
	if r.Type == "SRV" {
		p["weight"] = r.Weight
		p["port"] = r.Port
	}
	return p
}

// Njalla represents the apex as an empty name.
func apexToEmpty(n string) string {
	if n == "@" {
		return ""
	}
	return n
}

func ttlOr(t int) int {
	if t <= 0 {
		return 3600
	}
	return t
}

// mtaStsID is a monotonically-increasing policy id (used by DesiredMailRecords).
func mtaStsID() string { return time.Now().UTC().Format("20060102150405") }

// compile-time assertion.
var _ Provider = (*Njalla)(nil)
