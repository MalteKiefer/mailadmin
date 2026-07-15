package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Cloudflare implements Provider against the Cloudflare API v4
// (https://api.cloudflare.com/client/v4). Auth is an API token sent as a Bearer
// header. Records are addressed by Cloudflare's own record id, and names are
// full FQDNs on the wire; this client converts to/from mailadmin's relative
// "@"/label form. Zone ids are looked up once per domain and cached.
type Cloudflare struct {
	token  string
	client *http.Client

	mu    sync.Mutex
	zones map[string]string // domain -> zone id
}

// NewCloudflare builds a client. token must be non-empty.
func NewCloudflare(token string) *Cloudflare {
	return &Cloudflare{token: token, client: newHTTPClient(), zones: map[string]string{}}
}

func (*Cloudflare) Name() string { return "cloudflare" }

const cloudflareBase = "https://api.cloudflare.com/client/v4"

// cfEnvelope is the standard Cloudflare response wrapper.
type cfEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func (e cfEnvelope) err(op string) error {
	if e.Success {
		return nil
	}
	if len(e.Errors) > 0 {
		return fmt.Errorf("cloudflare %s: %d %s", op, e.Errors[0].Code, e.Errors[0].Message)
	}
	return fmt.Errorf("cloudflare %s: request failed", op)
}

// do performs an API call and returns the parsed envelope. body may be nil.
func (c *Cloudflare) do(ctx context.Context, method, path string, body any) (cfEnvelope, error) {
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return cfEnvelope{}, err
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, cloudflareBase+path, rdr)
	if err != nil {
		return cfEnvelope{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return cfEnvelope{}, fmt.Errorf("cloudflare: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var env cfEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return cfEnvelope{}, fmt.Errorf("cloudflare: decode %s: %w", method, err)
	}
	return env, nil
}

// zoneID resolves and caches the zone id for a domain.
func (c *Cloudflare) zoneID(ctx context.Context, domain string) (string, error) {
	c.mu.Lock()
	id, ok := c.zones[domain]
	c.mu.Unlock()
	if ok {
		return id, nil
	}
	env, err := c.do(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(domain), nil)
	if err != nil {
		return "", err
	}
	if err := env.err("zone lookup"); err != nil {
		return "", err
	}
	var zones []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(env.Result, &zones); err != nil {
		return "", fmt.Errorf("cloudflare: decode zones: %w", err)
	}
	if len(zones) == 0 {
		return "", fmt.Errorf("cloudflare: zone %q not found in this account", domain)
	}
	c.mu.Lock()
	c.zones[domain] = zones[0].ID
	c.mu.Unlock()
	return zones[0].ID, nil
}

type cfRecord struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Priority *int   `json:"priority,omitempty"`
	Data     *struct {
		Priority int    `json:"priority"`
		Weight   int    `json:"weight"`
		Port     int    `json:"port"`
		Target   string `json:"target"`
	} `json:"data,omitempty"`
}

func (c *Cloudflare) ListRecords(ctx context.Context, domain string) ([]Record, error) {
	zid, err := c.zoneID(ctx, domain)
	if err != nil {
		return nil, err
	}
	var out []Record
	for page := 1; ; page++ {
		env, err := c.do(ctx, http.MethodGet,
			fmt.Sprintf("/zones/%s/dns_records?per_page=100&page=%d", zid, page), nil)
		if err != nil {
			return nil, err
		}
		if err := env.err("list records"); err != nil {
			return nil, err
		}
		var recs []cfRecord
		if err := json.Unmarshal(env.Result, &recs); err != nil {
			return nil, fmt.Errorf("cloudflare: decode records: %w", err)
		}
		for _, cr := range recs {
			out = append(out, cfToRecord(cr, domain))
		}
		if env.ResultInfo.TotalPages == 0 || page >= env.ResultInfo.TotalPages {
			break
		}
	}
	return out, nil
}

func cfToRecord(cr cfRecord, domain string) Record {
	r := Record{
		ID:      cr.ID,
		Type:    strings.ToUpper(cr.Type),
		Name:    cfRelative(cr.Name, domain),
		Content: cr.Content,
		TTL:     cr.TTL,
	}
	if cr.Priority != nil {
		r.Prio = *cr.Priority
	}
	if r.Type == "SRV" && cr.Data != nil {
		r.Prio = cr.Data.Priority
		r.Weight = cr.Data.Weight
		r.Port = cr.Data.Port
		r.Content = cr.Data.Target
	}
	return r
}

func (c *Cloudflare) AddRecord(ctx context.Context, domain string, r Record) error {
	zid, err := c.zoneID(ctx, domain)
	if err != nil {
		return err
	}
	env, err := c.do(ctx, http.MethodPost, "/zones/"+zid+"/dns_records", cfBody(r, domain))
	if err != nil {
		return err
	}
	return env.err("add record")
}

func (c *Cloudflare) EditRecord(ctx context.Context, domain string, r Record) error {
	if r.ID == "" {
		return fmt.Errorf("cloudflare edit: missing id")
	}
	zid, err := c.zoneID(ctx, domain)
	if err != nil {
		return err
	}
	env, err := c.do(ctx, http.MethodPut, "/zones/"+zid+"/dns_records/"+r.ID, cfBody(r, domain))
	if err != nil {
		return err
	}
	return env.err("edit record")
}

func (c *Cloudflare) RemoveRecord(ctx context.Context, domain, id string) error {
	zid, err := c.zoneID(ctx, domain)
	if err != nil {
		return err
	}
	env, err := c.do(ctx, http.MethodDelete, "/zones/"+zid+"/dns_records/"+id, nil)
	if err != nil {
		return err
	}
	return env.err("remove record")
}

// cfBody builds the create/update JSON body. Cloudflare puts MX priority at the
// top level and nests all SRV fields under "data".
func cfBody(r Record, domain string) map[string]any {
	b := map[string]any{
		"type": strings.ToUpper(r.Type),
		"name": cfFQDN(r.Name, domain),
		"ttl":  ttlOr(r.TTL),
	}
	switch strings.ToUpper(r.Type) {
	case "MX":
		b["content"] = r.Content
		b["priority"] = r.Prio
	case "SRV":
		b["data"] = map[string]any{
			"priority": r.Prio,
			"weight":   r.Weight,
			"port":     r.Port,
			"target":   r.Content,
		}
	default:
		b["content"] = r.Content
	}
	return b
}

// cfFQDN converts a relative name ("@"/label) to the full name Cloudflare wants.
func cfFQDN(name, domain string) string {
	n := strings.TrimSpace(name)
	if n == "" || n == "@" {
		return domain
	}
	return n + "." + domain
}

// cfRelative converts a Cloudflare FQDN back to mailadmin's "@"/label form.
func cfRelative(name, domain string) string {
	n := strings.TrimSuffix(strings.TrimSpace(name), ".")
	if strings.EqualFold(n, domain) {
		return "@"
	}
	if rel, ok := strings.CutSuffix(n, "."+domain); ok {
		return rel
	}
	return n
}

// compile-time assertion.
var _ Provider = (*Cloudflare)(nil)
