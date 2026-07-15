package dnsprovider

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 TOTP mandates HMAC-SHA1; not used for data integrity
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"strings"
	"sync"
	"time"
)

// INWX implements Provider against the INWX DomRobot JSON-RPC API
// (https://api.domrobot.com/jsonrpc/). Auth is session-based: account.login
// establishes a session cookie (held in a cookie jar), and account.unlock
// completes TOTP two-factor when the account requires it (INWX_SHARED_SECRET is
// the base32 TOTP seed). Records carry INWX ids; names are relative to the
// domain with the apex represented as "".
type INWX struct {
	user, pass, sharedSecret string
	client                   *http.Client

	mu       sync.Mutex
	loggedIn bool
}

// NewINWX builds a client. sharedSecret is the base32 TOTP seed and may be empty
// when the account has no two-factor authentication.
func NewINWX(user, pass, sharedSecret string) *INWX {
	c := newHTTPClient()
	jar, _ := cookiejar.New(nil)
	c.Jar = jar
	return &INWX{user: user, pass: pass, sharedSecret: sharedSecret, client: c}
}

func (*INWX) Name() string { return "inwx" }

const inwxEndpoint = "https://api.domrobot.com/jsonrpc/"

// inwxResponse is the DomRobot envelope (not JSON-RPC 2.0: code/msg/resData).
type inwxResponse struct {
	Code    int             `json:"code"`
	Msg     string          `json:"msg"`
	ResData json.RawMessage `json:"resData"`
}

// call performs one JSON-RPC method. out (non-nil) receives resData.
func (n *INWX) call(ctx context.Context, method string, params map[string]any, out any) error {
	body, err := json.Marshal(map[string]any{"method": method, "params": params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, inwxEndpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("inwx: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var env inwxResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("inwx %s: decode: %w", method, err)
	}
	if env.Code != 1000 {
		return fmt.Errorf("inwx %s: %d %s", method, env.Code, env.Msg)
	}
	if out != nil && len(env.ResData) > 0 {
		return json.Unmarshal(env.ResData, out)
	}
	return nil
}

// login establishes a session (once), completing TOTP 2FA when required.
func (n *INWX) login(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.loggedIn {
		return nil
	}
	var res struct {
		TFA string `json:"tfa"`
	}
	if err := n.call(ctx, "account.login",
		map[string]any{"user": n.user, "pass": n.pass, "lang": "en"}, &res); err != nil {
		return err
	}
	if res.TFA != "" && res.TFA != "0" {
		if n.sharedSecret == "" {
			return fmt.Errorf("inwx: account requires 2FA but INWX_SHARED_SECRET is not set")
		}
		tan, err := totp(n.sharedSecret, time.Now())
		if err != nil {
			return fmt.Errorf("inwx: compute TOTP: %w", err)
		}
		if err := n.call(ctx, "account.unlock", map[string]any{"tan": tan}, nil); err != nil {
			return err
		}
	}
	n.loggedIn = true
	return nil
}

type inwxRecord struct {
	ID      json.Number `json:"id"`
	Name    string      `json:"name"`
	Type    string      `json:"type"`
	Content string      `json:"content"`
	TTL     int         `json:"ttl"`
	Prio    int         `json:"prio"`
}

func (n *INWX) ListRecords(ctx context.Context, domain string) ([]Record, error) {
	if err := n.login(ctx); err != nil {
		return nil, err
	}
	var res struct {
		Record []inwxRecord `json:"record"`
	}
	if err := n.call(ctx, "nameserver.info", map[string]any{"domain": domain}, &res); err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(res.Record))
	for _, ir := range res.Record {
		out = append(out, inwxToRecord(ir, domain))
	}
	return out, nil
}

func inwxToRecord(ir inwxRecord, domain string) Record {
	r := Record{
		ID:      ir.ID.String(),
		Type:    strings.ToUpper(ir.Type),
		Name:    inwxRelative(ir.Name, domain),
		Content: ir.Content,
		TTL:     ir.TTL,
		Prio:    ir.Prio,
	}
	if r.Type == "SRV" {
		// INWX stores SRV content as "weight port target"; priority is separate.
		if f := strings.Fields(ir.Content); len(f) == 3 {
			r.Weight, _ = strconv.Atoi(f[0])
			r.Port, _ = strconv.Atoi(f[1])
			r.Content = f[2]
		}
	}
	return r
}

func (n *INWX) AddRecord(ctx context.Context, domain string, r Record) error {
	if err := n.login(ctx); err != nil {
		return err
	}
	params := map[string]any{
		"domain":  domain,
		"type":    strings.ToUpper(r.Type),
		"name":    inwxName(r.Name),
		"content": inwxContent(r),
		"ttl":     ttlOr(r.TTL),
	}
	if r.Prio != 0 || r.Type == "MX" || r.Type == "SRV" {
		params["prio"] = r.Prio
	}
	return n.call(ctx, "nameserver.createRecord", params, nil)
}

func (n *INWX) EditRecord(ctx context.Context, domain string, r Record) error {
	if r.ID == "" {
		return fmt.Errorf("inwx edit: missing id")
	}
	if err := n.login(ctx); err != nil {
		return err
	}
	params := map[string]any{
		"id":      inwxID(r.ID),
		"content": inwxContent(r),
		"ttl":     ttlOr(r.TTL),
	}
	if r.Prio != 0 || r.Type == "MX" || r.Type == "SRV" {
		params["prio"] = r.Prio
	}
	return n.call(ctx, "nameserver.updateRecord", params, nil)
}

func (n *INWX) RemoveRecord(ctx context.Context, domain, id string) error {
	if err := n.login(ctx); err != nil {
		return err
	}
	return n.call(ctx, "nameserver.deleteRecord", map[string]any{"id": inwxID(id)}, nil)
}

// inwxContent renders a Record's content for INWX (priority is a separate field,
// so only SRV packs weight/port/target here; MX passes the bare host).
func inwxContent(r Record) string {
	if strings.EqualFold(r.Type, "SRV") {
		return fmt.Sprintf("%d %d %s", r.Weight, r.Port, r.Content)
	}
	return r.Content
}

// inwxID passes a numeric id as an int when possible (the API expects numbers).
func inwxID(id string) any {
	if num, err := strconv.Atoi(id); err == nil {
		return num
	}
	return id
}

// inwxName maps mailadmin's apex "@" to the empty label INWX expects on input.
func inwxName(name string) string {
	n := strings.TrimSpace(name)
	if n == "@" {
		return ""
	}
	return n
}

// inwxRelative converts an INWX FQDN back to mailadmin's "@"/label form.
func inwxRelative(name, domain string) string {
	n := strings.TrimSuffix(strings.TrimSpace(name), ".")
	if strings.EqualFold(n, domain) {
		return "@"
	}
	if rel, ok := strings.CutSuffix(n, "."+domain); ok {
		return rel
	}
	return n
}

// totp computes a 6-digit RFC 6238 TOTP from a base32 secret at time t.
func totp(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("bad base32 secret: %w", err)
	}
	secs := t.Unix()
	if secs < 0 {
		secs = 0
	}
	counter := uint64(secs) / 30 // #nosec G115 -- secs is non-negative (guarded); TOTP time step
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", code%1_000_000), nil
}

// compile-time assertion.
var _ Provider = (*INWX)(nil)
