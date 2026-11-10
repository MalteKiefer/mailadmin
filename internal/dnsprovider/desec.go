package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DeSEC implements Provider against the deSEC REST API (https://desec.io/api/v1).
// deSEC is RRset-oriented: records are grouped by (subname, type) with a values
// array, priorities are inline in the value, and TXT values are quoted. This
// client flattens RRsets into per-value Records (the Provider model) and, for
// mutations, reads the RRset, edits its values array, and writes it back. A
// Record's ID encodes "subname\x1ftype\x1fvalue" so edits/removes target the
// exact value within its RRset.
//
// deSEC limits RRset writes per domain (2/s, 15/min, 100/h). After ListRecords
// the zone's RRsets are cached, so a write needs no extra GET and creates go
// straight to POST: one request per changed RRset instead of two or three.
type DeSEC struct {
	token  string
	client *http.Client

	mu     sync.Mutex
	listed map[string]bool       // domains whose RRsets are cached
	sets   map[string]desecRRset // domain, subname, type -> RRset
}

// NewDeSEC builds a client from an API token (desec.io account → Token Management).
func NewDeSEC(token string) *DeSEC {
	return &DeSEC{token: token, client: newHTTPClient()}
}

func (*DeSEC) Name() string { return "desec" }

const desecBase = "https://desec.io/api/v1/domains/"

type desecRRset struct {
	Subname string   `json:"subname"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Records []string `json:"records"`
}

// apiError is a deSEC HTTP error response carrying the status code so callers
// can branch on it via errors.As rather than matching the error string.
type apiError struct {
	StatusCode int
	Method     string
	URL        string
	Body       string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("desec %s %s: %d %s", e.Method, e.URL, e.StatusCode, e.Body)
}

// isStatus reports whether err is an *apiError with the given HTTP status.
func isStatus(err error, code int) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.StatusCode == code
}

// do performs an API call. body may be nil. Into decodes the response when non-nil.
// desecMaxAttempts bounds the retries on a throttled (429) or transient 5xx write.
const desecMaxAttempts = 5

// retryableStatus reports whether an HTTP status warrants a retry: throttling
// (429) or a transient upstream/gateway failure (502/503/504).
func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func (d *DeSEC) do(ctx context.Context, method, url string, body, into any) error {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Token "+d.token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := d.client.Do(req)
		if err != nil {
			return err
		}
		// Retry throttled (429) and transient gateway (502/503/504) responses.
		// Honour Retry-After when present, else back off exponentially.
		if retryableStatus(resp.StatusCode) && attempt < desecMaxAttempts {
			wait := backoff(attempt, resp.Header.Get("Retry-After"))
			_ = resp.Body.Close()
			if werr := sleepCtx(ctx, wait); werr != nil {
				return werr
			}
			continue
		}
		if resp.StatusCode >= 400 {
			var buf bytes.Buffer
			_, _ = buf.ReadFrom(resp.Body)
			_ = resp.Body.Close()
			return &apiError{StatusCode: resp.StatusCode, Method: method, URL: url, Body: strings.TrimSpace(buf.String())}
		}
		if into != nil && resp.StatusCode != http.StatusNoContent {
			err = json.NewDecoder(resp.Body).Decode(into)
			_ = resp.Body.Close()
			return err
		}
		_ = resp.Body.Close()
		return nil
	}
}

// backoff returns how long to wait before retry `attempt` (1-based). A valid
// Retry-After header (seconds) wins; otherwise it grows exponentially
// (1s, 2s, 4s, 8s ...). Capped at 60s.
func backoff(attempt int, retryAfterHdr string) time.Duration {
	if d, ok := retryAfter(retryAfterHdr); ok {
		return d
	}
	secs := 1 << (attempt - 1) // 1, 2, 4, 8, ...
	if secs > 60 {
		secs = 60
	}
	return time.Duration(secs) * time.Second
}

// retryAfter parses a Retry-After header (seconds) into a wait duration, capped
// at 60s. ok is false when the header is absent or unparseable.
func retryAfter(h string) (time.Duration, bool) {
	secs, err := strconv.Atoi(strings.TrimSpace(h))
	if err != nil || secs <= 0 {
		return 0, false
	}
	if secs > 60 {
		secs = 60
	}
	return time.Duration(secs) * time.Second, true
}

// sleepCtx waits for d, or aborts early if ctx is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// desecNameservers are deSEC's fixed authoritative nameservers for delegation.
var desecNameservers = []string{"ns1.desec.io", "ns2.desec.org"}

type desecDomain struct {
	Name string `json:"name"`
	Keys []struct {
		DS []string `json:"ds"`
	} `json:"keys"`
}

// EnsureZone creates the zone at deSEC if absent and returns its delegation info
// (nameservers to set at the registrar + DNSSEC DS records to publish).
func (d *DeSEC) EnsureZone(ctx context.Context, domain string) (ZoneInfo, error) {
	// Already present?
	var dom desecDomain
	err := d.do(ctx, http.MethodGet, desecBase+domain+"/", nil, &dom)
	if err == nil {
		return ZoneInfo{Created: false, Nameservers: desecNameservers, DS: dsOf(dom)}, nil
	}
	if !isStatus(err, http.StatusNotFound) {
		return ZoneInfo{}, err
	}
	// Create it.
	if err := d.do(ctx, http.MethodPost, desecBase, map[string]string{"name": domain}, &dom); err != nil {
		return ZoneInfo{}, fmt.Errorf("desec create zone %s: %w", domain, err)
	}
	return ZoneInfo{Created: true, Nameservers: desecNameservers, DS: dsOf(dom)}, nil
}

func dsOf(dom desecDomain) []string {
	var out []string
	for _, k := range dom.Keys {
		out = append(out, k.DS...)
	}
	return out
}

func (d *DeSEC) ListRecords(ctx context.Context, domain string) ([]Record, error) {
	var out []Record
	url := desecBase + domain + "/rrsets/"
	for url != "" {
		// deSEC paginates via Link headers; for our small mail zones one page
		// suffices, but follow the array response regardless.
		var sets []desecRRset
		if err := d.do(ctx, http.MethodGet, url, nil, &sets); err != nil {
			return nil, err
		}
		for _, rs := range sets {
			for _, v := range rs.Records {
				out = append(out, desecToRecord(rs, v))
			}
		}
		d.cacheZone(domain, sets)
		url = "" // single page is enough for a mail record-set
	}
	return out, nil
}

func desecKey(domain, sub, typ string) string {
	return domain + "\x00" + sub + "\x00" + strings.ToUpper(typ)
}

// cacheZone remembers a zone's RRsets as just listed.
func (d *DeSEC) cacheZone(domain string, sets []desecRRset) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.listed == nil {
		d.listed, d.sets = map[string]bool{}, map[string]desecRRset{}
	}
	for k := range d.sets {
		if strings.HasPrefix(k, domain+"\x00") {
			delete(d.sets, k)
		}
	}
	for _, rs := range sets {
		d.sets[desecKey(domain, rs.Subname, rs.Type)] = rs
	}
	d.listed[domain] = true
}

// cached returns the cached RRset and whether the zone is cached at all.
func (d *DeSEC) cached(domain, sub, typ string) (desecRRset, bool, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.listed[domain] {
		return desecRRset{}, false, false
	}
	rs, ok := d.sets[desecKey(domain, sub, typ)]
	return rs, ok, true
}

// remember updates the cache after a successful write.
func (d *DeSEC) remember(domain string, rs desecRRset) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.listed[domain] {
		return
	}
	if len(rs.Records) == 0 {
		delete(d.sets, desecKey(domain, rs.Subname, rs.Type))
		return
	}
	d.sets[desecKey(domain, rs.Subname, rs.Type)] = rs
}

func (d *DeSEC) AddRecord(ctx context.Context, domain string, r Record) error {
	return d.upsertValue(ctx, domain, r.Name, r.Type, r.TTL, rrsetValue(r), "")
}

func (d *DeSEC) EditRecord(ctx context.Context, domain string, r Record) error {
	sub, typ, oldVal, ok := parseRRID(r.ID)
	if !ok {
		return fmt.Errorf("desec edit: bad record id")
	}
	if sub != desecSubname(r.Name) || !strings.EqualFold(typ, r.Type) {
		return fmt.Errorf("desec edit: id mismatch")
	}
	return d.upsertValue(ctx, domain, r.Name, r.Type, r.TTL, rrsetValue(r), oldVal)
}

func (d *DeSEC) RemoveRecord(ctx context.Context, domain, id string) error {
	sub, typ, val, ok := parseRRID(id)
	if !ok {
		return fmt.Errorf("desec remove: bad record id")
	}
	rs, err := d.getRRset(ctx, domain, sub, typ)
	if err != nil {
		return err
	}
	kept := removeValue(rs.Records, val)
	return d.writeRRset(ctx, domain, sub, typ, rs.TTL, kept)
}

// upsertValue replaces oldVal (empty = add) with newVal in the (subname,type)
// RRset, then writes the RRset back.
func (d *DeSEC) upsertValue(ctx context.Context, domain, name, typ string, ttl int, newVal, oldVal string) error {
	sub := desecSubname(name)
	rs, err := d.getRRset(ctx, domain, sub, typ)
	if err != nil {
		return err
	}
	values := rs.Records
	if oldVal != "" {
		values = removeValue(values, oldVal)
	}
	if !containsValue(values, newVal) {
		values = append(values, newVal)
	}
	useTTL := ttlOr(ttl)
	if rs.TTL > 0 {
		useTTL = rs.TTL
	}
	return d.writeRRset(ctx, domain, sub, typ, useTTL, values)
}

// getRRset fetches one RRset; a 404 yields an empty set (not an error).
func (d *DeSEC) getRRset(ctx context.Context, domain, sub, typ string) (desecRRset, error) {
	if rs, ok, zone := d.cached(domain, sub, typ); zone {
		if !ok {
			return desecRRset{Subname: sub, Type: strings.ToUpper(typ)}, nil
		}
		return rs, nil
	}
	url := fmt.Sprintf("%s%s/rrsets/%s/%s/", desecBase, domain, desecURLSub(sub), strings.ToUpper(typ))
	var rs desecRRset
	err := d.do(ctx, http.MethodGet, url, nil, &rs)
	if err != nil {
		if isStatus(err, http.StatusNotFound) {
			return desecRRset{Subname: sub, Type: strings.ToUpper(typ)}, nil
		}
		return desecRRset{}, err
	}
	return rs, nil
}

// writeRRset PUTs the RRset (creates when absent). An empty values array deletes
// the RRset.
func (d *DeSEC) writeRRset(ctx context.Context, domain, sub, typ string, ttl int, values []string) error {
	base := fmt.Sprintf("%s%s/rrsets/", desecBase, domain)
	body := desecRRset{Subname: sub, Type: strings.ToUpper(typ), TTL: ttlOr(ttl), Records: values}
	if len(values) == 0 {
		url := fmt.Sprintf("%s%s/%s/", base, desecURLSub(sub), strings.ToUpper(typ))
		if err := d.do(ctx, http.MethodDelete, url, nil, nil); err != nil {
			return err
		}
		d.remember(domain, body)
		return nil
	}
	// A set the cached zone does not have is created with one POST.
	if _, ok, zone := d.cached(domain, sub, typ); zone && !ok {
		if err := d.do(ctx, http.MethodPost, base, body, nil); err != nil {
			return err
		}
		d.remember(domain, body)
		return nil
	}
	// PUT to the collection upserts by (subname,type).
	url := fmt.Sprintf("%s%s/%s/", base, desecURLSub(sub), strings.ToUpper(typ))
	if err := d.do(ctx, http.MethodPut, url, body, nil); err != nil {
		// If the RRset does not exist yet, create it via POST to the collection.
		if !isStatus(err, http.StatusNotFound) {
			return err
		}
		if err := d.do(ctx, http.MethodPost, base, body, nil); err != nil {
			return err
		}
	}
	d.remember(domain, body)
	return nil
}

// ---- value <-> Record mapping ------------------------------------------

// desecSubname maps our apex "@"/"" to deSEC's empty subname.
func desecSubname(name string) string {
	n := strings.TrimSpace(name)
	if n == "" || n == "@" {
		return ""
	}
	return n
}

// desecURLSub maps an empty subname to "@" for the URL path.
func desecURLSub(sub string) string {
	if sub == "" {
		return "@"
	}
	return sub
}

// desecToRecord parses one RRset value into a Record, tagged with an ID that
// encodes its slot + raw value.
func desecToRecord(rs desecRRset, value string) Record {
	name := rs.Subname
	if name == "" {
		name = "@"
	}
	r := Record{Type: strings.ToUpper(rs.Type), Name: name, TTL: rs.TTL, ID: rrID(rs.Subname, rs.Type, value)}
	rrsetParse(&r, value)
	return r
}

func splitPrio(v string) (int, string) {
	fields := strings.SplitN(strings.TrimSpace(v), " ", 2)
	if len(fields) == 2 {
		if p, err := strconv.Atoi(fields[0]); err == nil {
			return p, strings.TrimSpace(fields[1])
		}
	}
	return 0, v
}

// quoteTXT renders a TXT value as deSEC expects: 255-char chunks, each quoted,
// space-separated (DNS character-string limit).
func quoteTXT(s string) string {
	const max = 255
	var parts []string
	for len(s) > 0 {
		n := len(s)
		if n > max {
			n = max
		}
		parts = append(parts, `"`+escapeTXT(s[:n])+`"`)
		s = s[n:]
	}
	if len(parts) == 0 {
		return `""`
	}
	return strings.Join(parts, " ")
}

// unquoteTXT reverses quoteTXT: strip quotes from each chunk and concatenate.
func unquoteTXT(s string) string {
	var b strings.Builder
	for _, chunk := range splitQuoted(s) {
		b.WriteString(chunk)
	}
	return b.String()
}

func escapeTXT(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

// splitQuoted returns the contents of each "..."-quoted chunk in s.
func splitQuoted(s string) []string {
	var out []string
	inQuote := false
	var cur strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\' && inQuote:
			esc = true
		case r == '"':
			if inQuote {
				out = append(out, cur.String())
				cur.Reset()
			}
			inQuote = !inQuote
		case inQuote:
			cur.WriteRune(r)
		}
	}
	if len(out) == 0 {
		return []string{strings.Trim(s, `"`)}
	}
	return out
}

// ---- record identity encoding ------------------------------------------

func containsValue(vals []string, v string) bool {
	for _, x := range vals {
		if strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(v)) {
			return true
		}
	}
	return false
}

func removeValue(vals []string, v string) []string {
	out := vals[:0:0]
	for _, x := range vals {
		if !strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(v)) {
			out = append(out, x)
		}
	}
	return out
}

var (
	_ Provider    = (*DeSEC)(nil)
	_ ZoneManager = (*DeSEC)(nil)
)
