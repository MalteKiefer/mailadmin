package applemobile

import (
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// keys returns every key name in the document, in order.
func keys(t *testing.T, doc []byte) []string {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(string(doc)))
	var out []string
	var inKey bool
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("profile is not well-formed XML: %v", err)
		}
		switch el := tok.(type) {
		case xml.StartElement:
			inKey = el.Name.Local == "key"
		case xml.CharData:
			if inKey {
				out = append(out, string(el))
			}
		case xml.EndElement:
			inKey = false
		}
	}
	return out
}

func TestBuildProfileIsWellFormedAndHasNoPassword(t *testing.T) {
	doc, err := BuildProfile("malte@kiefer-networks.de", "mail.kiefer-networks.de")
	if err != nil {
		t.Fatal(err)
	}
	ks := keys(t, doc)
	for _, k := range ks {
		if strings.Contains(strings.ToLower(k), "password") && k != "OutgoingPasswordSameAsIncomingPassword" && k != "IncomingMailServerAuthentication" && k != "OutgoingMailServerAuthentication" {
			t.Fatalf("profile carries a password key %q", k)
		}
	}
	s := string(doc)
	if strings.Contains(strings.ToLower(s), "<string>secret") {
		t.Fatal("unexpected value in profile")
	}
	for _, want := range []string{
		"<key>PayloadType</key><string>com.apple.mail.managed</string>",
		"<key>IncomingMailServerHostName</key><string>mail.kiefer-networks.de</string>",
		"<key>IncomingMailServerPortNumber</key><integer>993</integer>",
		"<key>OutgoingMailServerPortNumber</key><integer>465</integer>",
		"<key>EmailAddress</key><string>malte@kiefer-networks.de</string>",
		"<key>EmailAccountName</key><string>kiefer-networks.de</string>",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("profile missing %q", want)
		}
	}
	if !strings.Contains(s, "<string>Configuration</string>") {
		t.Fatal("outer payload type missing")
	}
}

func TestAccountUUIDStableAndVersion5(t *testing.T) {
	a := accountUUID("account:a@example.test")
	if a != accountUUID("account:a@example.test") {
		t.Fatal("UUID not stable")
	}
	if a == accountUUID("account:b@example.test") {
		t.Fatal("UUID not unique per address")
	}
	re := regexp.MustCompile(`^[0-9A-F]{8}-[0-9A-F]{4}-5[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$`)
	if !re.MatchString(a) {
		t.Fatalf("not a v5 RFC 4122 UUID: %s", a)
	}
}

func TestBuildProfileRejectsBadInput(t *testing.T) {
	for _, addr := range []string{"", "no-at-sign", "a@b@c", "x\"y@example.test", "<a>@example.test"} {
		if _, err := BuildProfile(addr, "mail.example.test"); err == nil {
			t.Fatalf("address %q accepted", addr)
		}
	}
	if _, err := BuildProfile("a@example.test", "bad host!"); err == nil {
		t.Fatal("bad mail host accepted")
	}
}

func TestDomainListRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apple-domains")
	if err := WriteDomainList(path, []string{"b.example.test", "a.example.test"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode %o, want 0644", info.Mode().Perm())
	}
	got, err := ReadDomainList(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got["a.example.test"] || !got["b.example.test"] || got["c.example.test"] {
		t.Fatalf("unexpected list %v", got)
	}
	missing, err := ReadDomainList(filepath.Join(t.TempDir(), "none"))
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing file should be empty list, got %v %v", missing, err)
	}
	if err := WriteDomainList(path, []string{"bad domain"}); err == nil {
		t.Fatal("domain with space accepted")
	}
}

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	h := NewHandler("mail.example.test", func() (map[string]bool, error) {
		return map[string]bool{"example.test": true}, nil
	})
	return h
}

func post(h http.Handler, email, xff string) *httptest.ResponseRecorder {
	form := url.Values{"email": {email}}
	req := httptest.NewRequest(http.MethodPost, "/profile", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:40000"
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestFormAndSecurityHeaders(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("form status %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `action="/profile"`) {
		t.Fatal("form does not post to /profile")
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") {
		t.Fatalf("unexpected CSP %q", csp)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("form cacheable")
	}
}

func TestProfileDownloadForHostedDomain(t *testing.T) {
	h := newTestHandler(t)
	rec := post(h, "malte@example.test", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/x-apple-aspen-config" {
		t.Fatalf("content type %q", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), `filename="mail-example.test.mobileconfig"`) {
		t.Fatalf("disposition %q", rec.Header().Get("Content-Disposition"))
	}
	keys(t, rec.Body.Bytes())
}

func TestRefusalIsGenericForUnknownDomainAndBadAddress(t *testing.T) {
	h := newTestHandler(t)
	unknown := post(h, "malte@other.test", "")
	bad := post(h, "not-an-address", "")
	if unknown.Code != http.StatusBadRequest || bad.Code != http.StatusBadRequest {
		t.Fatalf("codes %d %d", unknown.Code, bad.Code)
	}
	if unknown.Body.String() != bad.Body.String() {
		t.Fatal("refusal differs between unknown domain and bad address (enumeration)")
	}
	if strings.Contains(unknown.Body.String(), "other.test") {
		t.Fatal("refusal echoes the domain")
	}
}

func TestRateLimitPerClient(t *testing.T) {
	h := newTestHandler(t)
	now := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	codes := map[int]int{}
	for i := 0; i < perRateWindow+5; i++ {
		codes[post(h, "malte@example.test", "203.0.113.9").Code]++
	}
	if codes[http.StatusTooManyRequests] == 0 {
		t.Fatalf("no 429 after burst: %v", codes)
	}
	if post(h, "malte@example.test", "198.51.100.7").Code != http.StatusOK {
		t.Fatal("other client blocked by first client's bucket")
	}
	now = now.Add(rateRefill)
	if post(h, "malte@example.test", "203.0.113.9").Code != http.StatusOK {
		t.Fatal("bucket did not refill")
	}
}

func TestClientKeyUsesLastForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/profile", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.50")
	if got := clientKey(req); got != "203.0.113.50" {
		t.Fatalf("client key %q", got)
	}
}
