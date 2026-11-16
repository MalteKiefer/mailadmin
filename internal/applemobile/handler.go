package applemobile

import (
	"errors"
	"html/template"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"mailadmin/internal/valid"
)

// maxFormBytes bounds the request body. The form has one short field.
const maxFormBytes = 4 << 10

// Limits per client address: a burst of perRateWindow requests, refilled over the window.
const (
	perRateWindow = 10
	rateRefill    = time.Minute
)

// refusal is the one message for every rejected request. It does not say whether the
// address or the domain exists.
const refusal = "Diese Adresse kann hier nicht eingerichtet werden."

// Handler serves the profile form and the profile download.
type Handler struct {
	// Host is the mail server name written into the profile.
	Host string
	// Domains returns the active mail domains allowed for profiles.
	Domains func() (map[string]bool, error)
	// clientKey extracts the client address. Behind Caddy it is X-Forwarded-For.
	now     func() time.Time
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewHandler returns a handler with the default clock.
func NewHandler(host string, domains func() (map[string]bool, error)) *Handler {
	return &Handler{Host: host, Domains: domains, now: time.Now, buckets: map[string]*bucket{}}
}

// ServeHTTP routes GET / (form) and POST /profile (download).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/":
		h.form(w, "")
	case r.Method == http.MethodPost && r.URL.Path == "/profile":
		h.profile(w, r)
	default:
		http.NotFound(w, r)
	}
}

func setSecurityHeaders(w http.ResponseWriter) {
	hd := w.Header()
	hd.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Referrer-Policy", "no-referrer")
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Frame-Options", "DENY")
}

var formTmpl = template.Must(template.New("form").Parse(`<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mail auf dem Apple-Gerät einrichten</title>
<style>body{font:16px system-ui,sans-serif;max-width:32rem;margin:2rem auto;padding:0 1rem}input{width:100%;font:inherit;padding:.5rem;box-sizing:border-box}button{font:inherit;padding:.6rem 1rem;margin-top:.8rem}.msg{color:#a00}</style>
</head><body>
<h1>Mail auf dem iPhone oder Mac einrichten</h1>
<p>Gib deine Mailadresse ein. Du lädst dann ein Konfigurationsprofil herunter. Das Profil enthält keine Zugangsdaten. Dein Passwort gibst du bei der Installation auf dem Gerät ein.</p>
<form method="post" action="/profile">
<label for="email">Mailadresse</label>
<input id="email" name="email" type="email" autocomplete="email" required maxlength="254">
<button type="submit">Profil herunterladen</button>
</form>
{{if .Msg}}<p class="msg">{{.Msg}}</p>{{end}}
<p>Das Profil ist nicht signiert. iOS zeigt deshalb eine Warnung. Installiere es nur, wenn du die Adresse selbst eingegeben hast.</p>
</body></html>`))

func (h *Handler) form(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = formTmpl.Execute(w, struct{ Msg string }{msg})
}

func (h *Handler) profile(w http.ResponseWriter, r *http.Request) {
	if !h.allow(clientKey(r)) {
		http.Error(w, "Zu viele Anfragen. Bitte warte kurz.", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		h.refuse(w)
		return
	}
	address := strings.TrimSpace(r.PostFormValue("email"))
	local, domain, err := valid.Address(address)
	if err != nil || local == "" {
		h.refuse(w)
		return
	}
	allowed, err := h.Domains()
	if err != nil || !allowed[strings.ToLower(domain)] {
		h.refuse(w)
		return
	}
	body, err := BuildProfile(address, h.Host)
	if err != nil {
		if errors.Is(err, ErrBadAddress) {
			h.refuse(w)
			return
		}
		http.Error(w, "Profil konnte nicht erzeugt werden.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="mail-`+strings.ReplaceAll(domain, `"`, "")+`.mobileconfig"`)
	_, _ = w.Write(body)
}

func (h *Handler) refuse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_ = formTmpl.Execute(w, struct{ Msg string }{refusal})
}

// clientKey returns the address the request came from. Caddy is the only peer, so
// the client address is the last X-Forwarded-For entry it appended.
func clientKey(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// allow implements a token bucket per client: perRateWindow requests, refilled over
// rateRefill.
func (h *Handler) allow(key string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	b, ok := h.buckets[key]
	if !ok {
		b = &bucket{tokens: perRateWindow, last: now}
		h.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * float64(perRateWindow) / rateRefill.Seconds()
	if b.tokens > perRateWindow {
		b.tokens = perRateWindow
	}
	b.last = now
	if len(h.buckets) > 10000 {
		h.buckets = map[string]*bucket{key: b}
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
