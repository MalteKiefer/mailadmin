// Package notify sends operator alerts to a self-hosted ntfy.sh topic
// (https://ntfy.sh/ or a self-hosted instance, matching the ntfy() bash
// helper already used elsewhere on the mail host for the same purpose). It is
// a deliberately thin, best-effort client, not a general HTTP integration
// framework: mailadmin itself has no daemon and no scheduler (see
// docs/ARCHITECTURE.md), so this package only ever fires from an already-
// running command invocation (e.g. `doctor --notify`, `dns drift-check
// --notify`), never on its own.
//
// Alerting must never be the reason a real failure goes unreported louder
// than "notify didn't fire": Send never returns an error to the caller and
// never panics. A missing/incomplete Config makes it a clean no-op; a
// transport or non-2xx failure while POSTing is reported through the
// optional onWarn callback (typically wired to stderr) and otherwise
// swallowed, so a broken ntfy endpoint can never mask or replace the actual
// check failure and exit code the caller is reporting.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// timeout bounds every outbound POST to the ntfy endpoint.
const timeout = 10 * time.Second

// Config is the minimal ntfy target: a topic URL and its bearer token. The
// URL is not secret (it lives in config.toml's [notify] section); the token
// is (secrets.env's NTFY_TOKEN). Both must be non-empty for Configured to be
// true, a topic with no token, or a token with no topic, is treated as
// "not configured" rather than guessed at.
type Config struct {
	URL   string
	Token string
}

// Configured reports whether both URL and Token are set.
func (c Config) Configured() bool {
	return strings.TrimSpace(c.URL) != "" && strings.TrimSpace(c.Token) != ""
}

// Priority mirrors ntfy's Priority header values. PriorityDefault omits the
// header entirely, letting the server apply its own default.
type Priority string

const (
	PriorityDefault Priority = ""
	PriorityHigh    Priority = "high"
	PriorityLow     Priority = "low"
)

// Message is one ntfy notification. Tags is a comma-separated list of ntfy
// emoji-tag shortcodes (e.g. "rotating_light,mailadmin").
type Message struct {
	Title    string
	Body     string
	Priority Priority
	Tags     string
}

// newHTTPClient mirrors internal/dnsprovider's newHTTPClient: TLS 1.2+
// pinned explicitly, cert verification always on, a hard timeout so a
// notify call can never hang a command.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}

// Send posts msg to cfg's ntfy topic, mirroring the shape of the mailsync
// script's ntfy() bash helper: POST to the topic URL, "Authorization: Bearer
// <token>", "Title:"/"Priority:"/"Tags:" headers, body = the message text.
//
// It no-ops cleanly (no request made, nil returned) when cfg is not
// configured. Any failure to build or send the request, or a non-2xx
// response, is reported through onWarn (if non-nil) and otherwise swallowed
// , Send always returns nil. Callers must not treat a nil return as proof the
// notification was delivered; it only means the failure to deliver it did not
// propagate.
func Send(ctx context.Context, cfg Config, msg Message, onWarn func(string)) error {
	if !cfg.Configured() {
		return nil
	}
	warn := func(format string, args ...any) {
		if onWarn != nil {
			onWarn(fmt.Sprintf(format, args...))
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(cfg.URL, "/"), bytes.NewBufferString(msg.Body))
	if err != nil {
		warn("notify: build request: %v", err)
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	if msg.Title != "" {
		req.Header.Set("Title", msg.Title)
	}
	if msg.Priority != "" {
		req.Header.Set("Priority", string(msg.Priority))
	}
	if msg.Tags != "" {
		req.Header.Set("Tags", msg.Tags)
	}

	resp, err := newHTTPClient().Do(req)
	if err != nil {
		warn("notify: send to %s: %v", cfg.URL, err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		warn("notify: %s returned HTTP %d", cfg.URL, resp.StatusCode)
	}
	return nil
}
