package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Discord embed limits (https://discord.com/developers/docs/resources/message).
const (
	discordTitleMax = 256
	discordDescMax  = 4096
)

// Embed colours by priority: red for failures, green for heartbeats, blue otherwise.
const (
	colourHigh    = 0xED4245
	colourLow     = 0x57F287
	colourDefault = 0x5865F2
)

// ValidDiscordWebhook reports whether raw is an https webhook URL on a Discord
// host. Anything else is refused at config check, so no secret is sent to an
// arbitrary endpoint.
func ValidDiscordWebhook(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" {
		return fmt.Errorf("discord webhook must be an https URL")
	}
	host := strings.ToLower(u.Hostname())
	if host != "discord.com" && host != "discordapp.com" {
		return fmt.Errorf("discord webhook host %q is not discord.com", host)
	}
	if !strings.HasPrefix(u.Path, "/api/webhooks/") {
		return fmt.Errorf("discord webhook path must start with /api/webhooks/")
	}
	return nil
}

// discordPayload is the webhook body: one embed carrying the message.
type discordPayload struct {
	Embeds []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Colour      int    `json:"color"`
}

// DiscordPayload builds the webhook body for msg. Title and description are
// cut to Discord's limits.
func DiscordPayload(msg Message) discordPayload {
	colour := colourDefault
	switch msg.Priority {
	case PriorityHigh:
		colour = colourHigh
	case PriorityLow:
		colour = colourLow
	}
	return discordPayload{Embeds: []discordEmbed{{
		Title:       truncate(msg.Title, discordTitleMax),
		Description: truncate(msg.Body, discordDescMax),
		Colour:      colour,
	}}}
}

func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}

// SendDiscord posts msg to a Discord webhook. Like Send it is best-effort: it
// never returns an error, failures go to onWarn. An empty URL is a no-op.
func SendDiscord(ctx context.Context, webhookURL string, msg Message, onWarn func(string)) error {
	if strings.TrimSpace(webhookURL) == "" {
		return nil
	}
	warn := func(format string, args ...any) {
		if onWarn != nil {
			onWarn(fmt.Sprintf(format, args...))
		}
	}
	if err := ValidDiscordWebhook(webhookURL); err != nil {
		warn("notify: discord: %v", err)
		return nil
	}
	body, err := json.Marshal(DiscordPayload(msg))
	if err != nil {
		warn("notify: discord payload: %v", err)
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		warn("notify: discord request: %v", err)
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := newHTTPClient().Do(req)
	if err != nil {
		warn("notify: discord send: %v", err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		warn("notify: discord returned HTTP %d", resp.StatusCode)
	}
	return nil
}
