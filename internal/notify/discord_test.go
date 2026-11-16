package notify

import (
	"strings"
	"testing"
)

func TestValidDiscordWebhook(t *testing.T) {
	ok := []string{"", "https://discord.com/api/webhooks/123/abc", "https://discordapp.com/api/webhooks/1/x"}
	for _, u := range ok {
		if err := ValidDiscordWebhook(u); err != nil {
			t.Fatalf("%q refused: %v", u, err)
		}
	}
	bad := []string{"http://discord.com/api/webhooks/1/x", "https://evil.example/api/webhooks/1/x", "https://discord.com/other", "not a url"}
	for _, u := range bad {
		if err := ValidDiscordWebhook(u); err == nil {
			t.Fatalf("%q accepted", u)
		}
	}
}

func TestDiscordPayloadColourAndLimits(t *testing.T) {
	p := DiscordPayload(Message{Title: strings.Repeat("t", 400), Body: "b", Priority: PriorityHigh})
	e := p.Embeds[0]
	if e.Colour != colourHigh {
		t.Fatalf("high priority colour = %x", e.Colour)
	}
	if len([]rune(e.Title)) > discordTitleMax {
		t.Fatal("title over Discord limit")
	}
	if DiscordPayload(Message{Priority: PriorityLow}).Embeds[0].Colour != colourLow {
		t.Fatal("low priority colour")
	}
}
