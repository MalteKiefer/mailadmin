package notify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConfigured(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"both set", Config{URL: "https://notify.example.com/topic", Token: "tok"}, true},
		{"empty", Config{}, false},
		{"url only", Config{URL: "https://notify.example.com/topic"}, false},
		{"token only", Config{Token: "tok"}, false},
		{"whitespace only", Config{URL: "  ", Token: "  "}, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.Configured(); got != tt.want {
				t.Errorf("Configured() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSendNoopWhenUnconfigured(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	var warned []string
	err := Send(context.Background(), Config{}, Message{Title: "x", Body: "y"}, func(s string) {
		warned = append(warned, s)
	})
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if called {
		t.Fatal("Send made an HTTP request despite unconfigured Config")
	}
	if len(warned) != 0 {
		t.Fatalf("unexpected warnings for a clean no-op: %v", warned)
	}
}

func TestSendRequestShape(t *testing.T) {
	var gotMethod, gotAuth, gotTitle, gotPriority, gotTags, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotTitle = r.Header.Get("Title")
		gotPriority = r.Header.Get("Priority")
		gotTags = r.Header.Get("Tags")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{URL: srv.URL + "/mailadmin", Token: "s3cr3t"}
	msg := Message{
		Title:    "mailadmin doctor: 2 check(s) failing",
		Body:     "service:postfix: inactive/dead (disabled)\nports: not listening: 25",
		Priority: PriorityHigh,
		Tags:     "rotating_light",
	}

	var warned []string
	if err := Send(context.Background(), cfg, msg, func(s string) { warned = append(warned, s) }); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(warned) != 0 {
		t.Fatalf("unexpected warnings on a healthy 200 response: %v", warned)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotAuth != "Bearer s3cr3t" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer s3cr3t")
	}
	if gotTitle != msg.Title {
		t.Errorf("Title header = %q, want %q", gotTitle, msg.Title)
	}
	if gotPriority != "high" {
		t.Errorf("Priority header = %q, want %q", gotPriority, "high")
	}
	if gotTags != "rotating_light" {
		t.Errorf("Tags header = %q, want %q", gotTags, "rotating_light")
	}
	if gotBody != msg.Body {
		t.Errorf("body = %q, want %q", gotBody, msg.Body)
	}
}

func TestSendOmitsEmptyOptionalHeaders(t *testing.T) {
	var sawTitle, sawPriority, sawTags bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawTitle = r.Header.Get("Title") != ""
		sawPriority = r.Header.Get("Priority") != ""
		sawTags = r.Header.Get("Tags") != ""
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{URL: srv.URL, Token: "tok"}
	if err := Send(context.Background(), cfg, Message{Body: "just a body"}, nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if sawTitle || sawPriority || sawTags {
		t.Errorf("expected no optional headers, got title=%v priority=%v tags=%v", sawTitle, sawPriority, sawTags)
	}
}

func TestSendNonOKStatusWarnsButDoesNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	var warned []string
	cfg := Config{URL: srv.URL, Token: "tok"}
	err := Send(context.Background(), cfg, Message{Body: "hi"}, func(s string) { warned = append(warned, s) })
	if err != nil {
		t.Fatalf("Send returned error for a non-2xx response: %v", err)
	}
	if len(warned) != 1 {
		t.Fatalf("expected exactly one warning, got %v", warned)
	}
}

func TestSendUnreachableEndpointWarnsButDoesNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // now unreachable

	var warned []string
	cfg := Config{URL: url, Token: "tok"}
	err := Send(context.Background(), cfg, Message{Body: "hi"}, func(s string) { warned = append(warned, s) })
	if err != nil {
		t.Fatalf("Send returned error for an unreachable endpoint: %v", err)
	}
	if len(warned) != 1 {
		t.Fatalf("expected exactly one warning, got %v", warned)
	}
}

func TestSendNilOnWarnDoesNotPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := Config{URL: srv.URL, Token: "tok"}
	if err := Send(context.Background(), cfg, Message{Body: "hi"}, nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
}
