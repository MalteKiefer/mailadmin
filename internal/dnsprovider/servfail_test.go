package dnsprovider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// hostRewrite sends every request to the test server, keeping the API path.
type hostRewrite struct {
	target *url.URL
	rt     http.RoundTripper
}

func (h hostRewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = h.target.Scheme
	req.URL.Host = h.target.Host
	req.Host = h.target.Host
	return h.rt.RoundTrip(req)
}

func newFlushTestServfail(t *testing.T, zone string, putStatus int) (*Servfail, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var puts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/zones/example.com."):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(zone))
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/zones/example.com./rectify"):
			mu.Lock()
			puts = append(puts, r.URL.Path)
			mu.Unlock()
			if putStatus >= 400 {
				w.WriteHeader(putStatus)
				_, _ = w.Write([]byte(`{"error":"boom"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServfail("key", "ns1.servfail.network")
	s.client = &http.Client{Transport: hostRewrite{target: target, rt: http.DefaultTransport}}
	return s, &puts
}

func TestServfailFlushRectifiesUnlessAPIRectify(t *testing.T) {
	cases := []struct {
		name    string
		zone    string
		wantPUT bool
	}{
		{"dnssec without api rectify", `{"dnssec":true,"api_rectify":false}`, true},
		{"dnssec with api rectify", `{"dnssec":true,"api_rectify":true}`, false},
		{"not dnssec", `{"dnssec":false,"api_rectify":false}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, puts := newFlushTestServfail(t, tc.zone, http.StatusOK)
			if err := s.Flush(context.Background(), "example.com"); err != nil {
				t.Fatalf("Flush: %v", err)
			}
			if got := len(*puts) == 1; got != tc.wantPUT {
				t.Fatalf("rectify PUT happened=%v, want %v (puts=%v)", got, tc.wantPUT, *puts)
			}
		})
	}
}

func TestServfailFlushWrapsRectifyError(t *testing.T) {
	s, _ := newFlushTestServfail(t, `{"dnssec":true,"api_rectify":false}`, http.StatusInternalServerError)
	err := s.Flush(context.Background(), "example.com")
	if err == nil || !strings.HasPrefix(err.Error(), "rectify: ") {
		t.Fatalf("Flush error = %v, want rectify-wrapped error", err)
	}
}
