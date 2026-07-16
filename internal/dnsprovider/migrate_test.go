package dnsprovider

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// fakeProvider is an in-memory Provider for exercising Migrate. AddRecord can be
// made to fail with a preset error to test the failure-reason path.
type fakeProvider struct {
	records []Record
	addErr  error
}

func (*fakeProvider) Name() string { return "fake" }

func (f *fakeProvider) ListRecords(context.Context, string) ([]Record, error) {
	return f.records, nil
}

func (f *fakeProvider) AddRecord(_ context.Context, _ string, r Record) error {
	if f.addErr != nil {
		return f.addErr
	}
	f.records = append(f.records, r)
	return nil
}

func (*fakeProvider) EditRecord(context.Context, string, Record) error { return nil }

func (f *fakeProvider) RemoveRecord(context.Context, string, string) error { return nil }

func TestMigrateSkipsNSAndSOA(t *testing.T) {
	src := []Record{
		{Type: "NS", Name: "@", Content: "ns1.example.net"},
		{Type: "SOA", Name: "@", Content: "ns1.example.net. hostmaster.example.net. 1 2 3 4 5"},
		{Type: "A", Name: "@", Content: "203.0.113.1"},
		{Type: "MX", Name: "@", Content: "mail.example.com", Prio: 10},
	}
	target := &fakeProvider{}
	res, err := Migrate(context.Background(), target, "example.com", src)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if len(res.Created) != 2 {
		t.Fatalf("created = %d, want 2 (NS/SOA must be skipped)", len(res.Created))
	}
	for _, r := range target.records {
		if r.Type == "NS" || r.Type == "SOA" {
			t.Errorf("delegation record copied to target: %+v", r)
		}
	}
}

func TestMigrateFailureCarriesReason(t *testing.T) {
	target := &fakeProvider{addErr: &apiError{StatusCode: http.StatusTooManyRequests, Method: "PUT", URL: "x"}}
	res, err := Migrate(context.Background(), target, "example.com", []Record{{Type: "A", Name: "@", Content: "203.0.113.1"}})
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if len(res.Failed) != 1 {
		t.Fatalf("failed = %d, want 1", len(res.Failed))
	}
	if got := res.Failed[0].Reason; got == "" || got == (&apiError{}).Error() {
		t.Errorf("reason not set meaningfully: %q", got)
	}
}

func TestRetryAfter(t *testing.T) {
	if d, ok := retryAfter("3"); !ok || d != 3*time.Second {
		t.Errorf(`retryAfter("3") = %v,%v want 3s,true`, d, ok)
	}
	if d, ok := retryAfter("9999"); !ok || d != 60*time.Second {
		t.Errorf(`retryAfter("9999") = %v,%v want 60s,true (capped)`, d, ok)
	}
	for _, in := range []string{"", "0", "bad", "-1"} {
		if d, ok := retryAfter(in); ok {
			t.Errorf("retryAfter(%q) = %v,true want ok=false", in, d)
		}
	}
}

func TestBackoff(t *testing.T) {
	// Header wins when valid.
	if got := backoff(1, "5"); got != 5*time.Second {
		t.Errorf("backoff with header = %v, want 5s", got)
	}
	// No header → exponential 1,2,4,8, capped at 60.
	want := map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 4: 8 * time.Second, 10: 60 * time.Second}
	for attempt, w := range want {
		if got := backoff(attempt, ""); got != w {
			t.Errorf("backoff(%d, \"\") = %v, want %v", attempt, got, w)
		}
	}

	if !retryableStatus(http.StatusBadGateway) || !retryableStatus(http.StatusTooManyRequests) {
		t.Error("502/429 must be retryable")
	}
	if retryableStatus(http.StatusUnprocessableEntity) || retryableStatus(http.StatusNotFound) {
		t.Error("422/404 must not be retryable")
	}
}
