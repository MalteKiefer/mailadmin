package audit

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeLogger captures the arguments db.Log would receive.
type fakeLogger struct {
	calls  int
	actor  string
	action string
	target string
	before any
	after  any
	ip     string
	ua     string
	err    error
}

func (f *fakeLogger) Log(_ context.Context, actor, action, target string, before, after any, ip, ua string) error {
	f.calls++
	f.actor, f.action, f.target = actor, action, target
	f.before, f.after = before, after
	f.ip, f.ua = ip, ua
	return f.err
}

func TestSanitizeActor(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "root", "root"},
		{"trims spaces", "  mailadmin \t", "mailadmin"},
		{"empty", "", ""},
		{"only spaces", "   ", ""},
		{"newline rejected", "root\ninjected", ""},
		{"tab rejected", "ro\tot", ""},
		{"del rejected", "root\x7f", ""},
		{"esc rejected", "root\x1b[31m", ""},
		{"unicode kept", "münster", "münster"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeActor(tt.in); got != tt.want {
				t.Fatalf("sanitizeActor(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNewSanitizesActor(t *testing.T) {
	r := New(&fakeLogger{}, "root\ninjected")
	if r.Actor() != "" {
		t.Fatalf("actor with embedded control char should sanitize to empty, got %q", r.Actor())
	}
	r = New(&fakeLogger{}, "  mailadmin  ")
	if r.Actor() != "mailadmin" {
		t.Fatalf("Actor() = %q, want mailadmin", r.Actor())
	}
}

func TestCurrentActorNonEmpty(t *testing.T) {
	// Host-independent: whatever the lookup returns, CurrentActor must yield a
	// non-empty, attributable string (name or uid:<n>).
	got := CurrentActor()
	if got == "" {
		t.Fatal("CurrentActor() returned empty string")
	}
	if strings.ContainsAny(got, "\n\t") {
		t.Fatalf("CurrentActor() contains control chars: %q", got)
	}
}

func TestCurrentActorUIDFallback(t *testing.T) {
	// Simulate a machine where the username cannot be resolved.
	saveUID, saveName := currentUID, currentUsername
	defer func() { currentUID, currentUsername = saveUID, saveName }()

	currentUID, currentUsername = 1234, ""
	if got := CurrentActor(); got != "uid:1234" {
		t.Fatalf("CurrentActor() fallback = %q, want uid:1234", got)
	}

	currentUID, currentUsername = -1, ""
	if got := CurrentActor(); got != "uid:-1" {
		t.Fatalf("CurrentActor() fallback = %q, want uid:-1", got)
	}

	currentUID, currentUsername = 0, "root"
	if got := CurrentActor(); got != "root" {
		t.Fatalf("CurrentActor() = %q, want root", got)
	}
}

func TestRecordSuccess(t *testing.T) {
	f := &fakeLogger{}
	r := New(f, "root")
	before := map[string]any{"active": true}
	after := map[string]any{"active": false}

	if err := r.Record(context.Background(), " domain.disable ", " example.com ", before, after); err != nil {
		t.Fatalf("Record returned error: %v", err)
	}
	if f.calls != 1 {
		t.Fatalf("Log called %d times, want 1", f.calls)
	}
	if f.actor != "root" || f.action != "domain.disable" || f.target != "example.com" {
		t.Fatalf("unexpected forwarded values: actor=%q action=%q target=%q", f.actor, f.action, f.target)
	}
	if f.ip != "" || f.ua != "" {
		t.Fatalf("console entry must have empty ip/ua, got ip=%q ua=%q", f.ip, f.ua)
	}
	if f.before == nil || f.after == nil {
		t.Fatal("before/after snapshots were dropped")
	}
}

func TestRecordNilSnapshots(t *testing.T) {
	f := &fakeLogger{}
	r := New(f, "root")
	if err := r.Record(context.Background(), "domain.add", "example.com", nil, nil); err != nil {
		t.Fatalf("Record returned error: %v", err)
	}
	if f.before != nil || f.after != nil {
		t.Fatalf("nil snapshots must pass through as nil, got before=%v after=%v", f.before, f.after)
	}
}

func TestRecordEmptyAction(t *testing.T) {
	f := &fakeLogger{}
	r := New(f, "root")
	err := r.Record(context.Background(), "   ", "example.com", nil, nil)
	if !errors.Is(err, errInvalid) {
		t.Fatalf("empty action: got %v, want errInvalid", err)
	}
	if f.calls != 0 {
		t.Fatal("Log must not be called for an invalid entry")
	}
}

func TestRecordNilLogger(t *testing.T) {
	r := New(nil, "root")
	err := r.Record(context.Background(), "domain.add", "example.com", nil, nil)
	if !errors.Is(err, ErrNoLogger) {
		t.Fatalf("nil logger: got %v, want ErrNoLogger", err)
	}

	var rNil *Recorder
	if err := rNil.Record(context.Background(), "x", "y", nil, nil); !errors.Is(err, ErrNoLogger) {
		t.Fatalf("nil recorder: got %v, want ErrNoLogger", err)
	}
	if rNil.Actor() != unknownActor {
		t.Fatalf("nil recorder Actor() = %q, want %q", rNil.Actor(), unknownActor)
	}
}

func TestRecordCanceledContext(t *testing.T) {
	f := &fakeLogger{}
	r := New(f, "root")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := r.Record(ctx, "domain.add", "example.com", nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ctx: got %v, want context.Canceled", err)
	}
	if f.calls != 0 {
		t.Fatal("Log must not be called once context is canceled")
	}
}

func TestRecordWrapsLoggerError(t *testing.T) {
	sentinel := errors.New("db down")
	f := &fakeLogger{err: sentinel}
	r := New(f, "root")
	err := r.Record(context.Background(), "domain.add", "example.com", nil, nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("Record must wrap logger error with %%w, got %v", err)
	}
	if !strings.Contains(err.Error(), "domain.add") {
		t.Fatalf("wrapped error should name the action, got %q", err.Error())
	}
}
