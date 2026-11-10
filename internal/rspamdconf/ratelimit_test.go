package rspamdconf

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateRate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"20 / 1m", "20 / 1m", false},
		{"20/1m", "20 / 1m", false},
		{"20   /   1m", "20 / 1m", false},
		{"5 / 1h", "5 / 1h", false},
		{"5.5 / 1h", "5.5 / 1h", false},
		{"1000 / 1d", "1000 / 1d", false},
		{"1 / 1w", "", true}, // rspamd has no week unit
		{"1 / 7d", "1 / 7d", false},
		{"", "", true},
		{"20", "", true},
		{"20 / 1min", "", true}, // word units not accepted, see doc comment
		{"20 / m", "", true},
		{"-5 / 1m", "", true},
		{"20 / 1x", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := ValidateRate(tt.in)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidRate) {
					t.Fatalf("err = %v, want ErrInvalidRate", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsBucket(t *testing.T) {
	t.Parallel()
	for _, b := range RatelimitBuckets {
		if !IsBucket(b) {
			t.Fatalf("IsBucket(%q) = false, want true", b)
		}
	}
	if IsBucket("not_a_bucket") {
		t.Fatal("IsBucket(not_a_bucket) = true, want false")
	}
}

func writeTemp(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
}

func TestReadRatelimit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTemp(t, dir, RatelimitFile, "rates {\n  to = \"20 / 1min\";\n  bounce_to_ip = \"10 / 1h\";\n}\n")

	got, err := ReadRatelimit(dir)
	if err != nil {
		t.Fatalf("ReadRatelimit: %v", err)
	}
	want := map[string]string{"to": "20 / 1min", "bounce_to_ip": "10 / 1h"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("got[%q] = %q, want %q", k, got[k], v)
		}
	}
	// Buckets absent from the file must not appear.
	if _, ok := got["to_ip"]; ok {
		t.Fatal("to_ip should be absent (not set in file)")
	}
}

func TestReadRatelimitMissingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// rspamd ships no local.d/ratelimit.conf: a missing file means defaults.
	got, err := ReadRatelimit(dir)
	if err != nil || len(got) != 0 {
		t.Fatalf("missing file: got %v, %v; want no settings and no error", got, err)
	}
}

func TestSetRatelimitUnknownBucket(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTemp(t, dir, RatelimitFile, "rates {\n}\n")
	if _, _, err := SetRatelimit(dir, "not_a_bucket", "20 / 1m"); !errors.Is(err, ErrUnknownBucket) {
		t.Fatalf("err = %v, want ErrUnknownBucket", err)
	}
}

func TestSetRatelimitInvalidRate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTemp(t, dir, RatelimitFile, "rates {\n}\n")
	if _, _, err := SetRatelimit(dir, "to", "not-a-rate"); !errors.Is(err, ErrInvalidRate) {
		t.Fatalf("err = %v, want ErrInvalidRate", err)
	}
}

func TestSetRatelimitUpdatesExistingBucketPreservingRest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	original := "# tuned by ops\nrates {\n  to = \"20 / 1min\"; # legacy comment\n  to_ip = \"20 / 1min\";\n}\n"
	writeTemp(t, dir, RatelimitFile, original)

	oldContent, oldValue, err := SetRatelimit(dir, "to", "50 / 1m")
	if err != nil {
		t.Fatalf("SetRatelimit: %v", err)
	}
	if string(oldContent) != original {
		t.Fatalf("oldContent mismatch:\n got: %q\nwant: %q", oldContent, original)
	}
	if oldValue != "20 / 1min" {
		t.Fatalf("oldValue = %q, want %q", oldValue, "20 / 1min")
	}

	got, err := os.ReadFile(filepath.Join(dir, RatelimitFile))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	want := "# tuned by ops\nrates {\n  to = \"50 / 1m\"; # legacy comment\n  to_ip = \"20 / 1min\";\n}\n"
	if string(got) != want {
		t.Fatalf("file content =\n%q\nwant\n%q", got, want)
	}
}

func TestSetRatelimitCreatesMissingBucket(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTemp(t, dir, RatelimitFile, "rates {\n  to = \"20 / 1min\";\n}\n")

	_, oldValue, err := SetRatelimit(dir, "bounce_to", "5 / 1h")
	if err != nil {
		t.Fatalf("SetRatelimit: %v", err)
	}
	if oldValue != "" {
		t.Fatalf("oldValue = %q, want empty", oldValue)
	}

	values, err := ReadRatelimit(dir)
	if err != nil {
		t.Fatalf("ReadRatelimit: %v", err)
	}
	if values["bounce_to"] != "5 / 1h" {
		t.Fatalf("bounce_to = %q, want %q", values["bounce_to"], "5 / 1h")
	}
	if values["to"] != "20 / 1min" {
		t.Fatalf("to = %q, want unchanged %q", values["to"], "20 / 1min")
	}
}

func TestRestoreFileRollsBackContent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	original := "rates {\n  to = \"20 / 1min\";\n}\n"
	writeTemp(t, dir, RatelimitFile, original)

	oldContent, _, err := SetRatelimit(dir, "to", "999 / 1m")
	if err != nil {
		t.Fatalf("SetRatelimit: %v", err)
	}

	// Simulate a failed post-write validation: roll back.
	if err := RestoreFile(RatelimitPath(dir), oldContent); err != nil {
		t.Fatalf("RestoreFile: %v", err)
	}

	got, err := os.ReadFile(RatelimitPath(dir))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != original {
		t.Fatalf("file content after rollback = %q, want %q", got, original)
	}
}
