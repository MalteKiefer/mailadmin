package rspamdconf

import (
	"errors"
	"os"
	"testing"
)

func TestIsGreylistSetting(t *testing.T) {
	t.Parallel()
	for _, s := range GreylistSettings {
		if !IsGreylistSetting(s) {
			t.Fatalf("IsGreylistSetting(%q) = false, want true", s)
		}
	}
	if IsGreylistSetting("whitelist") {
		t.Fatal("IsGreylistSetting(whitelist) = true, want false (out of scope)")
	}
}

func TestReadGreylist(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTemp(t, dir, GreylistFile, "# greylist tuning\ntimeout = 300s;\nexpire = 1d;\n")

	got, err := ReadGreylist(dir)
	if err != nil {
		t.Fatalf("ReadGreylist: %v", err)
	}
	if got["timeout"] != "300s" || got["expire"] != "1d" {
		t.Fatalf("got %v", got)
	}
}

func TestReadGreylistPartialFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTemp(t, dir, GreylistFile, "# only timeout tuned\ntimeout = 5m;\n")

	got, err := ReadGreylist(dir)
	if err != nil {
		t.Fatalf("ReadGreylist: %v", err)
	}
	if got["timeout"] != "5m" {
		t.Fatalf("timeout = %q, want 5m", got["timeout"])
	}
	if _, ok := got["expire"]; ok {
		t.Fatal("expire should be absent (not set in file)")
	}
}

func TestSetGreylistUnknownSetting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTemp(t, dir, GreylistFile, "timeout = 300s;\n")
	if _, _, err := SetGreylist(dir, "not_a_setting", "1h"); !errors.Is(err, ErrUnknownSetting) {
		t.Fatalf("err = %v, want ErrUnknownSetting", err)
	}
}

func TestSetGreylistUpdatesExistingPreservingRest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	original := "# ops-tuned greylist config\ntimeout = 300s; # 5 minutes\nexpire = 1d;\nwhitelist = \"/etc/rspamd/greylist_whitelist.map\";\n"
	writeTemp(t, dir, GreylistFile, original)

	oldContent, oldValue, err := SetGreylist(dir, "timeout", "10m")
	if err != nil {
		t.Fatalf("SetGreylist: %v", err)
	}
	if string(oldContent) != original {
		t.Fatalf("oldContent mismatch")
	}
	if oldValue != "300s" {
		t.Fatalf("oldValue = %q, want 300s", oldValue)
	}

	got, err := os.ReadFile(GreylistPath(dir))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	want := "# ops-tuned greylist config\ntimeout = 10min; # 5 minutes\nexpire = 1d;\nwhitelist = \"/etc/rspamd/greylist_whitelist.map\";\n"
	if string(got) != want {
		t.Fatalf("file content =\n%q\nwant\n%q", got, want)
	}
}

func TestSetGreylistCreatesMissingSetting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTemp(t, dir, GreylistFile, "# defaults apply\n")

	_, oldValue, err := SetGreylist(dir, "expire", "2d")
	if err != nil {
		t.Fatalf("SetGreylist: %v", err)
	}
	if oldValue != "" {
		t.Fatalf("oldValue = %q, want empty", oldValue)
	}

	got, err := ReadGreylist(dir)
	if err != nil {
		t.Fatalf("ReadGreylist: %v", err)
	}
	if got["expire"] != "2d" {
		t.Fatalf("expire = %q, want 2d", got["expire"])
	}
}

func TestUCLDurationMinutes(t *testing.T) {
	for in, want := range map[string]string{"5m": "5min", "300s": "300s", "2h": "2h", "1d": "1d"} {
		if got := uclDuration(in); got != want {
			t.Errorf("uclDuration(%q) = %q, want %q", in, got, want)
		}
	}
}
