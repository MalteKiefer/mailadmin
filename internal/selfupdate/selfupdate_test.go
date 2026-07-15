package selfupdate

import "testing"

func TestIsNewer(t *testing.T) {
	cases := []struct {
		current, latest string
		want            bool
	}{
		{"1.13.1", "1.13.2", true},
		{"1.13.1", "1.14.0", true},
		{"1.13.1", "2.0.0", true},
		{"1.13.1", "v1.13.2", true},
		{"1.13.2", "1.13.2", false},
		{"1.13.2", "1.13.1", false},
		{"2.0.0", "1.99.99", false},
		{"dev", "1.0.0", true},          // non-semver current -> older
		{"1.0.0", "nightly", false},     // non-semver latest -> not newer
		{"1.13.1", "1.13.2-rc1", true},  // pre-release suffix ignored
		{"1.13.1-rc1", "1.13.1", false}, // suffix stripped -> equal
	}
	for _, tc := range cases {
		if got := IsNewer(tc.current, tc.latest); got != tc.want {
			t.Errorf("IsNewer(%q, %q) = %v, want %v", tc.current, tc.latest, got, tc.want)
		}
	}
}

func TestParseChecksums(t *testing.T) {
	body := "abc123  mailadmin-linux-amd64\n" +
		"def456 *mailadmin-linux-arm64\n" +
		"garbage line\n"
	if got := parseChecksums(body, "mailadmin-linux-amd64"); got != "abc123" {
		t.Errorf("amd64 = %q, want abc123", got)
	}
	if got := parseChecksums(body, "mailadmin-linux-arm64"); got != "def456" {
		t.Errorf("arm64 (star marker) = %q, want def456", got)
	}
	if got := parseChecksums(body, "missing"); got != "" {
		t.Errorf("missing = %q, want empty", got)
	}
}

func TestAssetName(t *testing.T) {
	if AssetName() == "" {
		t.Fatal("AssetName empty")
	}
}
