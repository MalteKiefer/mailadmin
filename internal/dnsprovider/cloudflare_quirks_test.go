package dnsprovider

import "testing"

func TestCloudflareTXTAndTLSA(t *testing.T) {
	r := cfToRecord(cfRecord{Type: "TXT", Name: "example.com", Content: `"v=spf1 mx -all"`}, "example.com")
	if r.Content != "v=spf1 mx -all" {
		t.Fatalf("TXT content = %q, want unquoted", r.Content)
	}
	b := cfBody(Record{Type: "TLSA", Name: "_25._tcp.mx", Content: "3 1 1 abcdef"}, "example.com")
	d, ok := b["data"].(map[string]any)
	if !ok || d["usage"] != 3 || d["selector"] != 1 || d["matching_type"] != 1 || d["certificate"] != "abcdef" {
		t.Fatalf("TLSA body = %v", b)
	}
	if _, has := b["content"]; has {
		t.Fatal("TLSA must not send content")
	}
}
