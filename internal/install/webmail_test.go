package install

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"mailadmin/internal/config"
)

func testWebmail() config.Webmail {
	return config.Webmail{Enabled: true, Domain: "webmail.kiefer-networks.de", Version: "v1",
		SHA256: strings.Repeat("0", 64), Listen: "127.0.0.1:8081"}
}

// releaseZip builds a zip shaped like the upstream release: the binary plus a
// macOS metadata entry that must be ignored.
func releaseZip(t *testing.T, bin []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string][]byte{
		"__MACOSX/._alps-linux-amd64": []byte("meta"),
		"alps-linux-amd64":            bin,
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestAlpsConfPointsAtLocalMail(t *testing.T) {
	var got struct {
		Server struct {
			Addr           string   `toml:"addr"`
			TrustedOrigins []string `toml:"trusted_origins"`
		} `toml:"server"`
		Provider struct {
			Imap struct {
				Server string `toml:"server"`
			} `toml:"imap"`
		} `toml:"provider"`
		Smtp struct {
			Server string `toml:"server"`
		} `toml:"smtp"`
	}
	if _, err := toml.Decode(AlpsConf(testWebmail(), "mail.kiefer-networks.de"), &got); err != nil {
		t.Fatalf("alps config is not valid TOML: %v", err)
	}
	if got.Server.Addr != "127.0.0.1:8081" {
		t.Fatalf("addr = %q", got.Server.Addr)
	}
	if len(got.Server.TrustedOrigins) != 1 || got.Server.TrustedOrigins[0] != "https://webmail.kiefer-networks.de" {
		t.Fatalf("trusted_origins = %v", got.Server.TrustedOrigins)
	}
	if got.Provider.Imap.Server != "imaps://mail.kiefer-networks.de:993" || got.Smtp.Server != "smtps://mail.kiefer-networks.de:465" {
		t.Fatalf("mail endpoints = %q, %q", got.Provider.Imap.Server, got.Smtp.Server)
	}
}

func TestCaddyWebmailRoutesDomain(t *testing.T) {
	out := CaddyWebmailFile(testWebmail())
	if !strings.Contains(out, "webmail.kiefer-networks.de {") || !strings.Contains(out, "reverse_proxy 127.0.0.1:8081") {
		t.Fatalf("route missing:\n%s", out)
	}
}

func TestExtractAlpsChecksumAndEntry(t *testing.T) {
	zipData := releaseZip(t, []byte("ALPS-BINARY"))
	sum := sha256Hex(zipData)
	bin, err := ExtractAlps(zipData, sum)
	if err != nil {
		t.Fatalf("ExtractAlps: %v", err)
	}
	if string(bin) != "ALPS-BINARY" {
		t.Fatalf("binary = %q", bin)
	}
	if _, err := ExtractAlps(zipData, strings.Repeat("f", 64)); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("wrong checksum must be refused, got %v", err)
	}
}

func TestApplyWebmailRefusesBadChecksumBeforeAnyChange(t *testing.T) {
	zipData := releaseZip(t, []byte("ALPS-BINARY"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipData)
	}))
	defer srv.Close()
	old := alpsReleaseBase
	alpsReleaseBase = srv.URL
	defer func() { alpsReleaseBase = old }()

	w := testWebmail() // pinned sum is all zeros, so the real release never matches
	x := &fakeExec{}
	err := ApplyWebmail(context.Background(), x, w, "mail.kiefer-networks.de")
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("ApplyWebmail must refuse a bad checksum, got %v", err)
	}
	if _, serr := os.Stat(AlpsBin); serr == nil {
		t.Fatal("binary written despite checksum mismatch")
	}
	if len(x.calls) != 0 {
		t.Fatalf("commands run despite checksum mismatch: %v", x.calls)
	}
}

func TestApplyWebmailDisabledDoesNothing(t *testing.T) {
	x := &fakeExec{}
	if err := ApplyWebmail(context.Background(), x, config.Webmail{}, "mail.kiefer-networks.de"); err != nil {
		t.Fatal(err)
	}
	if len(x.calls) != 0 {
		t.Fatalf("disabled webmail ran commands: %v", x.calls)
	}
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// The webmail needs IMAP METADATA; the managed Dovecot config must enable it.
func TestDovecotConfEnablesMetadata(t *testing.T) {
	conf := DovecotConf(nil)
	for _, want := range []string{"mail_attribute {", "path = %{home}/dovecot-attributes", "imap_metadata = yes"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("managed dovecot config lacks %q", want)
		}
	}
}
