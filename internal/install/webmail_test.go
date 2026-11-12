package install

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"mailadmin/internal/config"
)

func testWebmail() config.Webmail {
	return config.Webmail{Enabled: true, Domain: "webmail.kiefer-networks.de",
		URL: "https://example.org/alps", SHA256: strings.Repeat("0", 64), Listen: "127.0.0.1:8081"}
}

func TestAlpsConfPointsAtLocalMailAndHelper(t *testing.T) {
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
		Webauthn struct {
			RPID    string   `toml:"rpid"`
			Origins []string `toml:"origins"`
		} `toml:"webauthn"`
		Plugin map[string]map[string]any `toml:"plugin"`
	}
	if _, err := toml.Decode(AlpsConf(testWebmail(), "mail.kiefer-networks.de"), &got); err != nil {
		t.Fatalf("alps config is not valid TOML: %v", err)
	}
	if got.Webauthn.RPID != "webmail.kiefer-networks.de" || len(got.Webauthn.Origins) != 1 || got.Webauthn.Origins[0] != "https://webmail.kiefer-networks.de" {
		t.Fatalf("webauthn = %+v, want rpid and origin of the webmail domain", got.Webauthn)
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
	for _, name := range []string{"base", "gpg", "managesieve", "password"} {
		if on, _ := got.Plugin[name]["enabled"].(bool); !on {
			t.Fatalf("plugin %s must stay enabled once plugin sections exist", name)
		}
	}
	// No CalDAV or CardDAV server exists, so those plugins must stay off.
	for _, name := range []string{"caldav", "carddav"} {
		if on, _ := got.Plugin[name]["enabled"].(bool); on {
			t.Fatalf("plugin %s must be disabled without a server", name)
		}
	}
	pw, _ := got.Plugin["password"]["options"].(map[string]any)
	cmd, _ := pw["command"].([]any)
	if len(cmd) != 5 || cmd[0] != "/usr/bin/sudo" || cmd[4] != "{email}" || cmd[3] != "webmail-passwd" {
		t.Fatalf("password command = %v", cmd)
	}
	if stdin, _ := pw["stdin"].(string); stdin != "{old_password}\n{new_password}\n" {
		t.Fatalf("password stdin = %q", stdin)
	}
}

func TestSudoersAllowsOnlyTheHelper(t *testing.T) {
	out := AlpsSudoersFile()
	if !strings.Contains(out, "alps ALL=(root) NOPASSWD: "+PasswordHelper+" webmail-passwd *") {
		t.Fatalf("sudoers rule:\n%s", out)
	}
	if strings.Count(out, "NOPASSWD") != 1 {
		t.Fatalf("more than one rule:\n%s", out)
	}
}

func TestCaddyWebmailRoutesDomain(t *testing.T) {
	out := CaddyWebmailFile(testWebmail())
	if !strings.Contains(out, "webmail.kiefer-networks.de {") || !strings.Contains(out, "reverse_proxy 127.0.0.1:8081") {
		t.Fatalf("route missing:\n%s", out)
	}
}

func TestApplyWebmailRefusesBadChecksumBeforeAnyChange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not the pinned binary"))
	}))
	defer srv.Close()
	w := testWebmail()
	w.URL = srv.URL + "/alps"
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

// The managed Dovecot config enables IMAP METADATA, which alps needs.
func TestDovecotConfEnablesMetadata(t *testing.T) {
	conf := DovecotConf(nil)
	for _, want := range []string{"mail_attribute {", "path = %{home}/dovecot-attributes", "imap_metadata = yes"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("managed dovecot config lacks %q", want)
		}
	}
}

// Clients need the default folders with their SPECIAL-USE attributes.
func TestDovecotConfCreatesDefaultFolders(t *testing.T) {
	conf := DovecotConf(nil)
	for _, want := range []string{"namespace inbox {", "mailbox Sent {", "special_use = \\Sent", "special_use = \\Drafts", "special_use = \\Archive"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("managed dovecot config lacks %q", want)
		}
	}
}
