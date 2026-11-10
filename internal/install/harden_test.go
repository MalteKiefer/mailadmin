package install

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTLSGroupsNeedOpenSSL35ForMLKEM(t *testing.T) {
	if g := TLSGroups("OpenSSL 3.5.7 9 Jun 2026"); g[0] != "X25519MLKEM768" {
		t.Fatalf("OpenSSL 3.5 must prefer X25519MLKEM768, got %v", g)
	}
	for _, v := range []string{"OpenSSL 3.0.13 30 Jan 2024", "", "garbage"} {
		for _, g := range TLSGroups(v) {
			if g == "X25519MLKEM768" {
				t.Fatalf("%q must not offer X25519MLKEM768: older OpenSSL rejects the name", v)
			}
		}
	}
}

func TestSSHHardeningConfKeepsPasswordLoginWithoutKeys(t *testing.T) {
	caps := SSHCaps{Version: "OpenSSH_10.0p2 Debian-7", Kex: map[string]bool{"mlkem768x25519-sha256": true, "curve25519-sha256": true, "diffie-hellman-group14-sha1": true},
		Ciphers: map[string]bool{"chacha20-poly1305@openssh.com": true, "aes128-ctr": true},
		MACs:    map[string]bool{"hmac-sha2-512-etm@openssh.com": true, "hmac-sha1": true},
		KeySigs: map[string]bool{"ssh-ed25519": true, "rsa-sha2-512": true, "ssh-rsa": true}}
	on := SSHHardeningConf(caps, true, true, []string{"/etc/ssh/ssh_host_ed25519_key"})
	for _, want := range []string{"PasswordAuthentication no\n", "AuthenticationMethods publickey\n", "PermitRootLogin prohibit-password\n",
		"KexAlgorithms mlkem768x25519-sha256,curve25519-sha256\n", "Ciphers chacha20-poly1305@openssh.com\n",
		"MACs hmac-sha2-512-etm@openssh.com\n", "RequiredRSASize 3072\n", "HostKey /etc/ssh/ssh_host_ed25519_key\n", "X11Forwarding no\n"} {
		if !strings.Contains(on, want) {
			t.Errorf("hardened config misses %q:\n%s", want, on)
		}
	}
	for _, weak := range []string{"diffie-hellman-group14-sha1", "aes128-ctr", "hmac-sha1", "ssh-rsa,", "ssh-rsa\n"} {
		if strings.Contains(on, weak) {
			t.Errorf("weak algorithm %q must not be offered:\n%s", weak, on)
		}
	}
	off := SSHHardeningConf(caps, false, false, nil)
	if strings.Contains(off, "PasswordAuthentication no") || strings.Contains(off, "AuthenticationMethods") ||
		strings.Contains(off, "PermitRootLogin") {
		t.Fatalf("without a usable key, password login (root included) must stay on:\n%s", off)
	}
	old := SSHHardeningConf(SSHCaps{Version: "OpenSSH_8.9p1"}, true, true, nil)
	if strings.Contains(old, "RequiredRSASize") || strings.Contains(old, "KexAlgorithms") {
		t.Fatalf("options sshd 8.9 does not know, or empty lists, must be left out:\n%s", old)
	}
}

func TestAuthorizedKeyIn(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	comment := filepath.Join(dir, "comment")
	key := filepath.Join(dir, "key")
	_ = os.WriteFile(empty, nil, 0o600)
	_ = os.WriteFile(comment, []byte("# nothing\n\n"), 0o600)
	_ = os.WriteFile(key, []byte("ssh-ed25519 AAAAC3Nza test\n"), 0o600)
	if authorizedKeyIn([]string{empty, comment, filepath.Join(dir, "missing")}) {
		t.Fatal("no key line means no key")
	}
	if !authorizedKeyIn([]string{empty, key}) {
		t.Fatal("a key line must be found")
	}
}

// rsaKey builds an ssh-rsa public key blob with a modulus of the given size.
func rsaKey(bits int) string {
	n := make([]byte, bits/8)
	n[0] = 0x80
	var blob []byte
	for _, part := range [][]byte{[]byte("ssh-rsa"), {1, 0, 1}, append([]byte{0}, n...)} {
		blob = append(blob, byte(len(part)>>24), byte(len(part)>>16), byte(len(part)>>8), byte(len(part)))
		blob = append(blob, part...)
	}
	return base64.StdEncoding.EncodeToString(blob)
}

func TestUsableKeyMatchesHardenedSSHD(t *testing.T) {
	for line, want := range map[string]bool{
		"ssh-ed25519 AAAA x":                                  true,
		"ecdsa-sha2-nistp256 AAAA x":                          true,
		"sk-ecdsa-sha2-nistp256@openssh.com AAAA yubikey":     true,
		"ssh-rsa " + rsaKey(4096) + " big":                    true,
		"ssh-rsa " + rsaKey(2048) + " small":                  false,
		`command="/usr/bin/rrsync /srv" ssh-ed25519 AAAA bkp`: false,
		"restrict,port-forwarding ssh-ed25519 AAAA tunnel":    false,
		`from="10.0.0.1" ssh-ed25519 AAAA admin`:              true,
		"ssh-dss AAAA old":                                    false,
	} {
		if got := usableKey(line); got != want {
			t.Errorf("usableKey(%.40q) = %v, want %v", line, got, want)
		}
	}
	// Every accepted key type must also be in PubkeyAcceptedAlgorithms.
	accepted := strings.Join(sshUserSig, ",")
	for typ := range loginKeyTypes {
		if typ == "ssh-rsa" {
			continue // signed with rsa-sha2-256/512
		}
		if !strings.Contains(accepted, typ) {
			t.Errorf("usableKey accepts %s but sshd would refuse it", typ)
		}
	}
}

func TestSetDefsReplacesAndAppends(t *testing.T) {
	in := "# comment\nUMASK\t\t022\n#PASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0\nPASS_MIN_DAYS 5\n"
	got := SetDefs(in, [][2]string{{"UMASK", "027"}, {"PASS_MAX_DAYS", "365"}, {"PASS_MIN_DAYS", "1"}, {"PASS_WARN_AGE", "14"}})
	for _, want := range []string{"UMASK\t027\n", "PASS_MAX_DAYS\t365\n", "PASS_MIN_DAYS\t1\n", "# PASS_MIN_DAYS 5\n", "PASS_WARN_AGE\t14\n", "# comment\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Count(got, "UMASK") != 1 {
		t.Errorf("UMASK must appear once:\n%s", got)
	}
}

func TestHardenedMailTLS(t *testing.T) {
	groups := TLSGroups("OpenSSL 3.5.0")
	settings := map[string]string{}
	for _, s := range PostfixSettings("mx.example.com", groups) {
		settings[s.Key] = s.Value
	}
	for k, v := range map[string]string{
		"smtpd_tls_protocols": ">=TLSv1.2", "smtp_tls_protocols": ">=TLSv1.2",
		"smtpd_tls_mandatory_ciphers": "high", "tls_high_cipherlist": TLS12Ciphers,
		"tls_preempt_cipherlist": "yes", "tls_eecdh_auto_curves": "X25519MLKEM768 X25519 prime256v1 secp384r1",
		"smtpd_banner": "$myhostname ESMTP",
	} {
		if settings[k] != v {
			t.Errorf("postfix %s = %q, want %q", k, settings[k], v)
		}
	}
	d := DovecotConf(groups)
	for _, want := range []string{"ssl_cipher_list = " + TLS12Ciphers, "ssl_cipher_suites = " + TLS13Suites,
		"ssl_curve_list = X25519MLKEM768:X25519:prime256v1:secp384r1", "ssl_server_prefer_ciphers = server",
		"inet_listener imap {\n    port = 0", "protocol lmtp {\n  mail_plugins {\n    quota = yes\n    sieve = yes",
		"sieve_script personal {", `quota "User quota" {`, "AS quota_storage_size"} {
		if !strings.Contains(d, want) {
			t.Errorf("dovecot.conf misses %q", want)
		}
	}
	for _, suite := range strings.Split(TLS12Ciphers, ":") {
		aead := strings.Contains(suite, "-GCM-") || strings.Contains(suite, "CHACHA20-POLY1305")
		if !strings.HasPrefix(suite, "ECDHE-") || !aead {
			t.Errorf("TLS 1.2 list must hold only ECDHE AEAD suites, found %q", suite)
		}
	}
}

func TestModprobeBlocksUnusedModules(t *testing.T) {
	m := ModprobeHardening()
	for _, mod := range []string{"usb-storage", "dccp", "sctp", "cramfs"} {
		if !strings.Contains(m, "install "+mod+" /bin/false\n") {
			t.Errorf("module %s not blocked", mod)
		}
	}
}

func TestCrowdSecReplacesFail2ban(t *testing.T) {
	for _, p := range HardeningPackages() {
		if p == "fail2ban" {
			t.Fatal("fail2ban must not be installed next to CrowdSec")
		}
	}
	a := CrowdSecAcquis()
	for _, unit := range []string{"postfix.service", "postfix@-.service", "dovecot.service"} {
		if !strings.Contains(a, "_SYSTEMD_UNIT="+unit) {
			t.Errorf("acquisition misses %s", unit)
		}
	}
	if strings.Contains(a, "ssh.service") {
		t.Error("cscli setup already reads ssh.service; a second source counts every failure twice")
	}
	u := UnattendedUpgrades()
	for _, site := range []string{"apt.postgresql.org", "dl.cloudsmith.io", "packagecloud.io"} {
		if !strings.Contains(u, `"site=`+site+`";`) {
			t.Errorf("unattended-upgrades misses vendor site %s:\n%s", site, u)
		}
	}
	if _, ok := hardeningFiles()[CrowdSecAcquisPath]; !ok {
		t.Fatal("acquisition file not written")
	}
}

func TestSetBouncerKey(t *testing.T) {
	conf := "mode: nftables\napi_url: http://127.0.0.1:8080/\napi_key: ${API_KEY}\nlog_mode: file\n"
	got, err := SetBouncerKey(conf, "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "\napi_key: abc123\n") || strings.Contains(got, "${API_KEY}") || !strings.Contains(got, "log_mode: file") {
		t.Fatalf("key not replaced cleanly:\n%s", got)
	}
	if _, err := SetBouncerKey("mode: nftables\n", "k"); err == nil {
		t.Fatal("a config without api_key must be refused")
	}
}

func TestSetShellVar(t *testing.T) {
	if got := SetShellVar("# x\nENABLED=\"false\"\nHISTORY=7\n", "ENABLED", `"true"`); got != "# x\nENABLED=\"true\"\nHISTORY=7\n" {
		t.Fatalf("replace: %q", got)
	}
	if got := SetShellVar("HISTORY=7", "ENABLED", `"true"`); got != "HISTORY=7\nENABLED=\"true\"\n" {
		t.Fatalf("append: %q", got)
	}
}
