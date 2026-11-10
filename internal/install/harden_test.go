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
	on := SSHHardeningConf(caps, SSHPolicy{KeyOnly: true, RootKeyOnly: true, StrictRSA: true}, []string{"/etc/ssh/ssh_host_ed25519_key"})
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
	off := SSHHardeningConf(caps, SSHPolicy{}, nil)
	if strings.Contains(off, "PasswordAuthentication no") || strings.Contains(off, "AuthenticationMethods") ||
		strings.Contains(off, "PermitRootLogin") || strings.Contains(off, "RequiredRSASize") {
		t.Fatalf("without a usable key, password login (root included) must stay on:\n%s", off)
	}
	old := SSHHardeningConf(SSHCaps{Version: "OpenSSH_8.9p1"}, SSHPolicy{KeyOnly: true, RootKeyOnly: true, StrictRSA: true}, nil)
	if strings.Contains(old, "RequiredRSASize") || strings.Contains(old, "KexAlgorithms") {
		t.Fatalf("options sshd 8.9 does not know, or empty lists, must be left out:\n%s", old)
	}
}

func TestReadAuthorizedKeys(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "authorized_keys")
	ed := base64.StdEncoding.EncodeToString([]byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x01k"))
	_ = os.WriteFile(p, []byte("# comment\n\nssh-ed25519 "+ed+" me\nssh-rsa "+rsaKey(2048)+" old\n"), 0o600)
	keys := readAuthorizedKeys(p)
	if len(keys) != 2 || !keys[0].usable || keys[1].usable || keys[1].rsaBits != 2048 ||
		!strings.HasPrefix(keys[0].fingerprint, "SHA256:") {
		t.Fatalf("keys = %+v", keys)
	}
	if readAuthorizedKeys(filepath.Join(dir, "missing")) != nil {
		t.Fatal("a missing file has no keys")
	}
}

func TestDecideSSHPolicyFollowsTheActualLogin(t *testing.T) {
	ed := authKey{fingerprint: "SHA256:ed", usable: true}
	backup := authKey{fingerprint: "SHA256:backup", usable: true}
	weakRSA := authKey{fingerprint: "SHA256:rsa", usable: false, rsaBits: 2048}
	key := func(fp, typ string) sshLogin { return sshLogin{method: "publickey", keyType: typ, fingerprint: fp} }
	cases := []struct {
		name    string
		account string
		known   bool
		keys    []authKey
		root    []authKey
		logins  map[string]sshLogin
		want    SSHPolicy
	}{
		{"root with its own key", "root", true, []authKey{ed}, []authKey{ed},
			map[string]sshLogin{"root": key("SHA256:ed", "ED25519")}, SSHPolicy{KeyOnly: true, RootKeyOnly: true, StrictRSA: true}},
		{"root by password, backup key present", "root", true, []authKey{backup}, []authKey{backup},
			map[string]sshLogin{"root": {method: "password"}}, SSHPolicy{KeyOnly: false, RootKeyOnly: false, StrictRSA: true}},
		{"admin by key, root has none", "admin", true, []authKey{ed}, nil,
			map[string]sshLogin{"admin": key("SHA256:ed", "ED25519")}, SSHPolicy{KeyOnly: true, RootKeyOnly: true, StrictRSA: true}},
		{"admin by password", "admin", true, []authKey{ed}, nil,
			map[string]sshLogin{"admin": {method: "password"}}, SSHPolicy{KeyOnly: false, RootKeyOnly: true, StrictRSA: true}},
		{"key from another file", "admin", true, []authKey{ed}, nil,
			map[string]sshLogin{"admin": key("SHA256:other", "ED25519")}, SSHPolicy{KeyOnly: false, RootKeyOnly: true, StrictRSA: true}},
		{"weak RSA in use keeps RSA", "admin", true, []authKey{weakRSA}, nil,
			map[string]sshLogin{"admin": key("SHA256:rsa", "RSA")}, SSHPolicy{KeyOnly: false, RootKeyOnly: true, StrictRSA: false}},
		{"root used an unknown RSA key", "admin", true, []authKey{ed}, nil,
			map[string]sshLogin{"admin": key("SHA256:ed", "ED25519"), "root": key("SHA256:x", "RSA")}, SSHPolicy{KeyOnly: true, RootKeyOnly: true, StrictRSA: false}},
		{"no login uid", "", false, nil, []authKey{ed},
			map[string]sshLogin{"root": key("SHA256:ed", "ED25519")}, SSHPolicy{KeyOnly: false, RootKeyOnly: false, StrictRSA: true}},
		{"no journal entry", "admin", true, []authKey{ed}, nil, map[string]sshLogin{}, SSHPolicy{KeyOnly: false, RootKeyOnly: true, StrictRSA: true}},
	}
	for _, c := range cases {
		if got := decideSSHPolicy(c.account, c.known, c.keys, c.root, c.logins); got != c.want {
			t.Errorf("%s: policy = %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestAcceptedLineParsing(t *testing.T) {
	m := acceptedRe.FindStringSubmatch("Accepted publickey for root from 203.0.113.7 port 51234 ssh2: ED25519 SHA256:abcDEF+/x")
	if m == nil || m[1] != "publickey" || m[2] != "root" || m[3] != "ED25519" || m[4] != "SHA256:abcDEF+/x" {
		t.Fatalf("match = %q", m)
	}
	if m := acceptedRe.FindStringSubmatch("Accepted password for admin from 2001:db8::1 port 2 ssh2"); m == nil || m[1] != "password" || m[2] != "admin" {
		t.Fatalf("password match = %q", m)
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
		"sieve_script personal {", `quota "User quota" {`, "AS quota_storage_size", "sql_iterate_query = SELECT username || '@' || domain AS user"} {
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
	both := CrowdSecAcquis(false, false)
	for _, unit := range []string{"ssh.service", "postfix.service", "postfix@-.service", "dovecot.service"} {
		if !strings.Contains(both, "_SYSTEMD_UNIT="+unit) {
			t.Errorf("acquisition misses %s", unit)
		}
	}
	if a := CrowdSecAcquis(true, false); strings.Contains(a, "ssh.service") || !strings.Contains(a, "dovecot.service") {
		t.Errorf("sshd already read elsewhere must not be added again:\n%s", a)
	}
	if CrowdSecAcquis(true, true) != "" {
		t.Error("nothing missing must give an empty acquisition")
	}
	etc := t.TempDir()
	_ = os.MkdirAll(filepath.Join(etc, "acquis.d"), 0o755)
	_ = os.WriteFile(filepath.Join(etc, "acquis.d", "setup.sshd.yaml"), []byte("journalctl_filter:\n  - _SYSTEMD_UNIT=ssh.service\n"), 0o644)
	_ = os.WriteFile(filepath.Join(etc, "acquis.d", "setup.postfix.yaml"), []byte("filenames:\n  - /nonexistent/mail.log\n"), 0o644)
	_ = os.WriteFile(filepath.Join(etc, "acquis.d", "mailadmin.yaml"), []byte("_SYSTEMD_UNIT=postfix.service\n"), 0o644)
	if ssh, mail := crowdSecCoverage(etc); !ssh || mail {
		t.Errorf("coverage = ssh %v mail %v, want true false (own file and missing log files do not count)", ssh, mail)
	}
	u := UnattendedUpgrades()
	for _, site := range []string{"apt.postgresql.org", "dl.cloudsmith.io", "packagecloud.io"} {
		if !strings.Contains(u, `"site=`+site+`";`) {
			t.Errorf("unattended-upgrades misses vendor site %s:\n%s", site, u)
		}
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

func TestOperatorSSHKeepsStricterSettings(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "10-site.conf")
	_ = os.WriteFile(a, []byte("PermitRootLogin no # site rule\nMatch User x\nAuthenticationMethods any\n"), 0o600)
	b := filepath.Join(dir, "sshd_config")
	_ = os.WriteFile(b, []byte("PermitRootLogin yes\nAuthenticationMethods publickey,keyboard-interactive\n"), 0o600)
	prl, am := operatorSSH([]string{a, b})
	if prl != "no" || am != "publickey,keyboard-interactive" {
		t.Fatalf("got %q %q", prl, am)
	}
	conf := SSHHardeningConf(SSHCaps{}, SSHPolicy{KeyOnly: true, RootLoginNo: true, AuthMethods: am}, nil)
	for _, want := range []string{"PermitRootLogin no\n", "AuthenticationMethods publickey,keyboard-interactive\n"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "KbdInteractiveAuthentication no") {
		t.Error("keyboard-interactive is a required factor and must stay on")
	}
}
