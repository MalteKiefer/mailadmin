package install

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"mailadmin/internal/security"
)

// The hardening install applies follows the BSI IT-Grundschutz module SYS.1.3
// (Linux server) and the CIS Debian Linux Benchmark, Level 1 and Level 2, where a
// control fits a dedicated mail host. docs/HARDENING.md lists every control and the
// deliberate deviations.
const (
	SSHHardeningPath      = "/etc/ssh/sshd_config.d/00-mailadmin-hardening.conf"
	SysctlHardeningPath   = "/etc/sysctl.d/90-mailadmin-hardening.conf"
	ModprobeHardeningPath = "/etc/modprobe.d/mailadmin-hardening.conf"
	LimitsHardeningPath   = "/etc/security/limits.d/90-mailadmin.conf"
	CoredumpConfPath      = "/etc/systemd/coredump.conf.d/90-mailadmin.conf"
	JournaldConfPath      = "/etc/systemd/journald.conf.d/90-mailadmin.conf"
	AuditRulesPath        = "/etc/audit/rules.d/90-mailadmin.rules"
	CrowdSecAcquisPath    = "/etc/crowdsec/acquis.d/mailadmin.yaml"
	CrowdSecBouncerConf   = "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
	crowdSecBouncerName   = "mailadmin-nftables"
	UnattendedConfPath    = "/etc/apt/apt.conf.d/52mailadmin-unattended-upgrades"
	AutoUpgradesPath      = "/etc/apt/apt.conf.d/20auto-upgrades"
	NeedrestartConfPath   = "/etc/needrestart/conf.d/90-mailadmin.conf"
	PwqualityConfPath     = "/etc/security/pwquality.conf.d/90-mailadmin.conf" // #nosec G101 -- file path, not a credential
	LoginDefsPath         = "/etc/login.defs"
	IssueNetPath          = "/etc/issue.net"
	IssuePath             = "/etc/issue"
	AideDBPath            = "/var/lib/aide/aide.db"
	SysstatDefaultsPath   = "/etc/default/sysstat"
)

// TLS policy shared by Postfix and Dovecot: TLS 1.2 and 1.3 only, forward secret
// AEAD ciphers only. Groups start with the hybrid post-quantum key exchange where
// the installed OpenSSL supports it (see TLSGroups).
const (
	TLS12Ciphers = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:" +
		"ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:" +
		"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
	TLS13Suites = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
)

// LoginBanner is shown before SSH authentication and on local consoles (CIS 1.7).
const LoginBanner = "Authorized access only. Unauthorized access to this system is prohibited and may be\n" +
	"prosecuted under applicable law. All connections are monitored and logged, and the logs\n" +
	"may be used as evidence.\n"

// HardeningPackages are installed with the mail stack. They provide auditing,
// brute force protection, file integrity checks and unattended updates.
func HardeningPackages() []string {
	return []string{
		"auditd", "crowdsec", "crowdsec-firewall-bouncer-nftables", "aide", "aide-common",
		"needrestart", "unattended-upgrades", "apparmor", "apparmor-utils",
		"libpam-pwquality", "libpam-tmpdir", "debsums", "acct", "sysstat",
	}
}

// TLSGroups returns the key exchange groups, preferred first. X25519MLKEM768 needs
// OpenSSL 3.5; older releases reject an unknown group name and the daemon would
// not start, so it is only listed when the installed OpenSSL supports it.
func TLSGroups(opensslVersion string) []string {
	groups := []string{"X25519", "prime256v1", "secp384r1"}
	if versionAtLeast(opensslVersion, opensslVersionRe, 3, 5) {
		return append([]string{"X25519MLKEM768"}, groups...)
	}
	return groups
}

// installedTLSGroups asks the distribution's openssl for its version. The path is
// fixed: a self-built openssl in /usr/local would describe another libssl than
// the one Postfix and Dovecot link against.
func installedTLSGroups(ctx context.Context, x Exec) []string {
	res, err := x.Run(ctx, nil, "/usr/bin/openssl", "version")
	if err != nil {
		return TLSGroups("")
	}
	return TLSGroups(string(res.Stdout))
}

var (
	opensslVersionRe = regexp.MustCompile(`OpenSSL (\d+)\.(\d+)`)
	opensshVersionRe = regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`)
)

// versionAtLeast reports whether the first match of re in s (two numeric
// groups, major and minor) is at least major.minor.
func versionAtLeast(s string, re *regexp.Regexp, major, minor int) bool {
	m := re.FindStringSubmatch(s)
	if len(m) != 3 {
		return false
	}
	maj, err1 := strconv.Atoi(m[1])
	mnr, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return false
	}
	return maj > major || (maj == major && mnr >= minor)
}

// runSteps runs each argv in order and stops at the first failure.
func runSteps(ctx context.Context, x Exec, steps ...[]string) error {
	for _, s := range steps {
		if _, err := x.Run(ctx, nil, s...); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(s, " "), err)
		}
	}
	return nil
}

// SSHCaps is what the installed OpenSSH supports, so the hardened config only
// names algorithms and options sshd accepts.
type SSHCaps struct {
	Version string // ssh -V output, for example "OpenSSH_10.0p2 Debian-7"
	Kex     map[string]bool
	Ciphers map[string]bool
	MACs    map[string]bool
	KeySigs map[string]bool
}

func (c SSHCaps) atLeast(major, minor int) bool {
	return versionAtLeast(c.Version, opensshVersionRe, major, minor)
}

// Preferred algorithms, strongest first. Each list is cut to what sshd supports.
var (
	sshKex = []string{
		"mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256", "curve25519-sha256@libssh.org",
	}
	sshCiphers = []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com"}
	sshMACs    = []string{"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "umac-128-etm@openssh.com"}
	sshHostSig = []string{"ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com", "rsa-sha2-512", "rsa-sha2-256"}
	// User keys: Ed25519 and ECDSA (both also as FIDO keys) and RSA of at least
	// 3072 bits, the key types BSI TR-02102-4 accepts. usableKey must match this list.
	sshUserSig = []string{
		"ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com",
		"sk-ssh-ed25519@openssh.com", "sk-ssh-ed25519-cert-v01@openssh.com",
		"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
		"sk-ecdsa-sha2-nistp256@openssh.com",
		"rsa-sha2-512", "rsa-sha2-256",
		// Certificates of every accepted key type, so an SSH CA keeps working.
		"ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com",
		"ecdsa-sha2-nistp521-cert-v01@openssh.com", "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		"rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com",
	}
)

// SSHPolicy is what the drop-in enforces, decided from how the operator logs in.
type SSHPolicy struct {
	KeyOnly     bool // password and keyboard-interactive login off
	RootKeyOnly bool // PermitRootLogin prohibit-password
	StrictRSA   bool // RequiredRSASize 3072
	// Stricter settings the operator already had, kept on --adopt.
	RootLoginNo bool   // PermitRootLogin no
	AuthMethods string // AuthenticationMethods with more than one factor
}

func supported(prefer []string, have map[string]bool) []string {
	var out []string
	for _, a := range prefer {
		if have[a] {
			out = append(out, a)
		}
	}
	return out
}

// SSHHardeningConf renders the sshd drop-in for policy p (see ApplySSHHardening,
// which decides it so the operator cannot be locked out). hostKeys are the host
// key files to offer (ed25519 and RSA, not ECDSA or DSA).
func SSHHardeningConf(c SSHCaps, p SSHPolicy, hostKeys []string) string {
	var b strings.Builder
	b.WriteString("# Managed by mailadmin install. SSH hardening (BSI SYS.1.3, CIS Level 1 and 2).\n")
	b.WriteString("# Loaded first from sshd_config.d, so these values win over later drop-ins.\n")
	line := func(k, v string) { fmt.Fprintf(&b, "%s %s\n", k, v) }
	if p.RootLoginNo {
		line("PermitRootLogin", "no")
	} else if p.RootKeyOnly {
		line("PermitRootLogin", "prohibit-password")
	}
	line("PubkeyAuthentication", "yes")
	if p.KeyOnly {
		line("PasswordAuthentication", "no")
		if p.AuthMethods != "" {
			line("AuthenticationMethods", p.AuthMethods)
		} else {
			line("AuthenticationMethods", "publickey")
		}
	}
	if !strings.Contains(p.AuthMethods, "keyboard-interactive") {
		line("KbdInteractiveAuthentication", "no")
	}
	line("PermitEmptyPasswords", "no")
	line("HostbasedAuthentication", "no")
	line("IgnoreRhosts", "yes")
	line("StrictModes", "yes")
	line("MaxAuthTries", "3")
	line("MaxSessions", "2")
	line("MaxStartups", "10:30:60")
	line("LoginGraceTime", "30")
	line("ClientAliveInterval", "300")
	line("ClientAliveCountMax", "2")
	line("TCPKeepAlive", "no") // ClientAlive runs inside the encrypted channel and cannot be spoofed
	line("DisableForwarding", "yes")
	line("X11Forwarding", "no")
	line("AllowAgentForwarding", "no")
	line("AllowTcpForwarding", "no")
	line("AllowStreamLocalForwarding", "no")
	line("PermitTunnel", "no")
	line("GatewayPorts", "no")
	line("PermitUserEnvironment", "no")
	line("UseDNS", "no")
	line("Compression", "no")
	// INFO, not VERBOSE: VERBOSE logs every agent key sshd refuses as a failure,
	// and CrowdSec's ssh-bf then bans an operator whose agent holds several keys.
	line("LogLevel", "INFO")
	line("Banner", IssueNetPath)
	if l := supported(sshKex, c.Kex); len(l) > 0 {
		line("KexAlgorithms", strings.Join(l, ","))
	}
	if l := supported(sshCiphers, c.Ciphers); len(l) > 0 {
		line("Ciphers", strings.Join(l, ","))
	}
	if l := supported(sshMACs, c.MACs); len(l) > 0 {
		line("MACs", strings.Join(l, ","))
	}
	if l := supported(sshHostSig, c.KeySigs); len(l) > 0 {
		line("HostKeyAlgorithms", strings.Join(l, ","))
	}
	if l := supported(sshUserSig, c.KeySigs); len(l) > 0 && c.atLeast(8, 5) {
		line("PubkeyAcceptedAlgorithms", strings.Join(l, ","))
	}
	if p.StrictRSA && c.atLeast(9, 1) {
		line("RequiredRSASize", "3072")
	}
	for _, k := range hostKeys {
		line("HostKey", k)
	}
	return b.String()
}

// probeSSH reads the algorithms and the version of the installed OpenSSH.
func probeSSH(ctx context.Context, x Exec) (SSHCaps, error) {
	c := SSHCaps{}
	res, err := x.Run(ctx, nil, "ssh", "-V")
	if err != nil {
		return c, fmt.Errorf("ssh -V: %w", err)
	}
	c.Version = strings.TrimSpace(string(res.Stderr) + string(res.Stdout))
	query := func(kind string) (map[string]bool, error) {
		r, err := x.Run(ctx, nil, "ssh", "-Q", kind)
		if err != nil {
			return nil, fmt.Errorf("ssh -Q %s: %w", kind, err)
		}
		set := map[string]bool{}
		for _, l := range strings.Fields(string(r.Stdout)) {
			set[l] = true
		}
		return set, nil
	}
	if c.Kex, err = query("kex"); err != nil {
		return c, err
	}
	if c.Ciphers, err = query("cipher"); err != nil {
		return c, err
	}
	if c.MACs, err = query("mac"); err != nil {
		return c, err
	}
	if c.KeySigs, err = query("key-sig"); err != nil {
		return c, err
	}
	return c, nil
}

// authKey is one key line of an authorized_keys file.
type authKey struct {
	fingerprint string // SHA256:..., as sshd logs it
	usable      bool   // see usableKey
	rsaBits     int    // modulus size for ssh-rsa, else 0
}

// readAuthorizedKeys parses an authorized_keys file. A missing or unreadable
// file has no keys, so password login then stays on.
func readAuthorizedKeys(path string) []authKey {
	f, err := os.Open(path) // #nosec G304 -- the login account's authorized_keys
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var keys []authKey
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 16*1024), 1<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if k, ok := parseAuthorizedKey(l); ok {
			keys = append(keys, k)
		}
	}
	if sc.Err() != nil {
		return nil
	}
	return keys
}

// parseAuthorizedKey reads the key type and blob of one authorized_keys line.
func parseAuthorizedKey(line string) (authKey, bool) {
	fields := strings.Fields(line)
	for i, f := range fields {
		if !loginKeyTypes[f] || i+1 >= len(fields) {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(fields[i+1])
		if err != nil {
			return authKey{}, false
		}
		sum := sha256.Sum256(blob)
		k := authKey{fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), usable: usableKey(line)}
		if f == "ssh-rsa" {
			k.rsaBits = rsaBits(fields[i+1])
		}
		return k, true
	}
	return authKey{}, false
}

// sshLogin is what sshd logged for an account's most recent accepted login.
type sshLogin struct {
	method      string // publickey, password, keyboard-interactive/pam, ...
	keyType     string // ED25519, RSA, ECDSA-CERT, ... for publickey
	fingerprint string // SHA256:... for publickey
}

var acceptedRe = regexp.MustCompile(`^Accepted (\S+) for (\S+) from \S+ port \d+ [^\s:]+(?:: (\S+) (SHA256:\S+))?`)

// lastLogins returns the most recent accepted SSH login per account from sshd's
// journal (sshd-session since OpenSSH 9.8). Without the journal the map is
// empty, and the policy then keeps every login method.
func lastLogins(ctx context.Context, x Exec) map[string]sshLogin {
	out := map[string]sshLogin{}
	res, err := x.Run(ctx, nil, "journalctl", "-q", "-o", "cat", "--no-pager",
		"-t", "sshd", "-t", "sshd-session", "--since", "-30 days", "-n", "20000")
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		if m := acceptedRe.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			out[m[2]] = sshLogin{method: m[1], keyType: m[3], fingerprint: m[4]}
		}
	}
	return out
}

// decideSSHPolicy turns off password login only when the operator's own last
// login used a key that is in their authorized_keys and that the hardened sshd
// accepts. Anything it cannot prove (no login uid, no journal entry, a password
// or certificate login, a key from another file) keeps the current methods.
// RequiredRSASize is left out when the operator or root logged in with an RSA
// key that is shorter than 3072 bits or whose size is unknown.
func decideSSHPolicy(account string, known bool, keys, rootKeys []authKey, logins map[string]sshLogin) SSHPolicy {
	find := func(keys []authKey, fp string) (authKey, bool) {
		for _, k := range keys {
			if fp != "" && k.fingerprint == fp {
				return k, true
			}
		}
		return authKey{}, false
	}
	p := SSHPolicy{StrictRSA: true}
	if known {
		if l := logins[account]; l.method == "publickey" {
			k, ok := find(keys, l.fingerprint)
			p.KeyOnly = ok && k.usable
		}
		p.RootKeyOnly = account != "root" || p.KeyOnly
	}
	for acct, ks := range map[string][]authKey{account: keys, "root": rootKeys} {
		l := logins[acct]
		if acct == "" || l.method != "publickey" || !strings.HasPrefix(l.keyType, "RSA") {
			continue
		}
		if k, ok := find(ks, l.fingerprint); !ok || k.rsaBits < 3072 {
			p.StrictRSA = false
		}
	}
	return p
}

// loginKeyTypes are the key types usableKey accepts; they match sshUserSig.
var loginKeyTypes = map[string]bool{
	"ssh-ed25519": true, "sk-ssh-ed25519@openssh.com": true,
	"ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true, "ssh-rsa": true,
}

// usableKey reports whether an authorized_keys line holds a key the hardened sshd
// accepts for an interactive login: Ed25519 or ECDSA (also FIDO), or RSA with at
// least 3072 bits (RequiredRSASize). A key bound to a forced command or to
// restrict cannot open a shell, so it does not count.
func usableKey(line string) bool {
	fields := strings.Fields(line)
	for i, f := range fields {
		if !loginKeyTypes[f] {
			continue
		}
		opts := strings.Join(fields[:i], " ")
		if strings.Contains(opts, "command=") || strings.Contains(opts, "restrict") {
			return false
		}
		if f != "ssh-rsa" {
			return true
		}
		return i+1 < len(fields) && rsaBits(fields[i+1]) >= 3072
	}
	return false
}

// rsaBits returns the modulus size of a base64 ssh-rsa public key, or 0.
func rsaBits(b64 string) int {
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return 0
	}
	var parts [][]byte
	for len(blob) >= 4 && len(parts) < 3 {
		rest := blob[4:]
		n := binary.BigEndian.Uint32(blob)
		if n > uint32(min(len(rest), 1<<20)) { // #nosec G115 -- bounded to 1 MiB, fits uint32
			return 0
		}
		parts = append(parts, rest[:n])
		blob = rest[n:]
	}
	if len(parts) != 3 || string(parts[0]) != "ssh-rsa" {
		return 0
	}
	return new(big.Int).SetBytes(parts[2]).BitLen()
}

// loginAccount is the account the operator logged in with (the audit login uid,
// which survives sudo and su), and its home directory. known is false when there
// is no login uid (console, cron, many containers) or the uid is not in
// /etc/passwd (SSSD or LDAP accounts, which the static binary cannot resolve).
func loginAccount() (name, home string, known bool) {
	data, err := os.ReadFile("/proc/self/loginuid")
	uid := strings.TrimSpace(string(data))
	switch {
	case err != nil || uid == "" || uid == "4294967295":
		return "", "", false
	case uid == "0":
		return "root", "/root", true
	}
	u, err := user.LookupId(uid)
	if err != nil {
		return "", "", false
	}
	return u.Username, u.HomeDir, true
}

// operatorSSH returns the first PermitRootLogin and AuthenticationMethods values
// outside Match blocks in files (sshd's first value wins), skipping mailadmin's
// own drop-in.
func operatorSSH(files []string) (permitRootLogin, authMethods string) {
	for _, f := range files {
		if f == SSHHardeningPath {
			continue
		}
		data, err := os.ReadFile(f) // #nosec G304 -- sshd config files
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(data), "\n") {
			if i := strings.Index(l, "#"); i >= 0 {
				l = l[:i]
			}
			k, v, ok := strings.Cut(strings.TrimSpace(strings.Replace(l, "=", " ", 1)), " ")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			switch strings.ToLower(k) {
			case "match":
				goto next
			case "permitrootlogin":
				if permitRootLogin == "" {
					permitRootLogin = v
				}
			case "authenticationmethods":
				if authMethods == "" {
					authMethods = v
				}
			}
		}
	next:
	}
	return permitRootLogin, authMethods
}

// ApplySSHHardening writes the sshd drop-in, validates it with sshd -t and
// reloads sshd. A config that sshd rejects is rolled back, so a failed run never
// leaves sshd unable to start. It reports whether password login was turned off
// and the login account that decided it.
func ApplySSHHardening(ctx context.Context, x Exec) (policy SSHPolicy, account string, err error) {
	caps, err := probeSSH(ctx, x)
	if err != nil {
		return SSHPolicy{}, "", err
	}
	account, home, known := loginAccount()
	var keys []authKey
	if known {
		keys = readAuthorizedKeys(filepath.Join(home, ".ssh", "authorized_keys"))
	}
	policy = decideSSHPolicy(account, known, keys, readAuthorizedKeys("/root/.ssh/authorized_keys"), lastLogins(ctx, x))
	// The drop-in loads first and wins, so stricter settings the operator had
	// elsewhere are carried into it instead of being overridden.
	drops, _ := filepath.Glob("/etc/ssh/sshd_config.d/*.conf")
	prl, am := operatorSSH(append(drops, "/etc/ssh/sshd_config"))
	policy.RootLoginNo = strings.EqualFold(prl, "no")
	if f := strings.FieldsFunc(am, func(r rune) bool { return r == ',' || r == ' ' }); len(f) > 1 {
		policy.AuthMethods = am
	}
	var hostKeys []string
	for _, k := range []string{"/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_rsa_key"} {
		if _, err := os.Stat(k); err == nil {
			hostKeys = append(hostKeys, k)
		}
	}
	if err := writeAtomic(IssueNetPath, []byte(LoginBanner), 0o644); err != nil {
		return SSHPolicy{}, account, err
	}
	prev, prevErr := os.ReadFile(SSHHardeningPath)
	if err := writeAtomic(SSHHardeningPath, []byte(SSHHardeningConf(caps, policy, hostKeys)), 0o600); err != nil {
		return SSHPolicy{}, account, err
	}
	if _, err := x.Run(ctx, nil, "sshd", "-t"); err != nil {
		if prevErr == nil {
			_ = writeAtomic(SSHHardeningPath, prev, 0o600)
		} else {
			_ = os.Remove(SSHHardeningPath)
		}
		return SSHPolicy{}, account, fmt.Errorf("sshd rejected the hardened config, previous state restored: %w", err)
	}
	// try-reload-or-restart is a no-op for a socket-activated sshd that is not running.
	if _, err := x.Run(ctx, nil, "systemctl", "try-reload-or-restart", "ssh"); err != nil {
		return SSHPolicy{}, account, fmt.Errorf("reload sshd: %w", err)
	}
	return policy, account, nil
}

// SysctlHardening is the kernel and network hardening (CIS 1.5 and 3.3, BSI SYS.1.3.A10).
// IP forwarding and router advertisements keep their defaults: forwarding is off
// unless something else turned it on, and cloud hosts may get IPv6 from RAs.
func SysctlHardening() string {
	return `# Managed by mailadmin install. Kernel and network hardening.
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.kexec_load_disabled = 1
kernel.sysrq = 0
kernel.randomize_va_space = 2
kernel.perf_event_paranoid = 3
dev.tty.ldisc_autoload = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
`
}

// ModprobeHardening blocks filesystems and protocols a mail host never needs (CIS 1.1.1, 3.2).
func ModprobeHardening() string {
	var b strings.Builder
	b.WriteString("# Managed by mailadmin install. Modules a mail host does not need.\n")
	for _, m := range []string{
		"cramfs", "freevxfs", "hfs", "hfsplus", "jffs2", "udf", "usb-storage",
		"dccp", "sctp", "rds", "tipc", "firewire-core", "firewire-ohci", "bluetooth",
	} {
		fmt.Fprintf(&b, "install %s /bin/false\nblacklist %s\n", m, m)
	}
	return b.String()
}

// AuditRules records changes to identities, privileges, SSH, the mail secrets, the
// DKIM keys and the TLS keys, kernel module loads, and commands run as root by a
// logged-in user (CIS 6.2, BSI SYS.1.3.A12).
func AuditRules() string {
	return `## Managed by mailadmin install.
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/mailadmin/ -p wa -k mailadmin
-w /var/lib/rspamd/dkim/ -p wa -k dkim
-w /etc/ssl/mail/ -p wa -k tls
-w /etc/nftables.conf -p wa -k firewall
-w /etc/nftables.d/ -p wa -k firewall
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k rootcmd
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
`
}

// CrowdSecCollections are the hub collections for the services on a mail host.
var CrowdSecCollections = []string{
	"crowdsecurity/linux", "crowdsecurity/sshd", "crowdsecurity/postfix", "crowdsecurity/dovecot",
}

// crowdSecCoverage reports whether acquisition files other than mailadmin's
// already read sshd and the mail logs. A file source counts only when the file
// exists: Debian 13 writes no syslog files, so the file sources cscli setup
// writes there read nothing. With rsyslog, /var/log/syslog and mail.log carry
// the Postfix and Dovecot lines.
func crowdSecCoverage(etc string) (ssh, mail bool) {
	files, _ := filepath.Glob(filepath.Join(etc, "acquis.d", "*.yaml"))
	files = append(files, filepath.Join(etc, "acquis.yaml"))
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	for _, f := range files {
		if filepath.Base(f) == filepath.Base(CrowdSecAcquisPath) {
			continue
		}
		data, err := os.ReadFile(f) // #nosec G304 -- CrowdSec config files
		if err != nil {
			continue
		}
		c := string(data)
		ssh = ssh || strings.Contains(c, "_SYSTEMD_UNIT=ssh.service") || strings.Contains(c, "_SYSTEMD_UNIT=sshd.service") ||
			(strings.Contains(c, "/var/log/auth.log") && exists("/var/log/auth.log"))
		mail = mail || strings.Contains(c, "_SYSTEMD_UNIT=postfix") ||
			(strings.Contains(c, "/var/log/mail.log") && exists("/var/log/mail.log")) ||
			(strings.Contains(c, "/var/log/syslog") && exists("/var/log/syslog"))
	}
	return ssh, mail
}

// CrowdSecAcquis returns journal sources for the logs no other acquisition file
// reads, so no log line is counted twice: a doubled source halves every ban
// threshold. Postfix logs as postfix.service since Debian's postfix 3.9.1-7 and
// as postfix@-.service before; two filters on one field match either. An empty
// result means nothing is missing.
func CrowdSecAcquis(sshCovered, mailCovered bool) string {
	var b strings.Builder
	add := func(filters ...string) {
		if b.Len() == 0 {
			b.WriteString("# Managed by mailadmin install.\n")
		} else {
			b.WriteString("---\n")
		}
		b.WriteString("source: journalctl\njournalctl_filter:\n")
		for _, f := range filters {
			fmt.Fprintf(&b, "  - \"%s\"\n", f)
		}
		b.WriteString("labels:\n  type: syslog\n")
	}
	if !sshCovered {
		add("_SYSTEMD_UNIT=ssh.service")
	}
	if !mailCovered {
		add("_SYSTEMD_UNIT=postfix.service", "_SYSTEMD_UNIT=postfix@-.service")
		add("_SYSTEMD_UNIT=dovecot.service")
	}
	return b.String()
}

// UnattendedUpgrades installs every update from the distribution (release,
// updates, security) and from every vendor repository install adds, and reboots
// at 04:00 when an update needs it.
func UnattendedUpgrades() string {
	var sites strings.Builder
	for _, r := range VendorRepos("") { // the site does not depend on the codename
		if u, err := url.Parse(r.URI); err == nil && u.Host != "" {
			fmt.Fprintf(&sites, "\t\"site=%s\";\n", u.Host)
		}
	}
	return `// Managed by mailadmin install.
Unattended-Upgrade::Origins-Pattern {
	"origin=${distro_id},codename=${distro_codename}";
	"origin=${distro_id},codename=${distro_codename}-updates";
	"origin=${distro_id},codename=${distro_codename}-security";
	"origin=${distro_id},codename=${distro_codename},label=${distro_id}-Security";
` + sites.String() + `};
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
Unattended-Upgrade::SyslogEnable "true";
`
}

// AutoUpgrades turns on the daily apt run that unattended-upgrades hooks into.
func AutoUpgrades() string {
	return `// Managed by mailadmin install.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
`
}

// hardeningFiles are the drop-ins written as they are.
func hardeningFiles() map[string]string {
	return map[string]string{ // #nosec G101 -- file paths and contents, no credentials
		SysctlHardeningPath:   SysctlHardening(),
		ModprobeHardeningPath: ModprobeHardening(),
		LimitsHardeningPath:   "# Managed by mailadmin install. No core dumps (CIS 1.5.1).\n* hard core 0\n",
		CoredumpConfPath:      "# Managed by mailadmin install.\n[Coredump]\nStorage=none\nProcessSizeMax=0\n",
		JournaldConfPath:      "# Managed by mailadmin install.\n[Journal]\nStorage=persistent\nCompress=yes\n",
		AuditRulesPath:        AuditRules(),
		UnattendedConfPath:    UnattendedUpgrades(),
		AutoUpgradesPath:      AutoUpgrades(),
		NeedrestartConfPath:   "# Managed by mailadmin install. Restart services after library updates.\n$nrconf{restart} = 'a';\n",
		PwqualityConfPath:     "# Managed by mailadmin install.\nminlen = 14\nminclass = 4\nmaxrepeat = 3\nenforce_for_root\n",
		IssuePath:             LoginBanner,
		IssueNetPath:          LoginBanner,
	}
}

// loginDefs are the password aging and default umask values (CIS 5.4, BSI SYS.1.3.A2).
var loginDefs = [][2]string{
	{"UMASK", "027"},
	{"PASS_MAX_DAYS", "365"},
	{"PASS_MIN_DAYS", "1"},
	{"PASS_WARN_AGE", "14"},
	{"ENCRYPT_METHOD", "YESCRYPT"},
	{"YESCRYPT_COST_FACTOR", "7"},
	{"SHA_CRYPT_MIN_ROUNDS", "65536"},
	{"SHA_CRYPT_MAX_ROUNDS", "65536"},
}

// SetDefs sets KEY VALUE lines in a login.defs style file, replacing an existing
// line for the key (commented or not) or appending one.
func SetDefs(content string, kv [][2]string) string {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	for _, p := range kv {
		re := regexp.MustCompile(`^\s*#?\s*` + regexp.QuoteMeta(p[0]) + `\s`)
		done := false
		for i, l := range lines {
			if re.MatchString(l) && !done {
				lines[i] = p[0] + "\t" + p[1]
				done = true
			} else if re.MatchString(l) && !strings.HasPrefix(strings.TrimSpace(l), "#") {
				lines[i] = "# " + l // a second active line would override the first
			}
		}
		if !done {
			lines = append(lines, p[0]+"\t"+p[1])
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

// ApplySystemHardening writes the hardening drop-ins and activates them: sysctl,
// journald, auditd, AppArmor, time sync and the AIDE baseline. It also
// tightens login.defs and the cron permissions and disables services a mail host
// does not run.
func ApplySystemHardening(ctx context.Context, x Exec) error {
	for path, content := range hardeningFiles() {
		if err := writeAtomic(path, []byte(content), 0o644); err != nil {
			return err
		}
	}
	defs, err := os.ReadFile(LoginDefsPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", LoginDefsPath, err)
	}
	if err := writeAtomic(LoginDefsPath, []byte(SetDefs(string(defs), loginDefs)), 0o644); err != nil {
		return err
	}
	// sysstat collects only when enabled in its defaults file.
	if sa, err := os.ReadFile(SysstatDefaultsPath); err == nil {
		if err := writeAtomic(SysstatDefaultsPath, []byte(SetShellVar(string(sa), "ENABLED", `"true"`)), 0o644); err != nil {
			return err
		}
	}
	// PostgreSQL's config files are readable by the postgres group only (CIS 6.1).
	// The directory belongs to postgres, so a link there is never followed: it
	// could point root's chmod at any file.
	pgConfs, _ := filepath.Glob("/etc/postgresql/*/main/*.conf")
	for _, f := range pgConfs {
		if err := chmodNoFollow(f, 0o640); err != nil {
			return err
		}
	}
	// Cron is root only (CIS 5.1).
	_ = os.Chmod("/etc/crontab", 0o600)
	for _, d := range []string{"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
		if err := os.Chmod(d, 0o700); err != nil && !errors.Is(err, fs.ErrNotExist) { // #nosec G302 -- directory, root only
			return fmt.Errorf("chmod %s: %w", d, err)
		}
	}
	steps := [][]string{
		{"sysctl", "-e", "-p", SysctlHardeningPath},
		{"systemctl", "restart", "systemd-journald"},
		{"systemctl", "enable", "--now", "auditd"},
		{"augenrules", "--load"},
		{"systemctl", "enable", "--now", "apparmor"},
		{"systemctl", "enable", "--now", "apt-daily.timer"},
		{"systemctl", "enable", "--now", "apt-daily-upgrade.timer"},
		{"systemctl", "enable", "--now", "acct"},
		{"systemctl", "enable", "--now", "sysstat"},
		// Pending updates are installed now in the background, not only at the next timer run.
		{"systemctl", "start", "--no-block", "apt-daily-upgrade.service"},
	}
	if err := runSteps(ctx, x, steps...); err != nil {
		return err
	}
	// Without an NTP service (no systemd-timesyncd, no chrony) timedatectl fails;
	// the host then keeps its current time source.
	if _, err := x.Run(ctx, nil, "timedatectl", "set-ntp", "true"); err != nil {
		fmt.Fprintf(os.Stderr, "warning: timedatectl set-ntp true failed (%v); install systemd-timesyncd or chrony\n", err)
	}
	// Services a mail host never needs. A unit that is not installed is fine.
	for _, u := range []string{"avahi-daemon.service", "avahi-daemon.socket", "cups.service", "cups.socket",
		"rpcbind.service", "rpcbind.socket", "bluetooth.service"} {
		_, _ = x.Run(ctx, nil, "systemctl", "disable", "--now", u)
	}
	return nil
}

// StartAIDEBaseline schedules the first AIDE baseline once, 30 minutes from now,
// so it hashes the system after install and the first update run, not during
// them. A baseline that exists or is already scheduled or running is left alone.
func StartAIDEBaseline(ctx context.Context, x Exec) error {
	if _, err := os.Stat(AideDBPath); err == nil {
		return nil
	}
	if _, err := x.Run(ctx, nil, "systemctl", "is-active", "--quiet",
		"mailadmin-aideinit.timer", "mailadmin-aideinit.service"); err == nil {
		return nil
	}
	if _, err := x.Run(ctx, nil, "systemd-run", "--unit=mailadmin-aideinit", "--on-active=30min",
		"--timer-property=AccuracySec=1min", "/usr/sbin/aideinit", "-y", "-f"); err != nil {
		return fmt.Errorf("schedule AIDE baseline: %w", err)
	}
	return nil
}

// chmodNoFollow changes the mode of a regular file without following a link.
func chmodNoFollow(path string, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- fixed config glob
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil // a link: leave it alone
		}
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

// ApplyCrowdSec installs the hub collections, enrolls the instance in the CrowdSec
// console when a key is given, and starts the agent and the nftables bouncer. The
// bouncer bans in its own nftables table, so the mailadmin table stays untouched.
func ApplyCrowdSec(ctx context.Context, x Exec, hostname, enrollKey string) error {
	changed := false
	// The hub is fetched only while a collection is missing, so a rerun does not
	// depend on the hub CDN and does not restart the agent for nothing.
	if !crowdSecCollectionsInstalled(ctx, x) {
		if err := runSteps(ctx, x,
			[]string{"cscli", "hub", "update"},
			append([]string{"cscli", "collections", "install"}, CrowdSecCollections...)); err != nil {
			return err
		}
		changed = true
	}
	if enrollKey != "" {
		// The key is in argv; sys errors name only the command, never its arguments.
		if _, err := x.Run(ctx, nil, "cscli", "console", "enroll", "--overwrite", "--name", hostname, enrollKey); err != nil {
			return fmt.Errorf("crowdsec console enroll failed (%w); check the key and rerun", err)
		}
		changed = true
	}
	acquisChanged, err := writeCrowdSecAcquis()
	if err != nil {
		return err
	}
	changed = changed || acquisChanged
	if err := runSteps(ctx, x, []string{"systemctl", "enable", "--now", "crowdsec"}); err != nil {
		return err
	}
	if changed {
		if err := runSteps(ctx, x, []string{"systemctl", "restart", "crowdsec"}); err != nil {
			return err
		}
	}
	// The security allowlist commands and overview work on this list; cscli
	// allowlists add does not create it.
	if _, err := x.Run(ctx, nil, "cscli", "allowlists", "inspect", security.AllowlistName); err != nil {
		if _, err := x.Run(ctx, nil, "cscli", "allowlists", "create", security.AllowlistName,
			"--description", "managed by mailadmin"); err != nil {
			return fmt.Errorf("create crowdsec allowlist: %w", err)
		}
	}
	// The bouncer must get its key before it starts: started with the placeholder
	// it fails with "access forbidden" and stops the install.
	registered, err := registerBouncer(ctx, x)
	if err != nil {
		return err
	}
	if err := runSteps(ctx, x, []string{"systemctl", "enable", "--now", "crowdsec-firewall-bouncer"}); err != nil {
		return err
	}
	if registered {
		return runSteps(ctx, x, []string{"systemctl", "restart", "crowdsec-firewall-bouncer"})
	}
	return nil
}

// crowdSecCollectionsInstalled reports whether every hub collection is present.
func crowdSecCollectionsInstalled(ctx context.Context, x Exec) bool {
	res, err := x.Run(ctx, nil, "cscli", "collections", "list", "-o", "raw")
	if err != nil {
		return false
	}
	for _, c := range CrowdSecCollections {
		if !strings.Contains(string(res.Stdout), c) {
			return false
		}
	}
	return true
}

// writeCrowdSecAcquis writes mailadmin's acquisition file, or removes it when
// other sources already read everything, and reports whether it changed.
func writeCrowdSecAcquis() (bool, error) {
	acquis := CrowdSecAcquis(crowdSecCoverage("/etc/crowdsec"))
	if acquis == "" {
		err := os.Remove(CrowdSecAcquisPath)
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("remove %s: %w", CrowdSecAcquisPath, err)
		}
		return true, nil
	}
	return writeAtomicChanged(CrowdSecAcquisPath, []byte(acquis), 0o644)
}

// registerBouncer gives the nftables bouncer a local API key when its config
// has none yet. The package registers itself only when the local API already
// runs during its postinst, which is not the case when both packages arrive in
// one apt run; the config then keeps the ${API_KEY} placeholder and the bouncer
// gets "access forbidden". A key that is already set is kept: replacing it on
// every run would revoke the running bouncer's key and flush its bans.
func registerBouncer(ctx context.Context, x Exec) (bool, error) {
	conf, err := os.ReadFile(CrowdSecBouncerConf)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", CrowdSecBouncerConf, err)
	}
	if !bouncerKeyMissing(string(conf)) {
		return false, nil
	}
	_, _ = x.Run(ctx, nil, "cscli", "bouncers", "delete", crowdSecBouncerName)
	res, err := x.Run(ctx, nil, "cscli", "bouncers", "add", crowdSecBouncerName, "-o", "raw")
	if err != nil {
		return false, fmt.Errorf("register crowdsec bouncer: %w", err)
	}
	key := strings.TrimSpace(string(res.Stdout))
	if key == "" || strings.ContainsAny(key, " \n") {
		return false, errors.New("register crowdsec bouncer: cscli returned no key")
	}
	out, err := SetBouncerKey(string(conf), key)
	if err != nil {
		return false, err
	}
	return true, writeAtomic(CrowdSecBouncerConf, []byte(out), 0o600)
}

// bouncerKeyMissing reports whether the bouncer config holds no usable key.
func bouncerKeyMissing(conf string) bool {
	m := regexp.MustCompile(`(?m)^api_key:[ \t]*(.*)$`).FindStringSubmatch(conf)
	if m == nil {
		return true
	}
	v := strings.Trim(strings.TrimSpace(m[1]), `"'`)
	return v == "" || v == "${API_KEY}" || v == "<API_KEY>"
}

// SetBouncerKey replaces the api_key line of the bouncer config.
func SetBouncerKey(conf, key string) (string, error) {
	re := regexp.MustCompile(`(?m)^api_key:.*$`)
	if !re.MatchString(conf) {
		return "", errors.New("bouncer config has no api_key line")
	}
	return re.ReplaceAllLiteralString(conf, "api_key: "+key), nil
}

// SetShellVar sets NAME=value in a shell style defaults file, replacing an existing
// assignment or appending one.
func SetShellVar(content, name, value string) string {
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(name) + `=.*$`)
	if re.MatchString(content) {
		return re.ReplaceAllLiteralString(content, name+"="+value)
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + name + "=" + value + "\n"
}
