package install

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
)

// Paths of the Valkey state store and the rspamd modules that use it.
const (
	ValkeyConfPath      = "/etc/valkey/valkey.conf"
	ValkeyDropInPath    = "/etc/systemd/system/valkey-server.service.d/mailadmin.conf"
	ValkeyUser          = "rspamd"
	ValkeyAddr          = "127.0.0.1:6379"
	valkeyPasswordRegex = `rspamd on >([0-9a-f]+)` // #nosec G101 -- regex that finds the generated secret, not a credential
)

var valkeyPassword = regexp.MustCompile(valkeyPasswordRegex)

// ValkeyPasswordFrom reads the rspamd ACL password from an existing valkey.conf.
func ValkeyPasswordFrom(conf string) string {
	if m := valkeyPassword.FindStringSubmatch(conf); m != nil {
		return m[1]
	}
	return ""
}

// newValkeyPassword returns 32 random bytes as hex.
func newValkeyPassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ValkeyConf is the server config: localhost only, no persistence, the default
// user disabled, and one ACL user for rspamd with no dangerous commands.
func ValkeyConf(pw string) string {
	return fmt.Sprintf(`# Managed by mailadmin install. Valkey: Redis-compatible state for rspamd.
bind 127.0.0.1 ::1
protected-mode yes
port 6379
daemonize no
supervised systemd
dir /var/lib/valkey
save ""
appendonly no
maxmemory 256mb
maxmemory-policy volatile-lru
loglevel notice
logfile /var/log/valkey/valkey-server.log
acllog-max-len 128
user default off
user %s on >%s ~* &* +@all -@dangerous +@connection
`, ValkeyUser, pw)
}

// ValkeyDropInContent confines the valkey unit. ProtectSystem is full, not strict,
// so the log and data directories stay writable.
func ValkeyDropInContent() string {
	return "# Managed by mailadmin install.\n[Service]\nPrivateUsers=no\nPrivateTmp=yes\nProtectSystem=full\nProtectHome=yes\nNoNewPrivileges=yes\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n"
}

// RspamdLocalFiles are the rspamd modules and thresholds mailadmin owns. Greylisting,
// ratelimit and reputation keep their state in Valkey.
func RspamdLocalFiles(pw string) map[string]string {
	return map[string]string{
		"redis.conf": "# Managed by mailadmin install. Valkey (Redis-compatible) holds greylisting, ratelimit and reputation state.\n" +
			fmt.Sprintf("servers = %q;\nusername = %q;\npassword = %q;\n", ValkeyAddr, ValkeyUser, pw),
		"greylist.conf":   "# Managed by mailadmin install. Greylisting, state in Valkey.\nenabled = true;\nuse_redis = true;\n",
		"dmarc.conf":      "# Managed by mailadmin install. Inbound DMARC check. Reports are not sent.\nenabled = true;\nsend_reports = false;\n",
		"arc.conf":        "# Managed by mailadmin install. Verify ARC seals of forwarded mail.\nenabled = true;\n",
		"ratelimit.conf":  "# Managed by mailadmin install. Per-sender and per-IP rate limits, state in Valkey.\nenabled = true;\n",
		"reputation.conf": "# Managed by mailadmin install. Sender and IP reputation, state in Valkey.\nenabled = true;\n",
		"actions.conf":    "# Managed by mailadmin install. Thresholds: greylist from 4, header from 6, reject from 15.\nreject = 15;\nadd_header = 6;\ngreylist = 4;\n",
		"milter_headers.conf": "# Managed by mailadmin install. Authentication-Results carries the SPF, DKIM and DMARC verdicts.\n" +
			"# Local submissions (127.0.0.1) are scanned like inbound mail, so they get the headers too.\n" +
			"skip_local = false;\nuse = [\"authentication-results\", \"x-spamd-result\", \"x-rspamd-server\"];\n",
		"replies.conf": "# Managed by mailadmin install. Replies to our own sent mail count as ham. No external lookup.\nenabled = true;\n",
	}
}

// ApplyValkeyAndRspamd installs the Valkey config and rspamd modules. The password
// is generated once and kept across installs. The rspamd config is tested before
// rspamd is restarted.
func ApplyValkeyAndRspamd(ctx context.Context, x Exec) error {
	pw := ""
	if cur, err := os.ReadFile(ValkeyConfPath); err == nil { // #nosec G304 -- fixed system path
		pw = ValkeyPasswordFrom(string(cur))
	}
	if pw == "" {
		var err error
		if pw, err = newValkeyPassword(); err != nil {
			return err
		}
	}
	if err := writeAtomicWith(ValkeyConfPath, []byte(ValkeyConf(pw)), 0o640, nil); err != nil {
		return err
	}
	if _, err := x.Run(ctx, nil, "chown", "root:valkey", ValkeyConfPath); err != nil {
		return fmt.Errorf("chown valkey.conf: %w", err)
	}
	if err := os.MkdirAll(dirOf(ValkeyDropInPath), 0o755); err != nil { // #nosec G301 -- systemd drop-in dir
		return err
	}
	if err := writeAtomic(ValkeyDropInPath, []byte(ValkeyDropInContent()), 0o644); err != nil {
		return err
	}
	if _, err := x.Run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if _, err := x.Run(ctx, nil, "systemctl", "enable", "--now", "valkey-server"); err != nil {
		return fmt.Errorf("enable valkey-server: %w", err)
	}
	for name, content := range RspamdLocalFiles(pw) {
		path := RspamdLocalDir + "/" + name
		if err := writeAtomicWith(path, []byte(content), 0o640, nil); err != nil {
			return err
		}
		if _, err := x.Run(ctx, nil, "chgrp", "_rspamd", path); err != nil {
			return fmt.Errorf("chgrp %s: %w", path, err)
		}
	}
	if _, err := x.Run(ctx, nil, "rspamadm", "configtest"); err != nil {
		return fmt.Errorf("rspamd configtest: %w", err)
	}
	if _, err := x.Run(ctx, nil, "systemctl", "restart", "rspamd"); err != nil {
		return fmt.Errorf("restart rspamd: %w", err)
	}
	return nil
}
