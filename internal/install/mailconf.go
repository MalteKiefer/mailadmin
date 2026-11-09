package install

import (
	"fmt"
	"strings"

	"mailadmin/internal/webserver"
)

// Paths the mail stack is configured through. Each file is either fully owned by
// mailadmin (rendered here) or a single key set with postconf, so unrelated
// settings the operator made are not overwritten.
const (
	DovecotConfPath     = "/etc/dovecot/dovecot.conf"
	PostfixMapDir       = "/etc/postfix"
	RspamdLocalDir      = "/etc/rspamd/local.d"
	RspamdSelectorMap   = "/etc/rspamd/dkim_selectors.map"
	CaddyfilePath       = "/etc/caddy/Caddyfile"
	CaddyIncludeDir     = "/etc/caddy/Caddyfile.d"
	NftConfPath         = "/etc/nftables.conf"
	NftPersistPath      = "/etc/nftables.d/mailadmin.nft"
	TLSDir              = "/etc/ssl/mail"
	TLSFullchain        = TLSDir + "/fullchain.pem"
	TLSPrivkey          = TLSDir + "/privkey.pem"
	CaddyCertStore      = "/var/lib/caddy/.local/share/caddy/certificates"
	LibexecDir          = "/usr/local/libexec"
	FwPortHelperPath    = LibexecDir + "/mailadmin-fw-port"
	DKIMGenHelperPath   = LibexecDir + "/mailadmin-dkim-gen"
	CertSyncHelperPath  = LibexecDir + "/mailadmin-cert-sync"
	DKIMDirPath         = "/var/lib/rspamd/dkim"
	CertSyncServicePath = "/etc/systemd/system/mailadmin-cert-sync.service"
	CertSyncTimerPath   = "/etc/systemd/system/mailadmin-cert-sync.timer"
	PostfixMilterAddr   = "127.0.0.1:11332"
	DovecotLMTPSocket   = "/var/spool/postfix/private/dovecot-lmtp"
	DovecotAuthSocket   = "/var/spool/postfix/private/auth"
)

// DovecotConf renders the dovecot.conf mailadmin owns (Dovecot 2.4 syntax).
// It does not include the Debian conf.d tree, so no system account can log in.
func DovecotConf() string {
	return `# Managed by mailadmin install. The Debian default is kept as dovecot.conf.mailadmin-orig.
dovecot_config_version = 2.4.0
dovecot_storage_version = 2.4.0

protocols {
  imap = yes
  lmtp = yes
  sieve = yes
}

ssl = required
ssl_server {
  cert_file = ` + TLSFullchain + `
  key_file = ` + TLSPrivkey + `
}
ssl_min_protocol = TLSv1.2

auth_mechanisms = plain login
auth_allow_cleartext = no
# '+' separates the app-password label: user@domain+label.
auth_username_chars = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.-_@+
passdb_default_password_scheme = ARGON2ID

# Virtual mailboxes only: no PAM or system user passdb is configured.
# Named SQL connection: peer authentication as the dovecot role over the socket.
sql_driver = pgsql
pgsql /var/run/postgresql {
  parameters {
    dbname = mail
    user = dovecot
  }
}
passdb mailbox {
  driver = sql
  sql_query = SELECT username, domain, password FROM mailbox WHERE username = '%{user|username}' AND domain = '%{user|domain}' AND active
}
# App passwords: one row per label, so the login names the label (user@domain+label)
# and the query matches exactly one row. The identity returned is the mailbox.
passdb apppw {
  driver = sql
  sql_query = SELECT a.username, a.domain, a.password FROM app_password a JOIN mailbox m ON m.username = a.username AND m.domain = a.domain WHERE a.username || '@' || a.domain || '+' || a.label = '%{user}' AND a.active AND m.active
}
userdb mailbox {
  driver = sql
  sql_query = SELECT 5000 AS uid, 5000 AS gid FROM mailbox WHERE username = '%{user|username}' AND domain = '%{user|domain}' AND active
}

# Postfix talks to Dovecot over these sockets inside its chroot.
service auth {
  # Local lookups by lmtp and doveadm use this socket.
  unix_listener auth-userdb {
    mode = 0600
    user = dovecot
  }
  unix_listener auth-postfix {
    path = ` + DovecotAuthSocket + `
    mode = 0660
    user = postfix
    group = postfix
  }
}
service lmtp {
  unix_listener lmtp-postfix {
    path = ` + DovecotLMTPSocket + `
    mode = 0600
    user = postfix
    group = postfix
  }
}

# ManageSieve for clients (port 4190, STARTTLS required by ssl = required).
service managesieve-login {
  inet_listener sieve {
    port = 4190
  }
}

mail_plugins {
  quota = yes
}

mail_driver = maildir
mail_home = /var/vmail/%{user|domain}/%{user|username}
mail_path = /var/vmail/%{user|domain}/%{user|username}
mail_uid = 5000
mail_gid = 5000
first_valid_uid = 5000
`
}

// PostfixSetting is one postconf -e key=value pair.
type PostfixSetting struct{ Key, Value string }

// PostfixSettings returns the main.cf keys the mail stack depends on. Postfix
// keeps every other key from the distribution default.
func PostfixSettings(hostname string) []PostfixSetting {
	return []PostfixSetting{
		{"myhostname", hostname},
		{"myorigin", "$myhostname"},
		{"mydestination", "localhost"},
		{"mynetworks", "127.0.0.0/8 [::1]/128"},
		{"inet_interfaces", "all"},
		{"inet_protocols", "all"},
		{"smtpd_helo_required", "yes"},
		{"disable_vrfy_command", "yes"},
		{"virtual_mailbox_domains", "pgsql:" + PostfixMapDir + "/pgsql-virtual-domains.cf"},
		{"virtual_mailbox_maps", "pgsql:" + PostfixMapDir + "/pgsql-virtual-mailboxes.cf"},
		{"virtual_alias_maps", "pgsql:" + PostfixMapDir + "/pgsql-virtual-aliases.cf"},
		{"virtual_transport", "lmtp:unix:private/dovecot-lmtp"},
		{"smtpd_sasl_type", "dovecot"},
		{"smtpd_sasl_path", "private/auth"},
		{"smtpd_sasl_auth_enable", "yes"},
		{"smtpd_tls_cert_file", TLSFullchain},
		{"smtpd_tls_key_file", TLSPrivkey},
		{"smtpd_tls_security_level", "may"},
		{"smtpd_tls_auth_only", "yes"},
		{"smtp_tls_security_level", "may"},
		{"smtpd_relay_restrictions", "permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination"},
		{"smtpd_recipient_restrictions", "permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination"},
		{"smtpd_milters", "inet:" + PostfixMilterAddr},
		{"non_smtpd_milters", "inet:" + PostfixMilterAddr},
		{"milter_protocol", "6"},
		{"milter_default_action", "accept"},
	}
}

// PostfixSubmissionServices returns the postconf -M/-P calls for the submission
// (587, STARTTLS) and smtps (465, wrapper mode) services. Both require SASL login.
func PostfixSubmissionServices() [][]string {
	return [][]string{
		{"-M", "submission/inet=submission inet n - y - - smtpd"},
		{"-P", "submission/inet/smtpd_tls_security_level=encrypt"},
		{"-P", "submission/inet/smtpd_sasl_auth_enable=yes"},
		{"-P", "submission/inet/smtpd_recipient_restrictions=permit_sasl_authenticated,reject"},
		{"-M", "smtps/inet=smtps inet n - y - - smtpd"},
		{"-P", "smtps/inet/smtpd_tls_wrappermode=yes"},
		{"-P", "smtps/inet/smtpd_sasl_auth_enable=yes"},
		{"-P", "smtps/inet/smtpd_recipient_restrictions=permit_sasl_authenticated,reject"},
	}
}

// PostfixPgsqlMaps returns the three lookup tables. They connect as the postfix
// role over the unix socket (peer auth), so no password is stored.
func PostfixPgsqlMaps() map[string]string {
	common := "# Managed by mailadmin install.\nhosts = unix:/var/run/postgresql\ndbname = mail\nuser = postfix\n"
	return map[string]string{
		PostfixMapDir + "/pgsql-virtual-domains.cf": common +
			"query = SELECT name FROM domain WHERE name = '%s' AND active\n",
		PostfixMapDir + "/pgsql-virtual-mailboxes.cf": common +
			"query = SELECT 1 FROM mailbox m JOIN domain d ON d.name = m.domain " +
			"WHERE m.username = '%u' AND m.domain = '%d' AND m.active AND d.active\n",
		PostfixMapDir + "/pgsql-virtual-aliases.cf": common +
			"query = SELECT destination FROM alias WHERE active AND source IN ('%s', '@%d') " +
			"ORDER BY source = '%s' DESC LIMIT 1\n",
	}
}

// RspamdLocal returns the local.d overrides: the milter proxy, the controller
// password hash, DKIM signing per domain, and the selector map it reads.
func RspamdLocal(controllerHash string) map[string]string {
	return map[string]string{
		RspamdLocalDir + "/worker-proxy.inc": fmt.Sprintf(`# Managed by mailadmin install.
bind_socket = "%s";
milter = yes;
timeout = 120s;
upstream "local" {
  default = yes;
  self_scan = yes;
}
`, PostfixMilterAddr),
		RspamdLocalDir + "/worker-controller.inc": fmt.Sprintf(`# Managed by mailadmin install.
password = "%s";
`, controllerHash),
		RspamdLocalDir + "/dkim_signing.conf": fmt.Sprintf(`# Managed by mailadmin install.
enabled = true;
sign_authenticated = true;
sign_local = true;
use_domain = "header";
allow_username_mismatch = false;
use_redis = false;
selector_map = "%s";
path = "%s/$domain.$selector.key";
`, RspamdSelectorMap, DKIMDirPath),
	}
}

// RspamdSelectorMapContent renders "domain selector" lines for signing.
func RspamdSelectorMapContent(pairs [][2]string) string {
	var b strings.Builder
	b.WriteString("# Managed by mailadmin install: domain selector\n")
	for _, p := range pairs {
		fmt.Fprintf(&b, "%s %s\n", p[0], p[1])
	}
	return b.String()
}

// CaddyfileMain renders the main Caddyfile. The managed includes (autodiscovery,
// MTA-STS) are imported from CaddyIncludeDir, the mail host gets a certificate.
func CaddyfileMain(hostname string, tlsInternal bool) string {
	global := ""
	if tlsInternal {
		// Test mode: every site, including the includes, uses Caddy's local CA.
		global = "{\n\tlocal_certs\n}\n\n"
	}
	return fmt.Sprintf(`# Managed by mailadmin install. Includes are managed by mailadmin.
%simport %s/*.caddy

%s {
	respond "mailadmin" 404
}
`, global, CaddyIncludeDir, hostname)
}

// NftConf renders the firewall. Input is dropped by default. SSH ports come from sshd_config,
// so a bad element change cannot lock the operator out. The mail and web ports
// live in a set that mailadmin-fw-port edits. The helper saves the table to
// NftPersistPath, which this file includes on boot.
func NftConf() string {
	return `#!/usr/sbin/nft -f
# Managed by mailadmin install.
include "` + NftPersistPath + `"
`
}

// NftTableFile renders the mailadmin table with its port sets. It is used both at
// install time and as the persisted state the helper writes after each change.
func NftTableFile(tcp, udp, ssh []int) string {
	return fmt.Sprintf(`add table inet mailadmin
delete table inet mailadmin
# Managed by mailadmin install.
table inet mailadmin {
%s%s	chain input {
		type filter hook input priority 0; policy drop;
		ct state established,related accept
		iif "lo" accept
		meta l4proto { icmp, ipv6-icmp } accept
		tcp dport { %s } accept
		tcp dport @allowed_tcp accept
		udp dport @allowed_udp accept
	}
	chain forward {
		type filter hook forward priority 0; policy drop;
	}
	chain output {
		type filter hook output priority 0; policy accept;
	}
}
`, nftSet("allowed_tcp", tcp), nftSet("allowed_udp", udp), portList(ssh))
}

// nftSet renders one inet_service set. An empty set has no elements line, since
// nft rejects "elements = { }".
func nftSet(name string, ports []int) string {
	elements := ""
	if len(ports) > 0 {
		elements = "		elements = { " + portList(ports) + " }\n"
	}
	return fmt.Sprintf("\tset %s {\n\t\ttype inet_service\n%s\t}\n", name, elements)
}

func portList(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprint(p)
	}
	return strings.Join(parts, ", ")
}

// DefaultTCPPorts are the mail and web ports opened at install time: SMTP,
// submissions, smtps, IMAP over TLS, ManageSieve, and HTTP/HTTPS for ACME and autodiscovery.
var DefaultTCPPorts = []int{25, 80, 443, 465, 587, 993, 4190}

// FwPortHelper is the root helper that opens or closes one proto/port element.
// It validates every argument and writes the table back to NftPersistPath.
const FwPortHelper = `#!/bin/sh
# Managed by mailadmin install. Root helper: validated arguments only.
set -eu
verb=${1:-}; proto=${2:-}; port=${3:-}
case "$verb" in open|close|list) ;; *) echo "usage: $0 open|close|list tcp|udp PORT" >&2; exit 2 ;; esac
case "$proto" in tcp|udp) ;; *) echo "bad proto" >&2; exit 2 ;; esac
set_name="allowed_$proto"
if [ "$verb" = list ]; then
	exec /usr/sbin/nft list set inet mailadmin "$set_name"
fi
case "$port" in ''|*[!0-9]*) echo "bad port" >&2; exit 2 ;; esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { echo "bad port" >&2; exit 2; }
case "$verb" in
  open)  /usr/sbin/nft add element inet mailadmin "$set_name" "{ $port }" ;;
  close) /usr/sbin/nft delete element inet mailadmin "$set_name" "{ $port }" ;;
esac
tmp=$(mktemp /etc/nftables.d/.mailadmin.XXXXXX)
# add and delete come first, so reloading the file replaces the table instead of duplicating it.
{ echo 'add table inet mailadmin'; echo 'delete table inet mailadmin'; echo '# Managed by mailadmin install.'; /usr/sbin/nft list table inet mailadmin; } > "$tmp"
chmod 0600 "$tmp"
mv "$tmp" ` + NftPersistPath + `
`

// DKIMGenHelper creates a DKIM key pair once. It validates domain and selector,
// never overwrites an existing key, and writes the DNS record next to the key.
const DKIMGenHelper = `#!/bin/sh
# Managed by mailadmin install. Root helper: validated arguments only.
set -eu
domain=${1:-}; selector=${2:-}
case "$domain" in ''|*[!a-z0-9.-]*|.*|*..*) echo "bad domain" >&2; exit 2 ;; esac
case "$selector" in ''|[!a-z0-9]*|*[!a-z0-9._-]*) echo "bad selector" >&2; exit 2 ;; esac
dir=` + DKIMDirPath + `
key="$dir/$domain.$selector.key"
for f in "$key" "$key.pub"; do
  # mailadmin can write this directory, so a link here may have been planted.
  # Remove it so root never writes through it.
  if [ -L "$f" ]; then rm -f -- "$f"; fi
done
[ -e "$key" ] && exit 0
# Generate in a temp dir under /var/lib, then rename both files into place. /var/lib is
# writable by root only, and the temp dir must share a filesystem with the key directory,
# so the renames stay atomic. No directory that mailadmin or _rspamd can write sits on the
# write path, so neither can swap in a link. The key is renamed last: it is the commit
# point, so a run that dies midway leaves no key and the next run starts over. Signals go
# through the EXIT trap as well, which removes the temp dir.
parent=/var/lib
[ "$(stat -c %d "$parent")" = "$(stat -c %d "$dir")" ] || { echo "refusing: $dir is not on the same filesystem as $parent" >&2; exit 2; }
tmp=$(mktemp -d "$parent/.mailadmin-dkim.XXXXXX")
trap 'rc=$?; rm -rf -- "$tmp"; exit "$rc"' EXIT
trap 'exit 1' HUP INT TERM
umask 027
/usr/bin/rspamadm dkim_keygen -d "$domain" -s "$selector" -b 2048 -k "$tmp/key" -o dns > "$tmp/key.pub"
chown mailadmin:_rspamd "$tmp/key" "$tmp/key.pub"
chmod 0640 "$tmp/key" "$tmp/key.pub"
mv -fT -- "$tmp/key.pub" "$key.pub"
mv -fT -- "$tmp/key" "$key"
`

// CertSyncHelper copies the certificate Caddy obtained for the mail host into
// /etc/ssl/mail, and reloads postfix and dovecot only when the files changed.
//
// A changed certificate is swapped in two phases, because the DANE TLSA record
// pins the key. The new pair is staged in TLSDir/pending, the TLSA record is
// republished from it, and the swap happens on a later run once the DNS TTL has
// passed. Automatic renewal therefore waits for a successful TLSA publish: if the
// publish fails for another reason, the old pair stays in place and the next run
// retries. A domain without an automated DNS provider cannot publish a TLSA record,
// so its renewal is installed at once with a warning.
const CertSyncHelper = `#!/bin/sh
# Managed by mailadmin install. Root helper: copies the Caddy certificate for one host.
set -eu
host=${1:-}; domain=${2:-}
case "$host" in ''|*[!a-z0-9.-]*) echo "bad host" >&2; exit 2 ;; esac
case "$domain" in ''|*[!a-z0-9.-]*|.*|*..*) echo "bad domain" >&2; exit 2 ;; esac
install -d -m 0750 -o root -g root ` + TLSDir + `
pending=` + TLSDir + `/pending
marker=/var/lib/mailadmin/.cert-reload-pending
changed=0

# install_pair copies a certificate and key into place and records any change. Both files
# are staged first, so a failed copy leaves the live pair alone. Only then are they renamed,
# which keeps a copy error from leaving the new certificate next to the old key.
install_pair() {
	fc_new=0; pk_new=0
	if ! cmp -s "$1" ` + TLSFullchain + ` 2>/dev/null; then
		install -o root -g root -m 0600 "$1" ` + TLSFullchain + `.new; fc_new=1
	fi
	if ! cmp -s "$2" ` + TLSPrivkey + ` 2>/dev/null; then
		install -o root -g root -m 0600 "$2" ` + TLSPrivkey + `.new; pk_new=1
	fi
	if [ "$fc_new" = 1 ]; then mv ` + TLSFullchain + `.new ` + TLSFullchain + `; changed=1; fi
	if [ "$pk_new" = 1 ]; then mv ` + TLSPrivkey + `.new ` + TLSPrivkey + `; changed=1; fi
}

# The newest <host>.crt under the Caddy store. Its key is taken from the same directory.
crt=$(find ` + CaddyCertStore + ` -type f -name "$host.crt" -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -n 1 | cut -d' ' -f2-)
[ -n "$crt" ] || { echo "no certificate for $host yet" >&2; exit 3; }
key=$(dirname "$crt")/$host.key
[ -f "$key" ] || { echo "no key for $host next to its certificate" >&2; exit 3; }

if [ -e "$pending/since" ]; then
	# Phase two: install the pair that the TLSA record already pins, once the TTL has passed.
	since=$(cat "$pending/since")
	# A corrupt marker restarts the wait. It never skips it.
case "$since" in ''|*[!0-9]*) since=$(date +%s); date +%s > "$pending/since" ;; esac
	if [ $(( $(date +%s) - since )) -lt 3900 ]; then
		echo "pending certificate for $host waits for the DNS TTL" >&2
	else
		install_pair "$pending/fullchain.pem" "$pending/privkey.pem"
		rm -rf "$pending"
	fi
elif [ -e ` + TLSFullchain + ` ] && ! cmp -s "$crt" ` + TLSFullchain + ` 2>/dev/null; then
	# Phase one: stage the new pair and pin its TLSA record. The old pair stays in use.
	rm -rf "$pending"
	install -d -m 0750 -o root -g root "$pending"
	install -o root -g root -m 0600 "$crt" "$pending/fullchain.pem"
	install -o root -g root -m 0600 "$key" "$pending/privkey.pem"
	if out=$(MAILADMIN_MAIL_TLS_CERT="$pending/fullchain.pem" /usr/local/sbin/mailadmin --yes dns publish "$domain" --dane 2>&1); then
		date +%s > "$pending/since"
		exit 0
	fi
	case "$out" in
	*"manage its zone manually"*)
		# No automated DNS provider, so the TLSA record cannot be published from here.
		# The renewal goes ahead. DANE validation fails for this domain until the operator
		# publishes the new TLSA record by hand.
		echo "warning: $domain has no automated DNS provider, installing the renewed certificate without a TLSA update" >&2
		rm -rf "$pending"
		install_pair "$crt" "$key"
		;;
	*)
		printf '%s\n' "$out" >&2
		rm -rf "$pending"
		echo "TLSA publish failed for $domain, keeping the current certificate" >&2
		exit 1
		;;
	esac
else
	# First install, or the certificate is unchanged.
	rm -rf "$pending"
	install_pair "$crt" "$key"
fi

if [ "$changed" = 1 ] || [ -e "$marker" ]; then
	# A failed reload leaves the marker, so the next run retries it.
	if /usr/bin/systemctl reload-or-restart postfix dovecot rspamd >/dev/null 2>&1; then
		rm -f "$marker"
	else
		rm -f -- "$marker"
		set -C
		: > "$marker"
		set +C
		echo "reload failed, retrying on next run" >&2
		exit 4
	fi
fi
`

// CertSyncUnits returns the systemd service and timer that keep the mail
// certificate in sync with Caddy's renewals. The service gets the host and the
// primary domain, the domain is needed to republish the TLSA record.
func CertSyncUnits(hostname, domain string) (service, timer string) {
	service = fmt.Sprintf(`# Managed by mailadmin install.
[Unit]
Description=Copy the Caddy certificate for %s into /etc/ssl/mail
After=caddy.service

[Service]
Type=oneshot
ExecStart=%s %s %s
`, hostname, CertSyncHelperPath, hostname, domain)
	timer = `# Managed by mailadmin install.
[Unit]
Description=Sync the mail certificate from Caddy every six hours

[Timer]
OnBootSec=5min
OnUnitActiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target
`
	return service, timer
}

// AutoconfigFiles returns the client-configuration documents served by the
// managed Caddy sites. Thunderbird reads autoconfig.<domain>/mail/config-v1.1.xml
// and Outlook reads autodiscover.<domain>/autodiscover.xml. Caddy fills in the
// domain from the request host, so one template serves every hosted domain.
func AutoconfigFiles(hostname string) map[string]string {
	return map[string]string{
		webserver.DefaultAutoconfigRoot + "/mail/config-v1.1.xml": `<?xml version="1.0" encoding="UTF-8"?>
<!-- Managed by mailadmin install. -->
<clientConfig version="1.1">
  <emailProvider id="{{ trimPrefix "autoconfig." .Host }}">
    <domain>{{ trimPrefix "autoconfig." .Host }}</domain>
    <displayName>{{ trimPrefix "autoconfig." .Host }} mail</displayName>
    <incomingServer type="imap">
      <hostname>` + hostname + `</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>` + hostname + `</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>
`,
		webserver.DefaultAutodiscoverRoot + "/autodiscover.xml": `<?xml version="1.0" encoding="utf-8"?>
<!-- Managed by mailadmin install. -->
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <Protocol>
        <Type>IMAP</Type>
        <Server>` + hostname + `</Server>
        <Port>993</Port>
        <SSL>on</SSL>
        <AuthRequired>on</AuthRequired>
      </Protocol>
      <Protocol>
        <Type>SMTP</Type>
        <Server>` + hostname + `</Server>
        <Port>587</Port>
        <SSL>off</SSL>
        <AuthRequired>on</AuthRequired>
      </Protocol>
    </Account>
  </Response>
</Autodiscover>
`,
	}
}
