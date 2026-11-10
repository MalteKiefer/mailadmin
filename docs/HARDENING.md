# System hardening

`mailadmin install` hardens the host it installs on. The controls follow the BSI
IT-Grundschutz module SYS.1.3 (Linux server) and the CIS Debian Linux Benchmark,
Level 1 and Level 2, where a control fits a dedicated mail host. Every file is
written as a drop-in owned by mailadmin, so a rerun of `install --adopt`
converges the host to the same state.

## SSH

File: `/etc/ssh/sshd_config.d/00-mailadmin-hardening.conf` (loaded first, so it
wins over later drop-ins such as cloud-init's).

- Public key login only. Password and keyboard-interactive login are off, but
  only when the account the operator logged in with (the audit login uid, which
  survives sudo and su) last logged in over SSH with a key from its
  `authorized_keys` that the hardened sshd accepts: Ed25519 or ECDSA (also as
  FIDO keys), or RSA with at least 3072 bits, not bound to a forced command or
  `restrict`. Install reads that login from sshd's journal and matches the key
  fingerprint. If it cannot prove this (no login uid, an account outside
  /etc/passwd, a password or certificate login, no journal entry), password
  login stays on and install prints why, so the operator cannot be locked out.
- `PermitRootLogin prohibit-password`, unless the operator logs in as root
  without such a key, or the login account is unknown; then root login stays as
  configured.
- `RequiredRSASize 3072`, unless the operator or root last logged in with a
  shorter (or unknown) RSA key; install then warns instead of cutting that key off.
- `MaxAuthTries 3`, `MaxSessions 2`,
  `LoginGraceTime 30`, `MaxStartups 10:30:60`, idle sessions closed after 10
  minutes, `TCPKeepAlive no` (the keepalive runs inside the encrypted channel).
- No forwarding of any kind (`DisableForwarding`, TCP, agent, X11, tunnels).
- Key exchange: `mlkem768x25519-sha256` (hybrid post-quantum), `sntrup761x25519`,
  `curve25519`. Ciphers: `chacha20-poly1305`, AES-GCM. MACs: SHA-2 ETM and
  `umac-128-etm`. Host keys: Ed25519 and RSA (3072 bit minimum). User keys:
  Ed25519, ECDSA and RSA (3072 bit minimum), also as certificates. Each list is cut
  to what the installed OpenSSH supports, so the file also works on older releases.
- The config is checked with `sshd -t` before the reload. A rejected config is
  rolled back.

Note: `MaxAuthTries 3` counts every key an SSH agent offers. If the agent holds
several keys, connect with `-o IdentitiesOnly=yes -i <key>`.

## TLS

Postfix (inbound and outbound) and Dovecot use one policy:

- TLS 1.2 and 1.3 only.
- TLS 1.2: ECDHE with AES-GCM or ChaCha20-Poly1305 only (forward secrecy, AEAD).
- TLS 1.3: `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`,
  `TLS_AES_128_GCM_SHA256`.
- Groups: `X25519MLKEM768` (hybrid post-quantum, OpenSSL 3.5 or newer), then
  `X25519`, `P-256`, `P-384`.
- The server picks the cipher. Compression and renegotiation are off.

Port 25 keeps opportunistic TLS (`smtpd_tls_security_level = may`, RFC 3207 and
RFC 7435): a sender without TLS can still deliver. Submission (465, 587), IMAP
(993) and ManageSieve (4190) require TLS. The cleartext IMAP port 143 is closed.

Caddy uses Go's TLS defaults (TLS 1.2 and 1.3, AEAD only, X25519MLKEM768 first)
and sends HSTS on the mail host.

## Postfix

- HELO, sender and recipient must be fully qualified; unknown sender and
  recipient domains are rejected; pipelining before the greeting is rejected.
- Per-client rate limits for connections, messages, recipients and AUTH.
- The banner shows no software or version.

## Kernel and system

| Area | Control |
| --- | --- |
| sysctl (`/etc/sysctl.d/90-mailadmin-hardening.conf`) | kernel pointer and dmesg restriction, ptrace scope 2, no unprivileged BPF, BPF JIT hardening, kexec off, SysRq off, full ASLR, protected links, FIFOs and regular files, no SUID core dumps, no ICMP redirects, no source routing, reverse path filter, martian logging, SYN cookies |
| Kernel modules (`/etc/modprobe.d/mailadmin-hardening.conf`) | cramfs, freevxfs, hfs, hfsplus, jffs2, udf, usb-storage, dccp, sctp, rds, tipc, firewire, bluetooth cannot load |
| Core dumps | off (`limits.d` and systemd-coredump) |
| Logging | journald persistent and compressed |
| Audit | auditd with rules for identities, sudoers, SSH config, mailadmin config, DKIM keys, TLS keys, firewall, logins, module loads and root commands of logged-in users |
| Brute force | CrowdSec agent with the linux, sshd, postfix and dovecot collections, reading the journal, and the nftables bouncer (bans in CrowdSec's own table). Install reads the acquisition files that already exist and adds a journal source only for sshd, Postfix or Dovecot when no other source reads them (a file source counts only when the file exists), so no log line is counted twice. Install creates the allowlist `mailadmin` that `security allowlist` manages. The CrowdSec repository key is checked like the PGDG and Caddy keys (`--crowdsec-fingerprint`). With `--crowdsec-enroll-key` (asked during an interactive install) the instance joins the CrowdSec console. The agent shares attack signals with the CrowdSec central API in return for the community blocklist. |
| File integrity | AIDE, baseline built in the background on the first install, checked daily by Debian's timer |
| MAC | AppArmor enabled |
| Time | NTP sync enabled |
| Accounts | `login.defs`: umask 027, password aging, yescrypt with cost factor 7; pwquality minimum length 14; private `$TMPDIR` per session (libpam-tmpdir) |
| Accounting | process accounting (acct) and sysstat |
| Packages | debsums for package file verification |
| PostgreSQL | config files readable by the postgres group only |
| Cron | `/etc/crontab` and the cron directories root only |
| Services | avahi, cups, rpcbind and bluetooth disabled if installed |
| Banner | `/etc/issue` and `/etc/issue.net` with a legal notice |

## Updates

unattended-upgrades installs every update from the distribution (release,
updates, security) and from the PostgreSQL, Caddy and CrowdSec repositories, removes
unused packages and kernels, and reboots at 04:00 when an update needs it.
needrestart restarts services after library updates. Install starts one update run
right away, so a new host does not wait for the daily timer.

mailadmin itself runs with umask 022, so files it creates for other services
(apt keyrings, Caddy includes, the MTA-STS web root, rspamd config) stay
readable for them even under the hardened login umask 027.

`mailadmin update` replaces only the binary. The helpers, units and hardening
files change with `mailadmin install --adopt`, so run it after an update.

## Deviations

These controls are left out on purpose:

- Root login over SSH stays possible with a key (`prohibit-password`), because
  mailadmin runs as root. CIS asks for `PermitRootLogin no` with a separate
  admin user and sudo.
- Separate partitions for `/tmp`, `/var`, `/var/log`, `/home` with `nodev`,
  `nosuid` and `noexec` (CIS 1.1) cannot be created after the system is installed.
- No bootloader password: cloud hosts have no interactive console boot.
- IP forwarding and IPv6 router advertisements keep their defaults. Forwarding
  is off unless something else enabled it, and cloud hosts may receive their
  IPv6 configuration through router advertisements.
- auditd is not set to immutable (`-e 2`), so rules can change without a reboot.
- `kernel.modules_disabled` stays 0: systemd applies sysctl settings before
  nftables loads its kernel modules at boot, so the firewall would not come up.
- SSH stays on port 22. A different port hides nothing from a scan and the
  firewall rules follow the port sshd uses.
- No malware scanner (ClamAV needs more memory than a small mail host has),
  no remote syslog (needs a log host), no AIDE checksum tuning beyond the
  Debian defaults, no per-unit systemd sandboxing of the distribution services.
- Port 25 accepts mail without TLS from senders that cannot do TLS, as
  RFC 7435 recommends for opportunistic encryption between MTAs.
