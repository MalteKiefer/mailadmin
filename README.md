# mailadmin

[![ci](https://github.com/MalteKiefer/mailadmin/actions/workflows/ci.yml/badge.svg)](https://github.com/MalteKiefer/mailadmin/actions/workflows/ci.yml)
[![release](https://github.com/MalteKiefer/mailadmin/actions/workflows/release.yml/badge.svg)](https://github.com/MalteKiefer/mailadmin/releases)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A single-binary, console-only administration CLI for a self-hosted multi-domain
mail server (Postfix + Dovecot + Rspamd + PostgreSQL, fronted by Caddy). It
manages domains, mailboxes, aliases, app passwords, DKIM/DNS, the mail queue,
services, logs, statistics, Sieve filters, the firewall/ban lists, and keeps an
audit trail of every change.

`mailadmin` is a static Go binary with no runtime dependencies. It runs as root
over SSH; there is no HTTP server and no web UI.

---

## Features

- **Domains** — add/remove/enable/disable, DKIM selector management, per-domain
  DNS record set, provider-driven publish/takeover/restore.
- **Mailboxes** — create/remove (with optional maildir purge), password change
  (argon2id via `doveadm`), quota, enable/disable, dedupe, and per-mailbox
  **app passwords**.
- **Aliases** — including catch-all.
- **DNS** — verify (`SPF/DKIM/DMARC/MX/MTA-STS/TLS-RPT/rDNS/autoconfig`), publish,
  migrate and zone takeover through a provider API (**Njalla, deSEC, Cloudflare,
  INWX, Servercow, servfail.network/PowerDNS**), with a full-zone snapshot taken
  before any destructive change and a `restore`. Grade posture with `dns audit`
  (`SPF/DKIM/DMARC/DNSSEC/DANE/MTA-STS/TLS-RPT/BIMI`). See [docs/DNS.md](docs/DNS.md).
- **DANE** — manage inbound-SMTP TLSA records (`dns show/publish --dane`, and a
  DANE check in `dns audit`), derived from the mail host's certificate, with a
  documented rollover for certificate renewals. See [docs/DNS.md](docs/DNS.md#dane-tlsa).
- **Security** — CrowdSec ban list, IP allowlist, and nftables firewall
  open/close with a protected-port guard.
- **Queue** — list/show/flush/hold/release/delete Postfix queue entries.
- **Services / logs** — allowlisted `systemctl` control and `journalctl`/Caddy
  log access.
- **Statistics** — inbound/outbound/spam/per-domain, parsed from Postfix and
  Rspamd logs.
- **Sieve** — show/set/edit user filters via ManageSieve.
- **Audit** — every mutation is recorded (actor, action, target, before/after).
- **doctor** — one-shot health check of services, ports, TLS, and Rspamd config.
- **Self-update** — `mailadmin version --check` and `mailadmin update` pull
  signed-by-checksum release binaries from GitHub.
- Global `-o table|json|plain` output, `--yes`, `--dry-run`, `-q`, `--config`.

---

## Command reference

```
mailadmin
  domain     list | show <d> | add <d> [--selector] [--dns manual|njalla|desec|cloudflare|inwx|servercow|servfail]
             | remove <d> | enable <d> | disable <d>
             | set-dkim <d> <sel> | regen-dkim <d> | set-provider <d> <provider>
  mailbox    list [--domain d] | show <a> | add <a> [--quota] | remove <a> [--purge]
             | passwd <a> | set-quota <a> <bytes> | enable <a> | disable <a> | dedupe <a>
             app-password list <a> | add <a> <label> | remove <a> <label>
  alias      list [--domain d] | show <src> | add <src> <dst> [--catch-all] | remove <src> [<dst>]
  dns        show <d> [--dane] | check <d> | publish <d> [--dane] | audit <d>
             | migrate <d> --to <p> (--from <p>|--axfr <ns>|--zonefile <f>|--probe) [--clean] [--create]
             | takeover <d> [--keep-web] | restore <d> <backup> | zone create <d>
  security   ban list|add <ip> [--dur] | remove <ip>
             allowlist list|add <ip>|remove <ip>
             firewall show | open <proto> <port> | close <proto> <port>
             overview
  queue      list | show <qid> | flush | hold <qid> | release <qid> | delete <qid>
  service    list | status <unit> | start|stop|restart|reload <unit>
  log        show <unit> [-n] | tail <unit>
  stats      inbound | outbound | spam | domain <d>
  sieve      show <a> | set <a> <file> | edit <a>
  audit      list [-n]
  doctor
  config     show | check | edit | init
  version [--check] | update | completion <shell>
```

Exit codes: `0` ok · `1` runtime error · `2` usage error · `3` not-found ·
`4` confirmation declined.

---

## Requirements

Server-side components `mailadmin` talks to (it does not install them):

| Component | Used for |
|-----------|----------|
| PostgreSQL | domain/mailbox/alias/app-password/audit tables (`mail` database, `mailadmin` role) |
| Postfix | MTA; queue management (`postqueue`/`postsuper`) and log stats |
| Dovecot | IMAP/POP + `doveadm` (password hashing, quota, Sieve, dedupe) |
| Rspamd | DKIM keygen + spam stats |
| Caddy | TLS termination + MTA-STS / autodiscovery hosting |
| CrowdSec | ban decisions (`cscli`) |
| nftables | firewall port sets |
| systemd / journald | service control + logs |

Privileged helper scripts (shipped separately under `/usr/local/libexec`, invoked
with validated argument vectors — never a shell string):

- `mailadmin-dkim-gen <domain> <selector>` — generate a DKIM key via `rspamadm`.
- `mailadmin-fw-port <open|close|list> <tcp|udp> <port>` — edit nftables sets.
- `mailadmin-mta-sts-sync` — regenerate the Caddy MTA-STS include.

Build/development requirements: **Go 1.26+** (see `go.mod`).

---

## Install

### From a release (recommended)

Download the binary for your platform from the
[releases page](https://github.com/MalteKiefer/mailadmin/releases) and verify it:

```sh
curl -fsSLO https://github.com/MalteKiefer/mailadmin/releases/latest/download/mailadmin-linux-amd64
curl -fsSLO https://github.com/MalteKiefer/mailadmin/releases/latest/download/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
sudo install -m 0755 mailadmin-linux-amd64 /usr/local/sbin/mailadmin
```

### From source

```sh
git clone https://github.com/MalteKiefer/mailadmin.git
cd mailadmin
make build-linux                 # -> dist/mailadmin-linux-amd64
sudo make install                # -> /usr/local/sbin/mailadmin
```

### Self-update

```sh
mailadmin version --check        # report whether a newer release exists
sudo mailadmin update            # download + verify checksum + atomically replace
```

`update` fetches the platform binary from the latest GitHub release, verifies it
against the release's `SHA256SUMS` over TLS, and atomically renames it over the
running executable (requires write access to the install path, i.e. root).

---

## Configuration

Two files, by default under `/etc/mailadmin` (create them with `mailadmin config init`).

### `config.toml` (world-readable, non-secret)

```toml
[postgres]
service      = "mail-admin"
service_file = "/var/lib/mailadmin/.pg_service.conf"

[mail]
hostname         = "mail.example.com"
dkim_dir         = "/var/lib/rspamd/dkim"
default_selector = "mail2026"
tls_cert         = "/etc/ssl/mail/fullchain.pem"   # optional; for DANE TLSA (else read via STARTTLS)

[server]
ipv4 = "203.0.113.10"
ipv6 = "2001:db8::10"

[dns]
resolver = "1.1.1.1:53"

[backup]
dns_backup_dir = "/var/lib/mailadmin/dns-backups"

[logs]
units = ["postfix", "dovecot", "rspamd", "caddy", "crowdsec", "postgresql"]
```

| Key | Meaning |
|-----|---------|
| `postgres.service` / `postgres.service_file` | libpq service name + `PGSERVICEFILE` for peer-auth connection |
| `mail.hostname` | MX / mail host FQDN |
| `mail.dkim_dir` | Rspamd DKIM key directory |
| `mail.default_selector` | default DKIM selector for new domains |
| `mail.tls_cert` | optional PEM path for DANE TLSA generation (else read live via STARTTLS) |
| `server.ipv4` / `server.ipv6` | addresses used when generating DNS records |
| `dns.resolver` | resolver for `dns check` (fixed; never user-supplied) |
| `backup.dns_backup_dir` | where zone snapshots are written (0700 dir, 0600 files) |
| `logs.units` | allowlist of units `log`/`stats` may read |

### `secrets.env` (mode 0600, root only)

```sh
# DNS provider credentials — set only the one you use.
NJALLA_TOKEN=
DESEC_TOKEN=
CLOUDFLARE_API_TOKEN=
INWX_USER=
INWX_PASSWORD=
INWX_SHARED_SECRET=        # base32 TOTP seed; only if the INWX account has 2FA
SERVERCOW_USERNAME=
SERVERCOW_PASSWORD=
SERVFAIL_API_KEY=
SERVFAIL_SERVER=           # primary-NS server id incl. trailing dot (from the zone SOA)
RSPAMD_CONTROLLER_PW=
```

Set the credentials for whichever DNS provider you use. Secrets are loaded into memory
only; they are **never** logged, echoed, printed in errors, or included in
`-o json` output. `MAILADMIN_*` environment variables override config keys.

Inspect configuration without revealing secrets:

```sh
mailadmin config show      # redacted view
mailadmin config check     # validates paths, permissions, configured secrets
```

---

## DNS providers & takeover

`mailadmin dns` can drive a provider API to publish the desired record set:

- **Njalla** (`--dns njalla`, `NJALLA_TOKEN`)
- **deSEC** (`--dns desec`, `DESEC_TOKEN`)
- **Cloudflare** (`--dns cloudflare`, `CLOUDFLARE_API_TOKEN` — an API Token with
  Zone:DNS:Edit on the zone)
- **INWX** (`--dns inwx`, `INWX_USER` + `INWX_PASSWORD`, plus `INWX_SHARED_SECRET`
  if the account uses 2FA)
- **Servercow** (`--dns servercow`, `SERVERCOW_USERNAME` + `SERVERCOW_PASSWORD` —
  the DNS-API credentials, not the panel login)
- **servfail.network** (`--dns servfail`, `SERVFAIL_API_KEY` + `SERVFAIL_SERVER` —
  a hosted PowerDNS; the server id is the primary-NS FQDN incl. trailing dot)
- **manual** (`--dns manual`) — records are only displayed for you to publish.

Takeover is safe by construction: `dns takeover <d>` snapshots the entire zone to
`backup.dns_backup_dir` before replacing records, and `dns restore <d> <backup>`
puts it back. Reconciliation is idempotent and orders changes so a record slot is
never briefly empty. Use `--dry-run` to print the plan without touching anything.

Beyond publish/takeover, `dns migrate` copies a whole zone into a provider (from
another provider's API, AXFR, a zonefile, or public-DNS probe; `--clean` for a 1:1
replacement), `domain set-provider` points a domain at a backend afterwards,
`dns audit` grades mail-security posture, and `dns show/publish --dane` manage DANE
TLSA records. The full workflow, including DANE certificate-renewal rollover, is
documented in **[docs/DNS.md](docs/DNS.md)**.

---

## Security

- **Injection** — all SQL is parameterized (pgx `$n`); there is no `sh -c`.
  Every external command runs through one audited chokepoint (`internal/sys`) as
  an argument slice from an absolute path with a context timeout and capped
  output. All external tokens are validated/normalized in `internal/valid`
  (domain, address, queue-id `^[A-F0-9]{6,16}$`, IP, CIDR, port, proto, unit,
  selector, duration).
- **Least privilege** — `systemctl` and `nft`/`cscli` are gated by explicit
  allowlists; no wildcards.
- **Crypto / TLS** — mailbox passwords are argon2id; all outbound HTTPS pins
  TLS 1.2+ with certificate verification; no MD5/SHA1/DES/RC4. Self-update
  downloads are checksum-verified. The sole `InsecureSkipVerify` is the DANE
  STARTTLS probe, which reads the certificate to fingerprint it (chain trust is
  irrelevant — DANE pins the presented key), not to authenticate a session.
- **Secrets** — 0600 `secrets.env`, redacted in every output path, read from the
  TTY (never argv).
- **Audit** — every mutation writes an `audit_log` row; DNS takeovers snapshot
  the zone first.

A full audit (OWASP Top 10 / ASVS / SOC 2, with CVSS-scored findings) lives in
[`docs/SECURITY-AUDIT.md`](docs/SECURITY-AUDIT.md). Architecture and engineering
requirements are in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and
[`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md).

---

## Development

```sh
make check      # gofmt + vet + go test -race + staticcheck + gosec + govulncheck
make test       # unit tests
make build      # host build into ./mailadmin
```

The same gates run in CI on every push/PR (`.github/workflows/ci.yml`).

### Releasing

Tag a version and push it — the release workflow builds the static
`linux/amd64` + `linux/arm64` binaries, generates `SHA256SUMS`, and publishes a
GitHub release that `mailadmin update` can consume:

```sh
git tag v1.18.0
git push origin v1.18.0
```

The version embedded in the binary comes from the tag
(`-ldflags -X mailadmin/internal/cli.Version=<tag without v>`).

---

## License

[MIT](LICENSE) © Malte Kiefer
