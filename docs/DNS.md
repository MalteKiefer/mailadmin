# DNS & DANE

`mailadmin dns` manages a domain's mail DNS: it shows the desired record set,
verifies live DNS, publishes and reconciles records through a provider API,
migrates a zone between providers, grades mail-security posture, and manages
inbound-SMTP **DANE** (TLSA) including automatic rollover across certificate
renewals.

- [Providers](#providers)
- [The desired record set](#the-desired-record-set)
- [`dns show` / `dns check`](#dns-show--dns-check)
- [`dns publish`](#dns-publish)
- [`dns migrate`](#dns-migrate)
- [`domain set-provider`](#domain-set-provider)
- [`dns audit`](#dns-audit)
- [DANE (TLSA)](#dane-tlsa)
  - [Deriving the record](#deriving-the-record)
  - [Publishing](#publishing)
  - [Certificate renewal & rollover](#certificate-renewal--rollover)
- [`dns takeover` / `dns restore`](#dns-takeover--dns-restore)

---

## Providers

A domain's `dns_provider` (stored in the database) decides which backend API
`mailadmin dns` drives. Set it with [`domain add --dns`](#domain-set-provider) or
[`domain set-provider`](#domain-set-provider). Credentials live in `secrets.env`.

| Provider | `--dns` value | Credentials |
|----------|---------------|-------------|
| Njalla | `njalla` | `NJALLA_TOKEN` |
| deSEC | `desec` | `DESEC_TOKEN` |
| Cloudflare | `cloudflare` | `CLOUDFLARE_API_TOKEN` (Zone:DNS:Edit) |
| INWX | `inwx` | `INWX_USER`, `INWX_PASSWORD`, `INWX_SHARED_SECRET` (if 2FA) |
| Servercow | `servercow` | `SERVERCOW_USERNAME`, `SERVERCOW_PASSWORD` (DNS-API creds) |
| servfail.network | `servfail` | `SERVFAIL_API_KEY`, `SERVFAIL_SERVER` (primary-NS FQDN, trailing dot) |
| manual | `manual` | none — records are only printed for you to publish |

deSEC's API throttles writes; `mailadmin` transparently retries on `429` (honouring
`Retry-After`) and on transient `502/503/504` (exponential backoff), so a large
publish or migration completes without dropped records.

---

## The desired record set

`mailadmin` derives the correct mail record set for a domain from its config and
DKIM key: MX, SPF, DKIM, DMARC, the autoconfig/autodiscover CNAMEs and SRVs,
TLS-RPT, and — with `--with-mta-sts` — the MTA-STS records. DANE TLSA is managed
separately (see [DANE](#dane-tlsa)) because it is derived from the TLS certificate.

---

## `dns show` / `dns check`

```sh
mailadmin dns show <domain> [--with-mta-sts]     # print the desired record set
mailadmin dns check <domain>                     # diff desired vs. live public DNS
```

`check` resolves live DNS through the fixed `dns.resolver` and reports, per record,
whether it matches, drifts (old → new), or is missing.

---

## `dns publish`

```sh
mailadmin dns publish <domain> [--with-mta-sts] [--dry-run]
```

Reconciles the desired record set at the domain's provider: idempotent, ordered so
a record slot is never briefly empty, and never destructive beyond replacing the
records it manages. `--dry-run` prints the plan without touching the zone.

The domain must be on an automated provider (not `manual`); otherwise set one with
[`domain set-provider`](#domain-set-provider).

---

## `dns migrate`

Copy an existing zone into an automated provider — e.g. when moving registrars or
adopting `mailadmin` for a domain hosted elsewhere.

```sh
mailadmin dns migrate <domain> --to <provider> [source] [--clean] [--create] [--dry-run]
```

Pick exactly one **source**:

| Flag | Source |
|------|--------|
| `--from <provider>` | read via that provider's API (njalla/desec/cloudflare/inwx/servercow/servfail) |
| `--axfr <ns>` | zone transfer (AXFR) from a nameserver |
| `--zonefile <file>` | a BIND-format zone export |
| `--probe` | best-effort discovery via public DNS (fallback) |

Behaviour:

- **NS and SOA are never copied** — delegation belongs to the target zone.
- Existing target records are left untouched; nothing is deleted **unless** you
  pass `--clean`, which wipes the target (all records except NS/SOA) after a
  confirmation, for a clean 1:1 replacement.
- `--create` creates the zone at the target first (deSEC) and prints the
  nameservers + DNSSEC DS records to set at your registrar.
- The per-record result table shows a **reason** for any failure (e.g. rate
  limiting), so re-running (which skips records already present) is easy.
- On success, migrate offers to point the domain's `dns_provider` at the target
  so `dns publish` works immediately.

```sh
# Move kiefer-networks.de from servfail into deSEC, replacing the target 1:1:
mailadmin dns migrate kiefer-networks.de --from servfail --to desec --clean
```

---

## `domain set-provider`

```sh
mailadmin domain set-provider <domain> <manual|njalla|desec|cloudflare|inwx|servercow|servfail>
```

Points a domain at a DNS backend so `dns publish` (and DANE) manage its zone via
that provider's API. `dns migrate` copies records but leaves the provider
unchanged, so this is the follow-up (migrate also offers to do it for you).

---

## `dns audit`

Grades a domain's mail-security posture from live public DNS — correctness and
policy strength per RFC, for **any** domain (including externally hosted ones).

```sh
mailadmin dns audit <domain> [--selector <sel> ...]
```

Checks: **SPF** (presence, uniqueness, all-qualifier, 10-lookup limit), **DKIM**
(per selector: presence, non-revocation, key strength), **DMARC** (policy strength,
reporting), **DNSSEC** (signed / delegated / validated), **DANE** (TLSA present and
DNSSEC-authenticated), **MTA-STS** (record + fetched policy), **TLS-RPT**, and
**BIMI** (cross-checked against DMARC). Each finding is `pass` / `warn` / `fail` /
`info`; the exit status reflects the worst finding.

---

## DANE (TLSA)

DANE (DNS-based Authentication of Named Entities, RFC 7672) lets a sending MTA
verify your mail server's TLS certificate against a **TLSA** record published in
DNS, instead of trusting the public CA system alone. It only works when the zone
is DNSSEC-signed — the TLSA must be authenticated.

`mailadmin` manages inbound-SMTP DANE: a `3 1 1` TLSA record (usage **DANE-EE**,
selector **SPKI**, matching **SHA-256** — it pins the certificate's public key) at
`_25._tcp.<mail-host>`.

### Deriving the record

The TLSA value is computed from the mail host's certificate:

1. from the PEM at `mail.tls_cert` in `config.toml` when set, else
2. live via SMTP STARTTLS on port 25 (what a DANE verifier actually sees).

```sh
mailadmin dns show <domain> --dane
# TLSA for mail.example.com derived from file:/etc/ssl/mail/fullchain.pem
# TYPE  NAME           PRIO  CONTENT
# TLSA  _25._tcp.mail  0     3 1 1 <sha256-of-spki>
```

Configure a cert path so the value is deterministic (independent of whether the
daemon has already reloaded the new cert):

```toml
[mail]
tls_cert = "/etc/ssl/mail/fullchain.pem"
```

(Also settable via `MAILADMIN_MAIL_TLS_CERT`.)

### Publishing

```sh
mailadmin dns publish <domain> --dane [--dry-run]
```

Publishes the TLSA at the provider. The publish is **additive** — an existing TLSA
value is kept, which is exactly what a certificate rollover needs (both the old and
new values are valid, so a verifier matches either). The audit trail records every
publish.

### Certificate renewal & rollover

> **Important:** a `3 1 1` record pins the certificate's public key. If your ACME
> client rotates the key on renewal (Caddy/CertMagic does; Let's Encrypt/certbot
> does unless you use `--reuse-key`), the TLSA must be **republished** on every
> renewal, or DANE-validating senders will fail to deliver.

Two ways to stay valid:

1. **Reuse the key across renewals** (e.g. `certbot renew --reuse-key`) so the
   pinned SPKI never changes. Not available with Caddy/CertMagic.
2. **Republish on renewal** with a safe rollover order. Publish the new TLSA
   *before* the daemon serves the new certificate, wait out the record TTL so
   resolvers see it, then reload.

A worked example for a Caddy-issued cert deployed to Postfix/Dovecot, driven by a
systemd `path` unit that watches Caddy's certificate:

`/usr/local/sbin/mail-cert-deploy` (excerpt — install new cert, then rollover):

```bash
umask 027
install -o root -g mail-certs -m 0640 "$SRC_CRT" /etc/ssl/mail/fullchain.pem
install -o root -g mail-certs -m 0640 "$SRC_KEY" /etc/ssl/mail/privkey.pem

# DANE rollover: publish the NEW leaf's TLSA (mailadmin reads the just-installed
# fullchain.pem via mail.tls_cert, so it pins the new key). Additive — the old
# TLSA stays valid during the overlap. Wait out the TTL so validators see the new
# TLSA before we switch the served cert, then reload.
if mailadmin --yes dns publish "$DOMAIN" --dane; then
  sleep 3900            # > TLSA TTL (deSEC minimum is 3600)
fi
systemctl reload-or-restart postfix dovecot || true
```

Because the script sleeps out the TTL, give the oneshot service an unbounded start
timeout:

```ini
# /etc/systemd/system/mail-cert-deploy.service.d/timeout.conf
[Service]
TimeoutStartSec=infinity
```

With this in place, DANE survives every automatic key rotation with no delivery
outage. Verify at any time with `mailadmin dns audit <domain>` (DANE should read
`pass — N TLSA, authenticated`).

---

## `dns takeover` / `dns restore`

```sh
mailadmin dns takeover <domain> [--keep-web] [--with-mta-sts] [--dry-run]
mailadmin dns restore  <domain> <backup>
```

`takeover` replaces the **entire** zone with the mail record set, snapshotting it
to `backup.dns_backup_dir` first; `--keep-web` preserves apex/www A/AAAA/CNAME.
`restore` puts a snapshot back. Both are destructive — use `--dry-run` to preview.
