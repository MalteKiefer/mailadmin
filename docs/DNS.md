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
- [`domain set-bimi`](#domain-set-bimi)
- [DKIM rotation](#dkim-rotation)
- [`dns drift-check`](#dns-drift-check)

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
mailadmin dns check <domain> --registrar         # diff desired vs. live at the DNS provider (API)
```

`check` resolves live DNS through the fixed `dns.resolver` and reports, per record,
whether it matches, drifts (old → new), or is missing. With `--registrar` it queries
the API of the domain's configured provider instead of public DNS and additionally
lists stale records not part of the mail set. `--njalla` / `--desec` force that
specific provider's API regardless of the domain's configured `dns_provider` — handy
for verifying a zone before switching the domain over to it.

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

[`scripts/mail-cert-deploy.sh`](../scripts/mail-cert-deploy.sh) in this repo is
the source of truth for the script — deploy it to
`/usr/local/sbin/mail-cert-deploy` on the mail server (see the header comment
in that file for the exact deploy steps and for the assumptions made about the
scaffolding around the excerpt below, since only the core install+rollover
logic was ever pinned down here). Core of the script — install the new cert,
then roll DANE over:

```bash
umask 027
# Keep the served pair so a failed TLSA publish can roll back.
prev=$(mktemp -d)
cp -p /etc/ssl/mail/fullchain.pem /etc/ssl/mail/privkey.pem "$prev"/ 2>/dev/null || true
restore_prev() {
  if [ -f "$prev/fullchain.pem" ] && [ -f "$prev/privkey.pem" ]; then
    install -o root -g root -m 0600 "$prev/fullchain.pem" /etc/ssl/mail/fullchain.pem
    install -o root -g root -m 0600 "$prev/privkey.pem" /etc/ssl/mail/privkey.pem
  fi
}
# A failed copy can leave a mixed pair on disk, so restore the previous pair.
if ! { install -o root -g root -m 0600 "$SRC_CRT" /etc/ssl/mail/fullchain.pem &&
       install -o root -g root -m 0600 "$SRC_KEY" /etc/ssl/mail/privkey.pem; }; then
  restore_prev
  rm -rf "$prev"
  echo "mail-cert-deploy: installing the new cert failed, previous cert files restored" >&2
  exit 1
fi

# DANE rollover: publish the NEW leaf's TLSA (mailadmin reads the just-installed
# fullchain.pem via mail.tls_cert, so it pins the new key). Additive — the old
# TLSA stays valid during the overlap. Wait out the TTL so validators see the new
# TLSA before we switch the served cert, then reload.
if out=$(mailadmin --yes dns publish "$DOMAIN" --dane 2>&1); then
  sleep 3900            # > TLSA TTL (deSEC minimum is 3600)
else
  case "$out" in
  *"manage its zone manually"*)
    # No automated DNS provider: the TLSA record cannot be published from here, so the
    # renewal goes ahead. DANE validation fails for this domain until the new TLSA
    # record is published by hand.
    echo "warning: $DOMAIN has no automated DNS provider, continuing without a TLSA update; publish the new TLSA record by hand" >&2
    ;;
  *)
    printf '%s\n' "$out" >&2
    restore_prev
    rm -rf "$prev"
    echo "mail-cert-deploy: TLSA publish failed, previous cert files restored, reload skipped" >&2
    exit 1
    ;;
  esac
fi
rm -rf "$prev"
if ! systemctl reload-or-restart postfix dovecot; then
  echo "mail-cert-deploy: reload failed, postfix and dovecot still serve the old certificate; reload them by hand" >&2
  exit 1
fi
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

### Verifying DANE actually works

Publishing the TLSA record is only half of DANE. Two commands confirm it is
effective:

- `mailadmin dns audit <domain>` — the **DANE** finding now also fetches the
  live certificate over STARTTLS and confirms the published `3 1 1` TLSA still
  matches it. A stale TLSA (after a key rotation without `--reuse-key`) shows as
  **fail** — *"published TLSA does not match live certificate"* — which is
  exactly what DANE senders would reject. An unreachable mail host downgrades to
  a warning rather than a false pass.

- `mailadmin doctor` — checks the Postfix side on the mail host:
  - **dane-outbound**: `smtp_tls_security_level` is `dane`/`dane-only` and
    `smtp_dns_support_level=dnssec`. `dane` is opportunistic (falls back to
    plaintext when a peer has no signed TLSA); `dane-only` never falls back.
  - **dane-smtpd-cert**: `smtpd_tls_cert_file` matches the cert that feeds the
    TLSA (`mail.tls_cert`), catching deploy-path drift.
  - **dane-resolver**: a loopback nameserver in `/etc/resolv.conf` — outbound
    DANE needs a local validating resolver to trust the DNSSEC AD flag
    (best-effort check).

---

## `dns takeover` / `dns restore`

```sh
mailadmin dns takeover <domain> [--keep-web] [--with-mta-sts] [--dry-run]
mailadmin dns restore  <domain> <backup>
```

`takeover` replaces the **entire** zone with the mail record set, snapshotting it
to `backup.dns_backup_dir` first; `--keep-web` preserves apex/www A/AAAA/CNAME.
`restore` puts a snapshot back. Both are destructive — use `--dry-run` to preview.

---

## `domain set-bimi`

```sh
mailadmin domain set-bimi <domain> --logo-url <https-url> [--logo-file <path>] [--vmc-url <https-url>]
```

Computes and publishes the `default._bimi` TXT record
(`v=BIMI1; l=<logo-url>[; a=<vmc-url>]`) through the same
Plan/Reconcile path `dns publish` uses — it respects `--dry-run` and the
domain's configured `dns_provider` (manual just prints the record; an
automated provider publishes it after confirmation).

**Hosting design decision:** mailadmin does **not** host the logo or the VMC.
An alternative was considered — a managed Caddy web root at `/srv/caddy/bimi`,
mirroring `internal/webserver`'s autodiscovery/MTA-STS include pattern — but
was rejected: BIMI logos must satisfy constraints mailadmin cannot check or
obtain on the operator's behalf (full SVG Tiny PS conformance, and — for the
checkmark to actually render in most mailbox providers — a Verified Mark
Certificate issued by a commercial CA against the *exact* hosted bytes).
Hosting it locally would not remove that dependency, only add a Caddy include
and reload path for no real benefit. So: host the SVG (and VMC, if you have
one) yourself at a stable HTTPS URL, then run `set-bimi` to publish the
pointer record.

`--logo-file` is optional and purely a local sanity check: it parses the file
as XML and confirms the root `<svg>` carries `baseProfile="tiny-ps"` — the two
most common mistakes (not valid XML at all, or a normal SVG export missing the
BIMI profile). It is **not** a full SVG Tiny PS conformance check.

BIMI only displays once DMARC enforces (`p=quarantine` or `p=reject`) — see
[`dns audit`](#dns-audit)'s BIMI finding, which now points here when no record
is published yet.

---

## DKIM rotation

```sh
mailadmin domain dkim-rotate-start  <domain> [--selector <new-selector>]
mailadmin domain dkim-rotate-finish <domain> <new-selector> [--remove-old]
```

`domain set-dkim` / `domain regen-dkim` cut over **instantly**: a new key is
generated and the domain's row is updated to the new selector in one step.
That is fine when the old key is not worth keeping alive, but it means any
DNS resolver still caching the old public key sees a mismatch the moment
signing switches — a real, if usually brief, delivery risk during
propagation.

`dkim-rotate-start`/`dkim-rotate-finish` split that into two explicit steps
with an overlap window, no instant cutover:

1. **`dkim-rotate-start`** generates a **new** key under a **new** selector
   and publishes **both** the current and new selector's DKIM TXT records.
   The domain keeps *signing* with the old selector throughout — nothing
   about mail delivery changes yet. The new selector defaults to
   `<current>-<YYYYMMDD>`, or pass `--selector` explicitly. The command
   prints the selector it used; **mailadmin does not persist rotation state**
   between the two steps, so note it down (or use an explicit `--selector`)
   if you're not running `dkim-rotate-finish` right away.
2. Wait for DNS to propagate — at least the record TTL, longer for a
   comfortable margin.
3. **`dkim-rotate-finish <domain> <new-selector>`** performs the DB cutover
   (`SetDKIMSelector`) that `set-dkim`/`regen-dkim` do instantly, now as an
   explicit, deliberate step once the new key is known-good in DNS.

**Old-record grace period (tradeoff):** by default `dkim-rotate-finish`
leaves the old selector's DNS record published after cutover. It costs
nothing (an unused TXT record) and is safer — any mail that was queued or is
still being verified against the old signature keeps working. Pass
`--remove-old` to delete it immediately instead, once you're confident
nothing still depends on it.

Both `set-dkim`/`regen-dkim` (instant, no-overlap) and
`dkim-rotate-start`/`dkim-rotate-finish` (two-step, overlapping) stay
available — pick whichever fits the situation.

---

## `dns drift-check`

```sh
mailadmin dns drift-check <domain>          # one domain
mailadmin dns drift-check --all             # every domain
mailadmin dns drift-check --all -o json     # machine-parseable summary
```

Runs the exact same desired-vs-live public DNS comparison as
[`dns check`](#dns-show--dns-check) — it is a thin wrapper, not a second
implementation of the diffing logic — but is shaped for unattended use: it
**exits non-zero** (runtime error, exit code 1) if any record is missing or
has drifted, so it can be dropped straight into a cron job or systemd timer.
`-o json` emits one object per domain (`domain`, `total`, `matched`,
`drift`), for a monitoring script to parse instead of scraping table output.

See [`docs/DNS-DRIFT-MONITORING.md`](DNS-DRIFT-MONITORING.md) for a systemd
timer example.
