# mailadmin — Disaster Recovery Runbook

**Scenario:** the mail server is gone (hardware failure, provider account
loss, ransomware, fat-fingered `rm -rf`). You have: a `mailadmin backup`
bundle (from `mailadmin backup create`, ideally copied off-host — a backup
that only lives on the dead server is not a backup), a copy of
`secrets.env` from wherever it was stored separately (it is **never** in a
`mailadmin backup` bundle — see [Why secrets.env is separate](#why-secretsenv-is-separate)),
and DNS access at your registrar. You do not necessarily have any memory of
how this server was set up.

Follow this in order. Each step says what to run and how to tell it worked
before moving on. If a step fails, stop and fix it — do not proceed on a
guess.

## Contents
- [0. Before you start](#0-before-you-start)
- [1. Provision a new server](#1-provision-a-new-server)
- [2. Install the base stack](#2-install-the-base-stack)
- [3. Recreate Postgres roles and apply migrations](#3-recreate-postgres-roles-and-apply-migrations)
- [4. Install mailadmin](#4-install-mailadmin)
- [5. Restore config.toml and secrets.env](#5-restore-configtoml-and-secretsenv)
- [6. Restore the database, DKIM keys, and Sieve scripts](#6-restore-the-database-dkim-keys-and-sieve-scripts)
- [7. Point DNS at the new server](#7-point-dns-at-the-new-server)
- [8. Reissue TLS certificates](#8-reissue-tls-certificates)
- [9. Re-verify DANE and MTA-STS](#9-re-verify-dane-and-mta-sts)
- [10. Final checks before declaring victory](#10-final-checks-before-declaring-victory)
- [Why secrets.env is separate](#why-secretsenv-is-separate)
- [Rehearsing this runbook](#rehearsing-this-runbook)

## 0. Before you start

Gather these before touching anything:

- [ ] A `mailadmin backup` bundle directory (`mailadmin-<timestamp>/`), copied
      off the dead server — from your off-host copy (rsync target, object
      storage, whatever you use; `mailadmin backup create` only writes
      locally, see its `--out` flag and [`backup.dir`](ARCHITECTURE.md)).
      Run `mailadmin backup list` against a copy of that directory to confirm
      you have one and see what it covers.
- [ ] A copy of `secrets.env` from wherever it is stored separately (password
      manager, sealed secret, offline vault — see
      [Why secrets.env is separate](#why-secretsenv-is-separate)).
- [ ] Registrar login for every domain this server serves mail for (`dig NS
      <domain>` against a public resolver, or check the bundle's
      `manifest.json` → `domains`, to know which).
- [ ] The old server's public IPv4/IPv6, if you're reusing them (DNS `A`/
      `AAAA`/`MX`/DANE records reference them). If you're moving to new
      addresses, plan for a DNS TTL-bounded cutover instead — see
      [7. Point DNS at the new server](#7-point-dns-at-the-new-server).

## 1. Provision a new server

Debian (the version currently in production — see
[`docs/ARCHITECTURE.md`](ARCHITECTURE.md); update this line if that changes),
root SSH access, a static public IPv4 and (recommended) IPv6. Point the
server's reverse DNS (PTR) at the mail hostname before you send any mail from
it — most receivers reject or heavily penalise mail from an IP with no
matching PTR.

```sh
apt-get update && apt-get -y upgrade
apt-get -y install curl gnupg2 ca-certificates
```

## 2. Install the base stack

Install and enable, in this order (later services depend on earlier ones
being up): **PostgreSQL**, **Dovecot**, **Postfix**, **Rspamd**, **Caddy**,
**CrowdSec**. Use whatever package versions `docs/ARCHITECTURE.md` /
`docs/REQUIREMENTS.md` currently pin — do not blindly take `apt`'s default
version without checking, since Debian stable can lag behind what this
project targets.

```sh
apt-get -y install postgresql dovecot-imapd dovecot-pgsql dovecot-managesieved \
                    postfix postfix-pgsql
# Rspamd, Caddy, CrowdSec: from their own upstream repos, not Debian's
# default archive (they move faster than Debian stable) — add each
# project's official apt repo per its current install docs, then:
apt-get -y install rspamd caddy crowdsec
```

Do **not** configure Postfix/Dovecot/Rspamd/Caddy's actual mail-serving
config yet (virtual maps, TLS, milter hookup) — that depends on the database
and DKIM keys you restore in steps 4–6. For now just get the packages
installed and the services stopped:

```sh
systemctl stop postfix dovecot rspamd caddy crowdsec
```

Recreate mailadmin's own service account and directories:

```sh
useradd --system --home /var/lib/mailadmin --shell /usr/sbin/nologin mailadmin
mkdir -p /etc/mailadmin /var/lib/mailadmin /var/lib/rspamd/dkim \
         /var/lib/mailadmin/dns-backups /var/lib/mailadmin/backups
chown -R mailadmin:mailadmin /var/lib/mailadmin /var/lib/rspamd/dkim
```

## 3. Recreate Postgres roles and apply migrations

Create the database and the roles mailadmin/Postfix/Dovecot connect as. The
exact role names/grants below match what `migrations/001_baseline.sql`
expects — **that GRANT block is a best-effort reconstruction, not something
re-derived from a live `\dp` dump of the old server**, so if you have any
record of the old server's actual role setup (a prior `pg_dumpall
--roles-only`, config management history, notes), prefer that over this file.

```sh
sudo -u postgres createuser --login mailadmin
sudo -u postgres createuser --login postfix
sudo -u postgres createuser --login dovecot
sudo -u postgres createdb --owner=mailadmin mail
```

Apply the schema migrations **in numeric order** — `001_baseline.sql` first,
then every later `NNN_*.sql` in the `migrations/` directory:

```sh
psql -U postgres -d mail -f migrations/001_baseline.sql
psql -U postgres -d mail -f migrations/002_dns_provider.sql
# repeat for any migrations/NNN_*.sql added after this runbook was written
```

There is no migration-runner tool in this repo (no `mailadmin migrate`
command as of this writing) — applying each file with `psql -f`, in order, by
hand is the current convention. If that changes, update this step.

Verify the schema landed correctly before moving on:

```sh
psql -U postgres -d mail -c '\dt'
# expect: domain, mailbox, alias, app_password, audit_log
psql -U postgres -d mail -c '\d domain'
# expect a dns_provider column (added by 002) — if it's missing, 002 didn't apply
```

Set up the libpq service file mailadmin/Postfix/Dovecot use to connect
without embedding a password (peer auth over the unix socket, matching
`internal/db/db.go`'s doc comment):

```sh
cat > /var/lib/mailadmin/.pg_service.conf <<'EOF'
[mail-admin]
dbname=mail
user=mailadmin
EOF
chown mailadmin:mailadmin /var/lib/mailadmin/.pg_service.conf
chmod 0600 /var/lib/mailadmin/.pg_service.conf
```

## 4. Install mailadmin

Either build from source or grab a released binary and verify it against its
published `SHA256SUMS` (the same check `mailadmin update` does internally —
see `internal/selfupdate`):

```sh
# from a release:
curl -LO https://github.com/MalteKiefer/mailadmin/releases/latest/download/mailadmin
curl -LO https://github.com/MalteKiefer/mailadmin/releases/latest/download/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
install -m 0755 mailadmin /usr/local/bin/mailadmin

# or from source, on a machine with Go installed:
go build -o /usr/local/bin/mailadmin ./cmd/mailadmin
```

```sh
mailadmin version
```

## 5. Restore config.toml and secrets.env

Write `/etc/mailadmin/config.toml` to match the old server (hostname,
IPv4/IPv6, DKIM dir, Postgres service name, backup dirs, log units). The
fastest correct source is the bundle's own copy — every `mailadmin backup
create` bundle includes `config.toml` as it was at backup time:

```sh
cp /path/to/mailadmin-<timestamp>/config.toml /etc/mailadmin/config.toml
chmod 0644 /etc/mailadmin/config.toml
```

(Equivalently, `mailadmin backup restore <bundle> --component config` does
the same copy, plus prompts for confirmation and writes an audit-log entry —
prefer it once `mailadmin` itself is runnable, i.e. after this step's first
manual copy or once you have a working config from another source.)

Review it — server IPs, hostname, and paths may need to change if this is not
the exact same machine (e.g. new IPv4/IPv6, per
[7. Point DNS at the new server](#7-point-dns-at-the-new-server)).

Restore `secrets.env` from your **separate** secrets store (never from a
`mailadmin backup` bundle — it is deliberately excluded, see
[below](#why-secretsenv-is-separate)):

```sh
install -m 0600 -o root -g root /path/to/restored/secrets.env /etc/mailadmin/secrets.env
```

Sanity-check both files together:

```sh
mailadmin config check
```

Every row should read OK. Fix anything that doesn't before continuing —
in particular `secrets_file` (must be exactly mode 0600) and any DNS
provider token you rely on for automated DNS.

## 6. Restore the database, DKIM keys, and Sieve scripts

With a runnable `mailadmin` and a valid config, restore the rest of the
bundle. Preview first:

```sh
mailadmin backup restore /path/to/mailadmin-<timestamp> --dry-run
```

This prints, per component, exactly what would change — for the database it
runs a read-only `pg_restore --list` against the dump (touches nothing), for
DKIM/Sieve it reports file/mailbox counts, without writing anything. Read it.
Then restore for real:

```sh
mailadmin backup restore /path/to/mailadmin-<timestamp>
```

You'll be asked to confirm (this overwrites whatever is currently in the
`domain`/`mailbox`/`alias`/`app_password` tables, the DKIM key directory, and
every backed-up mailbox's active Sieve script — on a freshly-provisioned
server that's everything, which is the point). Pass `--yes` only in a
scripted/unattended rebuild where you've already reviewed the dry-run output.

To restore only one piece (e.g. you already have a good DKIM directory but
need the DB), use `--component`:

```sh
mailadmin backup restore /path/to/mailadmin-<timestamp> --component domain-db
```

Verify:

```sh
mailadmin domain list
mailadmin mailbox list
mailadmin audit list -n 5   # the restore itself is audit-logged as backup.restore
```

**This step has not been exercised against a real Postgres round-trip as
part of building this feature** — `pg_dump`/`pg_restore` were not run
against a live database while writing `mailadmin backup create`/`restore`
(no Postgres was available in that environment). Before trusting this
runbook in a real incident, do a full rehearsal — see
[Rehearsing this runbook](#rehearsing-this-runbook) — on a disposable
Postgres instance.

Now bring up the mail-serving side: point Postfix/Dovecot's SQL maps and
Rspamd's DKIM signing at what you just restored (this is standard
Postfix/Dovecot/Rspamd `pgsql` virtual-mailbox configuration, outside
mailadmin's scope — the schema is `mail-admin` service /
`domain`/`mailbox`/`alias` from step 3, and the DKIM directory is
`mail.dkim_dir` from config.toml), then:

```sh
systemctl start postgresql dovecot postfix rspamd caddy crowdsec
mailadmin doctor
```

`doctor` checks services, ports, TLS, and Rspamd config together — fix
anything it flags before moving on.

## 7. Point DNS at the new server

If you kept the same public IPv4/IPv6, DNS needs no change beyond making sure
it still resolves correctly — skip to verification:

```sh
mailadmin dns check <domain>          # public DNS
mailadmin dns check <domain> --registrar   # live at the registrar API
```

If the IPs changed (new host, same or different registrar), for each domain:

1. Update `[server]` `ipv4`/`ipv6` in `config.toml` to the new addresses,
   then `mailadmin config check`.
2. `mailadmin dns show <domain>` to see the new desired record set.
3. `mailadmin dns publish <domain> --dry-run` to preview, then without
   `--dry-run` to publish (only works for domains on an automated DNS
   provider — see `docs/DNS.md` for manual-provider domains).
4. If the domain's zone itself needs rebuilding from scratch (new registrar,
   lost zone), `mailadmin dns takeover <domain>` replaces the whole zone with
   the mail record-set (backing up whatever was there first) — see
   `docs/DNS.md` for the full flow, including `--keep-web` if the domain also
   serves a website.

Expect a delay for DNS propagation and for other mail servers' MX caches to
catch up — do not declare success until `dns check` is clean from more than
one vantage point (e.g. also check via `mailadmin dns check <domain>
--registrar` and a public tool like `dig` from outside your network).

## 8. Reissue TLS certificates

Caddy issues and renews certs automatically once it's running with the
correct domain config and DNS resolves to this server (steps 6–7). Confirm:

```sh
systemctl status caddy
journalctl -u caddy -n 50 --no-pager
mailadmin log tail caddy   # equivalent, through mailadmin
```

Look for successful ACME issuance for the mail hostname (and any autodiscover
/ MTA-STS hostnames Caddy serves). If issuance is failing, it's almost always
DNS not yet resolving to this server, or port 80/443 not reachable from the
internet (firewall — `mailadmin security firewall show`).

Once Caddy has a live cert, re-derive and republish the DANE TLSA record —
DANE is tied to the exact certificate, so a reissued cert invalidates the
previously-published TLSA value:

```sh
mailadmin dns show <domain> --dane          # what TLSA should be, from the live cert
mailadmin dns publish <domain> --dane --dry-run
mailadmin dns publish <domain> --dane
```

Publishing DANE only adds the new TLSA (old values are kept during the
overlap so in-flight verification doesn't break) — remove the stale one after
one TTL, per `docs/DNS.md`'s DANE section.

## 9. Re-verify DANE and MTA-STS

```sh
mailadmin doctor            # dane-outbound / dane-smtpd-cert / dane-resolver checks
mailadmin dns audit <domain>   # full mail-security grade: SPF/DKIM/DMARC/DNSSEC/DANE/MTA-STS/TLS-RPT/BIMI
```

`dns audit` is read-only against live public DNS/TLS and works for any
domain, so run it per-domain for everything this server serves. Everything
should come back pass/warn — treat any `fail` as blocking. If MTA-STS was
enforced before the outage, re-publish it explicitly once you've confirmed
the policy endpoint itself is reachable (it refuses to publish otherwise):

```sh
mailadmin dns publish <domain> --with-mta-sts --dry-run
mailadmin dns publish <domain> --with-mta-sts
```

## 10. Final checks before declaring victory

- [ ] `mailadmin doctor` — all green.
- [ ] `mailadmin dns audit <domain>` for every domain — no `fail`.
- [ ] Send a real test message in and out through the new server (not just a
      local `swaks`/`sendmail` — an actual external round trip, ideally to a
      mailbox at a major provider, to catch reputation/DANE/MTA-STS problems
      the DNS checks above can't see).
- [ ] `mailadmin sieve show <address>` for a couple of mailboxes with
      user-authored filters — confirm the restored script matches what the
      user expects, not just that *a* script is active.
- [ ] `mailadmin backup create` on the *new* server, right away, and copy it
      off-host — you do not have a current backup of the rebuilt server until
      you take one.
- [ ] Update wherever the old server's IP/fingerprint was pinned (monitoring,
      SSH known_hosts references, runbooks, this document if the stack
      versions moved).

## Why secrets.env is separate

`mailadmin backup create` deliberately never includes `secrets.env` (DNS
provider API tokens, the Rspamd controller password). A backup bundle is
built to be copied off-host routinely and possibly kept in more than one
place; secrets.env is a much higher-value target and belongs in a
secrets-appropriate store (password manager, sealed secret, vault) with its
own access control and rotation — not bundled alongside routine DR backups.
Every `backup create` run prints this reminder and stamps it into the
bundle's `manifest.json` (`notes` field) so it's never a silent gap.
**You must back up `secrets.env` yourself, separately, before you need it.**

## Rehearsing this runbook

This runbook — and the `backup create`/`backup restore` commands it leans on
— have not yet been exercised end-to-end against a real Postgres instance
(the environment used to build this feature had no live Postgres to test
against; only the surrounding logic — manifest generation, argument
construction, path handling — is unit-tested). Before trusting either in a
real incident:

1. Stand up a disposable Postgres + mailadmin on a test VM with a handful of
   real-shaped domains/mailboxes/aliases.
2. `mailadmin backup create`, then wipe the DB/DKIM dir/Sieve scripts.
3. `mailadmin backup restore` and confirm the domain/mailbox/alias/
   app_password rows, DKIM keys, and Sieve scripts all come back exactly.
4. Time it. Note anything in this document that turned out to be wrong,
   missing, or a different command than what's actually current — this
   runbook is only as good as the last time someone actually ran it.
