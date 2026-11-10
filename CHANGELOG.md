# Changelog

All notable changes to `mailadmin` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/).

This file was populated retroactively from `git log` and `docs/SECURITY-AUDIT.md`
for every tagged release (`v1.14.0` onward). History before `v1.14.0` was
squashed into a single "Initial import" commit before this file existed, so it
is summarized rather than itemized commit-by-commit.

## Upgrading

### To v1.14.0 or later — `DESEC_TOKEN` may now be required

Release **v1.14.0** added deSEC as a supported DNS provider and, as part of the
same audit-remediation pass, added `DESEC_TOKEN` handling to `config init` /
`config check` (see `docs/SECURITY-AUDIT.md`, "L-6, L-7, I-1, I-3, I-4" and
"released as 1.14.0"). If you set a domain's `dns_provider` to `desec` (see
`docs/DNS.md`), `secrets.env` must define `DESEC_TOKEN`, or `dns publish` /
`dns migrate` / DANE rollover against that domain will fail. Domains left on
`manual` or another provider are unaffected. Run `mailadmin config check` after
upgrading to confirm your `secrets.env` has everything the configured
providers need.

## [v1.25.0] - 2026-11-10

### Added
- `mailadmin install` hardens the host along BSI SYS.1.3 and the CIS Debian Benchmark, Level 1 and 2. See `docs/HARDENING.md` for every control and the deliberate deviations.
- SSH: key only login (only when an authorized key exists, so nobody is locked out), no forwarding, `MaxAuthTries 3`, `MaxSessions 2`, hybrid post quantum key exchange `mlkem768x25519`, AEAD ciphers, SHA 2 MACs, RSA keys of at least 3072 bit. The config is checked with `sshd -t` and rolled back if rejected.
- TLS for Postfix and Dovecot: TLS 1.2 and 1.3 only, ECDHE with AEAD only, `X25519MLKEM768` first where OpenSSL 3.5 is installed, server cipher preference. IMAP port 143 is closed. Caddy sends HSTS on the mail host.
- Postfix: strict HELO, sender and recipient checks, per client rate limits, banner without version.
- System: sysctl hardening, blocked kernel modules, no core dumps, persistent journal, auditd rules, AIDE, AppArmor, time sync, `login.defs` policy, pwquality, libpam-tmpdir, process accounting, sysstat, debsums, cron and PostgreSQL config permissions, legal login banner.
- Updates: unattended-upgrades for the distribution and the vendor repositories with reboot at 04:00 when needed, needrestart, and a first update run during install.
- CrowdSec with the nftables bouncer replaces fail2ban. The repository key is checked like the others (`--crowdsec-fingerprint`). `--crowdsec-enroll-key` (asked during an interactive install) enrolls the instance in the CrowdSec console.

### Fixed
- `backup create` failed because the migrations left `schema_migrations` and the sequences unreadable for the mailadmin role. Install now grants read access.
- `doctor` checks port 587.
- `config check` no longer fails for provider tokens that are not used.
- The missing fingerprint error names the right flag (`--caddy-fingerprint`).
- mailadmin runs with umask 022, so files it creates for other services stay readable under a hardened login umask. Repository keyrings are written with an explicit mode.

## [v1.24.1] - 2026-11-10

### Fixed
- A trailing slash in `dkim_dir` no longer bypasses the symlink check.
- Restore creates a missing DKIM directory with mode 0750, not 0700, so rspamd can read the keys.
- The DKIM helper refuses a link at the key directory. The reload marker is replaced by a rename, so a planted FIFO or file is never opened.
- The snapshot directory must not be a link. Snapshots are synced before a wipe.
- `dns restore` checks the snapshot provider before the dry run and the prompt.
- Audit rows for `dns takeover`, `dns restore` and `dns migrate` are written after Ctrl+C. The clean audit has a 30 second timeout.
- Prompted hostname and domain, and the selector flag, are lower cased.
- Disabled records match Unicode case variants the way `EqualFold` does.

## [v1.24.0] - 2026-11-09

### Fixed
- Root-run paths can no longer be redirected through links: DKIM key generation commits by `mv -T` from a root-owned temp directory, the reload marker is written with noclobber, the DKIM owner change works through an `os.Root`, and owned host directories are changed through `O_NOFOLLOW` descriptors.
- Snapshot files are created with `O_EXCL|O_NOFOLLOW`.
- `env` and `runuser` receive absolute paths for the commands they run, so a user-writable `PATH` entry cannot supply `apt-get` or `psql`.
- The firewall table replaces itself with `add` and `delete` instead of `destroy`, which needs nftables 1.0.7 (Debian 12 ships 1.0.6). `nftables.conf` is written only after the table passes `nft -c`.
- `dns restore` refuses a snapshot taken at another provider.
- The certificate wait retries only when the sync helper reports "no certificate yet" (exit 3).
- Disabled DNS records are matched on normalised content, so a case difference no longer re-adds or re-enables them.
- The `dns migrate --clean` audit row survives Ctrl+C, and a failed audit write is reported.
- Restore creates a missing DKIM directory instead of aborting.
- Hostname and domain are lower-cased before they reach the units and helpers.

## [v1.23.1] - 2026-11-09

### Fixed
- Backup restore refuses a symlinked DKIM directory, and the owner change no longer reaches entries behind a link.
- Backup copy reads its source through an `os.Root`, so a directory swapped for a symlink during the backup cannot leak files from outside the tree.
- DKIM keys are generated in a root-owned temp directory and renamed into place, key last. A killed run leaves no partial key that later runs accept.
- The install refuses symlinks only on directories mailadmin owns. Other links, such as a vmail volume, work as before.
- `secrets.env`, `config.toml`, `pg_hba.conf`, `pg_ident.conf` and the nftables persist file are written atomically and synced, so a crash never leaves them truncated.
- The cert sync stages both certificate and key before renaming either, so a failed copy no longer leaves the new certificate next to the old key.
- `dns publish --dane` does not add a TLSA record that is already live.
- `dns migrate --clean` saves a snapshot first and writes an audit row, also when the clean stops midway.
- DNS record replacement keeps disabled records disabled instead of switching them back on.
- Bare command names are resolved in fixed system directories, not through `PATH`.

## [v1.23.0] - 2026-11-09

### Added
- `mailadmin install` for Ubuntu and Debian. It installs PostgreSQL and Caddy from their vendor repositories (key fingerprints must match), the mail packages, and configures Postfix, Dovecot 2.4, rspamd, Caddy, nftables and the certificate sync. It refuses existing mail state unless `--adopt` is given.

### Fixed
- Firewall reads the sshd ports (`Port` and `ListenAddress`) instead of a fixed port 22, so a host on another SSH port is not locked out.
- DNS takeover, migrate, restore, set-bimi and dkim-rotate-start record audit and output when a rectify fails after the change is live. `migrate --clean` and DKIM record removal flush correctly.
- DKIM selectors accept the characters `valid.Selector` allows. `--adopt` keeps the stored selector. The key helper no longer writes through planted symlinks.
- rspamd no longer signs for a From domain that differs from the login. `mail.tls_cert` is written so the TLSA rollover reads the new certificate.
- The cert sync retries a failed reload. App-password labels with `+` or `@` can be revoked.
- Backup restore skips the dkim component for bundles without a dkim directory.
- `scripts/mail-cert-deploy.sh` restores the previous certificate pair when installing the new one fails.
- `config init` sets the file mode explicitly, so a umask no longer narrows `config.toml`.

## [v1.22.0] - 2026-08-30

### Added
- Rspamd ratelimit and greylist tuning in the security CLI.
- Push alerting: `doctor` and `dns drift-check` report via ntfy.
- Audit list filters by actor, action, target, since and until.
- CI runs the internal/db integration tests against a real Postgres service.

### Fixed
- App-password `last_used` is no longer presented as tracked data.
- `mailbox` queries include the password column (lint and gosec findings from the merge).

## [v1.21.0] - 2026-08-30

### Added
- Rspamd Bayes feedback loop (`learn-spam`, `learn-ham`).
- `queue bounces` and log-derived rspamd and Postfix statistics.
- Sieve `vacation` and `vacation-off` autoresponder commands.
- Backup and restore commands with a DR runbook and a baseline migration.
- BIMI provisioning, two-step DKIM rotation and a cron-friendly DNS drift check.
- `valid.PathUnder` for realpath-confined path validation.

### Fixed
- Lint findings from merged branches (errorlint, gofmt, duplicate fuzz targets).

## [v1.20.3] - 2026-08-30

### Fixed
- `--dry-run` is now honoured across `mailbox`, `sieve`, `security`,
  `service`, `queue`, and `config` mutating commands (previously only
  `domain`/`alias` checked it), so a dry run never touches the DB, an
  external command, or a file for these command groups either.

### Changed
- Bumped the `go` directive to 1.26.6.

## [v1.20.2] - 2026-08-30

### Fixed
- `--dry-run` is now honoured in `domain` and `alias` mutating commands.
- The MTA-STS Caddy `include` is now kept in sync with a domain's lifecycle
  (added/removed alongside the domain) instead of drifting.

## [v1.20.1] - 2026-07-23

### Fixed
- `dns check --njalla` / `--desec` now force that specific provider's API
  regardless of the domain's configured `dns_provider`, matching the
  documented "verify a zone before switching providers" workflow.

## [v1.20.0] - 2026-07-23

### Added
- `--registrar` / `--desec` flags on `dns check`, to diff desired vs. live
  records at the provider's API instead of public DNS.

## [v1.19.0] - 2026-07-17

### Added
- End-to-end DANE verification:
  - `dns audit` now fetches the live certificate over STARTTLS and confirms
    the published `3 1 1` TLSA still matches it, catching a stale TLSA after
    a key rotation.
  - `doctor` gained outbound-DANE checks: `dane-outbound` (Postfix
    `smtp_tls_security_level` / `smtp_dns_support_level`), `dane-smtpd-cert`
    (served cert matches the cert that feeds the TLSA), and `dane-resolver`
    (loopback validating resolver present).

### Docs
- Documented DANE verification (`dns audit` live-cert match, `doctor`
  checks) and the design/implementation plan behind it.

## [v1.18.0] - 2026-07-17

### Added
- `domain set-provider <domain> <provider>` to point a domain at a DNS
  backend; `dns migrate` now offers to run it automatically on success.

## [v1.17.0] - 2026-07-16

### Added
- Inbound-SMTP DANE support: derive and manage a `3 1 1` TLSA record
  (`dns show --dane`, `dns publish --dane`), additive publishing so an
  in-progress certificate rollover never breaks delivery.

## [v1.16.1] - 2026-07-16

### Fixed
- deSEC API calls now retry `502`/`503`/`504` with exponential backoff, in
  addition to the existing `429` (`Retry-After`) handling, so a large publish
  or migration doesn't fail on a transient provider error.

## [v1.16.0] - 2026-07-16

### Added
- `dns migrate` retries on deSEC `429`, skips copying `NS`/`SOA` records
  (delegation belongs to the target zone), and gained `--clean` to wipe the
  target zone for a clean 1:1 replacement.

## [v1.15.0] - 2026-07-15

### Added
- Four new DNS providers: Cloudflare, INWX, Servercow, and servfail.network
  (alongside the existing Njalla/deSEC/manual), each with its own credential
  set in `secrets.env`.

### Security
- Recorded audit remediation status: sudoers and five orphaned privileged
  helper scripts removed on the server; `errcheck`/`ineffassign` cleared;
  deSEC errors now use a typed `*apiError` + `errors.As`; five dead functions
  and the queue-summary cluster removed; `DESEC_TOKEN` added to
  `config init`/`config check` (see [Upgrading](#upgrading)).

### CI
- Bumped `actions/checkout` to v5 and `actions/setup-go` to v6.

## [v1.14.0] - 2026-07-15

Initial tagged release. Squashed "Initial import" commit — the full CLI
(`domain`, `mailbox`, `alias`, `app-password`, `dns show`/`check`/`publish`/
`migrate`/`takeover`/`restore`, `dns audit`, `queue`, `sieve`, `security`
ban/allowlist/firewall, `service`, `audit list`, `doctor`, `stats`, `config`,
self-update) plus the Postgres-backed `internal/db` layer, Njalla/deSEC DNS
providers, and the injection-defence `internal/valid` package, as they stood
at the security audit dated 2026-07-15 (see `docs/SECURITY-AUDIT.md`, which
supersedes a 2026-07-14 report predating this tag).

[v1.20.3]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.20.3
[v1.20.2]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.20.2
[v1.20.1]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.20.1
[v1.20.0]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.20.0
[v1.19.0]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.19.0
[v1.18.0]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.18.0
[v1.17.0]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.17.0
[v1.16.1]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.16.1
[v1.16.0]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.16.0
[v1.15.0]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.15.0
[v1.14.0]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.14.0
