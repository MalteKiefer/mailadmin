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
