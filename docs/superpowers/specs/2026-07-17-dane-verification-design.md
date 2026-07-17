# DANE verification — design

**Date:** 2026-07-17
**Status:** approved (design), pending implementation

## Problem

mailadmin's DANE support (v1.17.0) only handles the DNS side: `dns publish --dane`
writes a `3 1 1` TLSA record, and `dns audit` checks a TLSA exists at
`_25._tcp.<MX>` and is DNSSEC-authenticated (AD flag). Publishing records is not
enough — nothing verifies that:

1. the published TLSA still matches the certificate the mail host actually serves
   (goes stale after a cert/key rotation → DANE senders reject mail);
2. Postfix is configured to *use* outbound DANE at all (`smtp_tls_security_level`,
   `smtp_dns_support_level`, a validating resolver);
3. the certificate Postfix's `smtpd` serves is the same one that fed the TLSA
   (config drift between the deploy path and Postfix's path);
4. which fallback mode is in effect (`dane` opportunistic vs `dane-only`).

## Scope split

Checks are split by access type — network-only stays in `dns audit`, anything
needing `postconf` on the mail host goes in `doctor`.

| Gap | Home | Rationale |
|-----|------|-----------|
| 1 Live-cert vs TLSA match | `dns audit` (`internal/dnsaudit`) | network-only, runs from anywhere |
| 2 Outbound config + resolver | `doctor` (`internal/cli/doctor.go`) | needs `postconf` via runner |
| 3 smtpd-cert drift | `doctor` | dito |
| 4 Fallback semantics | `doctor` detail + docs | interpretation of security_level value, no dedicated code |

## Part A — `dns audit`: live-cert match (Gap 1)

### resolverConn change
`tlsa(ctx, name)` returns `(values []string, ad bool, err error)` instead of
`(count int, ad bool, err error)` — the raw `"3 1 1 <hex>"` record strings.
`count` becomes `len(values)`. `liveConn.tlsa` updated to collect values.

### New injection seam
`Auditor` gains a field `probeCert func(ctx context.Context, host string) (string, error)`,
defaulting in `New` to an adapter over `dane.Value(ctx, "", host)` (live STARTTLS
read, re-derives `3 1 1`). Tests inject a stub — no network. `internal/dnsaudit`
imports `internal/dane` (dane is standalone: crypto + net/smtp, no reverse dep).

### evalDANE logic
When TLSA present **and** DNSSEC-authenticated, for each MX:
- fetch the live cert, re-derive its `3 1 1` value;
- `daneMatch(published []string, live string) bool` — pure; match = live value is
  a member of the published set (rollover overlap keeps old + new).

Outcomes:
- **match** → Pass (unchanged detail).
- **no match** → **Fail**: `"published TLSA does not match live certificate (stale
  after key rotation) — DANE senders will reject mail"`.
- **live unreachable** (STARTTLS timeout/error) → **Warn**: `"TLSA authenticated
  but live cert unreachable to confirm match"` (never downgrade a real Pass on a
  transient probe failure).
- **published TLSA are not `3 1 1`** (e.g. `2 x x` DANE-TA) → match skipped, noted
  in detail; presence+DNSSEC verdict stands.

Stays a single `DANE` finding; `classifyDANE` extended to carry the match verdict.
Pure, table-tested like the existing `classifyDANE` cases.

## Part B — `doctor`: Postfix DANE checks (Gaps 2-4)

New constant `binPostconf = "/usr/sbin/postconf"`. New rows appended in
`runDoctor`.

### Outbound (Gap 2 + 4)
`postconf -h smtp_tls_security_level smtp_dns_support_level`:
- `dane`/`dane-only` **and** `dnssec` → **OK**, detail names the fallback mode
  (`dane` = opportunistic, falls back to plaintext; `dane-only` = no fallback).
- security_level `dane`/`dane-only` but support_level ≠ `dnssec` → **FAIL** (DANE is
  silently inactive without DNSSEC support).
- otherwise → **WARN**: `"outbound DANE not enabled"`.

### Resolver (Gap 2)
Best-effort: unbound unit active OR `/etc/resolv.conf` nameserver is loopback.
Cannot be confirmed → **WARN** advisory. True validation is not directly probeable;
flagged honestly as best-effort.

### smtpd-cert drift (Gap 3)
`postconf -h smtpd_tls_cert_file` vs `cfg.Mail.TLSCert` (fallback `tlsCertPath`).
Differ → **WARN**: TLSA is derived from a cert other than what Postfix serves.

postconf output parsing factored into a pure function and unit-tested (like
`parseListeningPorts`); the runner-calling wrapper stays thin (like `portCheck`).

## Testing
- `internal/dnsaudit`: `daneMatch` + extended `classifyDANE` table tests; `evalDANE`
  with a fake `resolverConn` + stub `probeCert`.
- `internal/cli` (doctor): pure postconf parse/classify tested; runner call thin
  (follows existing doctor pattern — no new runner fake).

## Out of scope (YAGNI)
- No auto-fixing of `main.cf` — diagnosis only, not config management.
- No DANE-TA (`2 x x`) derivation — mailadmin only publishes `3 1 1`.

## Docs
- `docs/DNS.md`: DANE section gains fallback-mode explanation (`dane` vs
  `dane-only`) and a note that `doctor` verifies the Postfix side.
- README: doctor check list mentions DANE.
