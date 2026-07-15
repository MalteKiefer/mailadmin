# mailadmin — Security & Quality Audit

Date: 2026-07-15 · Auditor: automated deep review (static analysis + live dep/CVE
research + manual review vs OWASP Top 10 / ASVS 5.0 / SOC 2). Scope: whole Go
module (`mailadmin`, root/`mailadmin`-user CLI, Debian) **plus related components**
— privileged helper scripts under `/usr/local/libexec`, `/etc/sudoers.d/mailadmin`,
`config.toml`, `secrets.env`, deploy method, systemd units. CVSS v4.0 (v3.1 fallback).

Supersedes the 2026-07-14 report. Version audited: **1.13.1** (deployed).

## Result

**Go binary: PASS — no High+ in application code.** The application layer is
clean and idiomatic. **All High/Medium findings are in server-side related
components (shell helpers + sudoers), most of them orphaned by the deletion of
`mailadmin-web`.** Remediation is mostly *removal* of dead privileged surface.

## Gates (run 2026-07-15, verified — not from memory)

| Gate | Tool | Result |
|------|------|--------|
| Build | `CGO_ENABLED=0 GOOS=linux go build ./...` | clean |
| Format | `gofmt -l .` | empty |
| Vet | `go vet ./...` | clean |
| Race + unit | `go test -race ./...` | all pass |
| Static | `staticcheck ./...` | 0 |
| Security static | `gosec ./...` | 0 issues (17 justified `#nosec`) |
| Lint | `golangci-lint run` | **4 issues** (see L-4) — prior report's "0" was stale |
| Dependency CVEs | `govulncheck ./...` | No vulnerabilities found |

## Versions (live-verified 2026-07-15 via proxy.golang.org / go.dev / osv.dev)

- **Go 1.26.5** — latest patch of 1.26 (no 1.26.6/1.27 exists); itself a security release.
- All direct + indirect deps on latest stable; none behind. No CVE/GHSA affects any
  pinned version. `golang.org/x/net v0.57.0` clean (all fixes ≤ 0.55.0).
- Precaution: `golang.org/x/crypto` is **not** a dependency; if it ever resolves
  transitively, pin ≥ 0.52.0 (CVE-2026-46595 SSH authz bypass, fixed 0.52.0).

## Findings — by severity, sorted by CVSS

| ID | Sev | CVSS (v4.0 base) | Component | OWASP / SOC2 |
|----|-----|------|-----------|--------------|
| H-1 | High | 7.3 | sudoers `rm -rf` wildcard | A01/A05 · CC6.1/CC6.3 |
| M-1 | Med | 5.1 | orphaned privileged helpers + sudoers grants | A04/A05 · CC6.1 |
| L-1 | Low | 3.1 | `mailadmin-app-passwd` SQL string-interpolation | A03 · PI1.1 |
| L-2 | Low | 2.4 | `mailadmin-app-passwd` password on argv | A02/A09 · C1.1 |
| L-3 | Low | 2.3 | `mailadmin-rspamd-learn` path regex allows `..` | A01 · CC6.1 |
| L-4 | Low | 2.0 | `mailadmin-snappymail-domain` unvalidated path arg | A03/A05 · CC6.1 |
| L-5 | Low | 2.0 | `mailadmin-app-sync` non-atomic passwd write | A05 · A1.2 |
| L-6 | Low | 0.0* | golangci-lint: 3 errcheck + 1 ineffassign | — · PI1.1 |
| L-7 | Low | 0.0* | `desec.go` 404 detection via error-string match | A08 · PI1.1 |
| I-1 | Info | 0.0 | dead code (5 funcs) | — |
| I-2 | Info | 0.0 | DRY duplication (DNS exchange ×3, MTA-STS ×2, prompts ×2) | — |
| I-3 | Info | 0.0 | stale/superfluous comment `db.go:8` (refs deleted module) | — |
| I-4 | Info | 0.0 | config gaps: `DESEC_TOKEN` absent from `init`/`check`; `RSPAMD_CONTROLLER_PW` loaded-never-used | A05 |

`*` quality/robustness, no exploitable security impact → CVSS 0.0.

---

### H-1 — sudoers wildcard grants root arbitrary file deletion (path traversal)
**File:** `/etc/sudoers.d/mailadmin:2` (server)
```
mailadmin ALL=(root) NOPASSWD: /bin/rm -rf -- /var/vmail/*
```
**Vector:** `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N` — **7.3 High**
**OWASP:** A01 Broken Access Control / A05 Security Misconfiguration · **SOC2:** CC6.1, CC6.3
The sudoers `*` wildcard matches `/` and `..`. The `--` stops flag parsing but not
path traversal, so the `mailadmin` account can delete **any** path as root:
`sudo /bin/rm -rf -- /var/vmail/../../etc/<x>`. Classic sudo-wildcard escalation
(arbitrary-file-deletion → DoS / integrity loss / potential further compromise).
Live likelihood is reduced now that `mailadmin-web` (the only thing that ran as the
`mailadmin` user) is deleted — an attacker must first gain code-exec as `mailadmin`
(nologin, no running service) — but the primitive is real and must not remain.
**Fix:** Remove the rule. If maildir deletion is ever needed again, add a dedicated
validating helper `mailadmin-rm-maildir <user@domain>` that builds the path
*internally*, `realpath`-confines it under `/var/vmail`, and rejects `..`/symlink
escapes — grant sudo to *that*, never to raw `rm` with a glob.

### M-1 — Orphaned privileged surface after `mailadmin-web` deletion
**Files (server):** `/etc/sudoers.d/mailadmin` (all 5 lines), `/usr/local/libexec/{mailadmin-app-passwd,mailadmin-app-sync,mailadmin-user-dedupe,mailadmin-snappymail-domain,mailadmin-rspamd-learn}`
**Vector:** `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N` — **5.1 Medium**
**OWASP:** A04 Insecure Design / A05 · **SOC2:** CC6.1 (least privilege)
The deployed CLI invokes only three helpers — `mailadmin-fw-port`,
`mailadmin-dkim-gen`, `mailadmin-mta-sts-sync` (verified: `internal/security`,
`internal/mail`) — and runs them as root (no sudo). The remaining helpers and every
`sudoers.d/mailadmin` grant existed only for the now-deleted `mailadmin-web` account
service. They are dead privileged code: `mailadmin-app-passwd` can mint mailbox
credentials and `mailadmin-app-sync` rewrites `/etc/dovecot/passwd-app`. Dead
privilege = attack surface.
**Fix:** Remove the five web-only helpers and the `sudoers.d/mailadmin` file
entirely (keep the three CLI helpers, which need no sudo). Removing this file also
resolves H-1, L-1, L-2, L-3, L-5 in one step.

### L-1 — `mailadmin-app-passwd`: SQL built by shell string-interpolation
**File:** `/usr/local/libexec/mailadmin-app-passwd` (server) — `sql_esc` + `$PSQL -c "…'$(sql_esc "$x")'…"`
**Vector:** `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` — **3.1 Low**
**OWASP:** A03 Injection · **SOC2:** PI1.1
Hand-rolled escaping (`sed s/'/''/g`) is only safe while `standard_conforming_strings=on`
(the PG default) and no `E''` context — fragile. The `label` field was
attacker-influenced via the web. **Fix:** Removed with M-1. (The Go CLI's
`internal/db` app-password path is fully parameterized — unaffected.)

### L-2 — `mailadmin-app-passwd`: plaintext password on argv
**File:** `/usr/local/libexec/mailadmin-app-passwd` — `doveadm pw -s ARGON2ID -p "$pw"`
**Vector:** `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` — **2.4 Low**
**OWASP:** A02 Crypto Failures / A09 · **SOC2:** C1.1
The generated app password is visible in the process table (`ps`) to any local user
for the lifetime of the `doveadm` call. (The Go CLI's `internal/dovecotpw` correctly
passes it on stdin.) **Fix:** Removed with M-1; if retained, feed via stdin.

### L-3 — `mailadmin-rspamd-learn`: path regex permits `..`
**File:** `/usr/local/libexec/mailadmin-rspamd-learn` — `^/var/vmail/[a-z0-9.-]+/[a-z0-9._-]+/.*$`
**Vector:** `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` — **2.3 Low**
**OWASP:** A01 · **SOC2:** CC6.1
Trailing `.*` and dot-permitting components allow `/var/vmail/x/y/../../<file>`;
`rspamc learn` would read an arbitrary root-readable file into the Bayes DB (no
content returned to caller, so exposure is indirect). **Fix:** Removed with M-1; if
retained, `realpath`-confine under `/var/vmail`.

### L-4 — `mailadmin-snappymail-domain`: unvalidated path argument
**File:** `/usr/local/libexec/mailadmin-snappymail-domain` — `dst="$dir/${domain}.json"` with `domain="$1"`
**Vector:** `CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` — **2.0 Low**
**OWASP:** A03/A05 · **SOC2:** CC6.1
No validation of `$1` → traversal in the copy destination. Runs as root but not in
sudoers and not called by the CLI (orphaned). **Fix:** Removed with M-1; if retained,
validate `domain` against a strict regex before use.

### L-5 — `mailadmin-app-sync`: non-atomic write of hash file
**File:** `/usr/local/libexec/mailadmin-app-sync` — `cat "$tmp" > /etc/dovecot/passwd-app`
**Vector:** `CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N` — **2.0 Low**
**OWASP:** A05 · **SOC2:** A1.2 (availability)
`cat >` truncates then streams — a concurrent Dovecot read can see a partial file;
target perms are inherited, not asserted (file holds argon2 hashes). **Fix:** Removed
with M-1; if retained, `install -m 0640 -o root -g dovecot "$tmp" /etc/dovecot/passwd-app`
(atomic rename + explicit perms).

### L-6 — golangci-lint findings (application code)
- `internal/cli/dns.go:429` — `defer f.Close()` unchecked (errcheck)
- `internal/dnsprovider/desec.go:62` — `defer resp.Body.Close()` unchecked (errcheck)
- `internal/webserver/webserver.go:100` — `defer os.Remove(tmpName)` unchecked (errcheck)
- `internal/dnsaudit/checks.go:158` — `found = true` ineffectual (all returns hardcode the bool)

No security impact; the prior report's "golangci-lint 0 issues" is inaccurate.
**Fix:** wrap deferred cleanups as `defer func() { _ = x.Close() }()` (matches the
codebase's existing pattern) and drop the redundant `found = true`.

### L-7 — `desec.go`: 404 detected via error-string matching
**File:** `internal/dnsprovider/desec.go:93,187,208` — `strings.Contains(err.Error(), "404")`
against `fmt.Errorf("desec … %d …")`. Fragile (false-positive on any "404" substring).
**Fix:** return a typed `*apiError{StatusCode int}` and match with `errors.As`.

### I-1..I-4 — Informational (quality, from REQUIREMENTS "definition of done")
- **I-1 Dead code:** `sieve.Service.List` (sieve.go:88), `postfixq.Service.Summary`
  (postfixq.go:93), `mail.Manager.SyncMTASTS` (mail.go:135), `dovecotpw.PromptNewPassword`
  (prompt.go:24 + its helper `readSecret`), `valid.IP` (valid.go:96). Zero non-test callers.
- **I-2 DRY:** DNS `*dns.Client` exchange helper duplicated ×3
  (`dnscheck.go:398`, `dnsaudit/audit.go:264`, `discover.go:103`); MTA-STS fetch+parse
  ×2 (`cli/dns.go:876`, `dnsaudit/audit.go:214`); twice-entered password prompt ×2
  (`cli/prompt.go`, `dovecotpw/prompt.go`); duplicated bin-path consts (`binDoveadm` ×3,
  `binSystemctl`/`binJournalctl` ×2). (HTTPS-client duplication partly resolved by
  `dnsprovider/httpclient.go` in 1.13.1.)
- **I-3 Stale comment:** `internal/db/db.go:8-10` documents "reconstructed from the
  compiled mailadmin-web binary" — refers to the deleted module; superfluous now.
- **I-4 Config:** `DESEC_TOKEN` fully supported at runtime (`dns.go`) but absent from
  the `config init` starter template and `config check` (command.go); `RSPAMD_CONTROLLER_PW`
  is loaded + presence-checked but never consumed by any code path.

---

## Fixed since prior report (1.13.1, deployed 2026-07-15)
- `dnsprovider.WriteSnapshot` re-validates `s.Domain` at the sink (path-traversal guard).
- Njalla + deSEC clients pin `tls.VersionTLS12` via shared `newHTTPClient()`.
- `logs.New` validates the unit allowlist with `valid.Unit` (parity with `services.New`).

## Idiomatic-Go / RFC review
- **Errors:** `%w`-wrapped, sentinels (`ErrNotFound/ErrDeclined/ErrUsage`) → exit
  codes; no silent drops beyond the errcheck items in L-6; no `panic` in normal flow.
- **context:** threaded through every DB/exec/DNS/HTTP call with timeouts; only
  filesystem-local funcs omit it (correct).
- **Concurrency:** two `go func` sites (`logs.Tail`, `dnsprovider.discover`) — both
  leak-free (ctx-honoring select, buffered channel / semaphore + WaitGroup, all
  goroutines bounded by ExchangeContext timeout). `go test -race` clean.
- **Interfaces:** 6, all small + consumer-side (`audit.Logger`, `sys.Recorder`, …); no god objects.
- **TLS (RFC 8446/5246):** MinVersion 1.2 pinned everywhere; cert verification on
  (no `InsecureSkipVerify`); no MD5/SHA1/DES/RC4. **DNS (RFC 1035/7208/6376/8461):**
  proper `miekg/dns` `ExchangeContext` + AXFR via `dns.Transfer`; SPF/DKIM/DMARC/MTA-STS/TLS-RPT
  checks. **HTTP:** `NewRequestWithContext` + client timeouts + `io.LimitReader` bodies.
  **OAuth/JWT:** N/A — OIDC lived only in the deleted `mailadmin-web`.

## SOC 2 (control observations, not attestation)
- **Security (CC6):** strong secret hygiene + input validation + single audited exec
  chokepoint; **gap:** H-1/M-1 orphaned sudo grants violate least privilege.
- **Availability (A1):** timeouts + capped subprocess output + idempotent reconcile. OK.
- **Processing integrity (PI1):** parameterized SQL, transactions, snapshot-before-takeover. OK.
- **Confidentiality (C1):** secrets 0600, redacted `String()`, never logged/argv/`-o json`. OK.
- **Change mgmt / audit (CC7/CC8):** every mutation → `audit_log` (actor/action/target/
  before-after, no secrets); **gap:** audit log shares the app DB with no external,
  append-only/immutable sink (CC7.2 monitoring) — consider shipping to a separate store.

## Residual / assumptions
- Scanners run on darwin with `GOOS=linux` builds; live daemon behaviour of privileged
  helpers validated on the server via `mailadmin doctor`.
- Server-side findings (H-1, M-1, L-1..L-5) require changes on the host, not in the Go
  repo; they are remediated by removing the `mailadmin-web` leftovers.
