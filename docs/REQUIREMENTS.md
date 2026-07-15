# mailadmin — engineering & security requirements (definition of done)

Every build must satisfy these before it is considered complete.

## Go quality
- Idiomatic per **Effective Go**, **Go Code Review Comments**, **Uber Go Style Guide**.
- Error handling: wrap with `%w`, no silent drops, no `panic` in normal flow,
  sentinel/`errors.Is`/`As` where matched.
- `context.Context` threaded through every I/O / exec / DB / DNS call; timeouts set.
- Concurrency: only where it earns its keep; channels/goroutines leak-free; race-clean (`go test -race`).
- Interfaces small + consumer-side; no god-objects; clear package boundaries; DRY.
- No dead code, no commented-out remnants, no superfluous comments, **no lingering TODOs**.
- Shared structures over duplication; reusable/composable types.
- Prefer established, well-maintained libraries for non-trivial work (TOML, cobra,
  pgx, miekg/dns) — but do not pull deps for trivial one-liners.

## Versions & vulns (RESEARCH LIVE — do not trust memory)
- Latest stable **Go** (verify go.dev/dl); pin `go` directive accordingly.
- Every module in go.mod at latest stable — `go get -u ./... && go mod tidy`;
  cross-check each on its release page / pkg.go.dev.
- `govulncheck ./...` clean; cross-check the GitHub Advisory DB for each dep.

## Security — OWASP Top 10 + ASVS
- **Injection**: all SQL parameterized (already in db); NO `sh -c` — exec via
  arg slices only (`internal/sys`); validate/normalize every external token
  (local-part, domain, qid `^[A-F0-9]{6,16}$`, IP, port).
- **Broken access control**: single-user root CLI, but least-privilege intent —
  explicit unit/command allowlists; never a wildcard `systemctl`/`nft`.
- **Crypto failures**: argon2id for mailbox pw (doveadm); TLS 1.2+ only anywhere
  outbound (Njalla HTTPS — verify certs, no InsecureSkipVerify); no MD5/SHA1/DES/RC4.
- **AuthN/session**: n/a (no web) — but secrets never logged.
- **SSRF**: DNS resolver + Njalla endpoint are fixed/config — no user-controlled URLs.
- **Deserialization**: only trusted JSON (Njalla API, our snapshots); strict decode.
- **Misconfig / secure defaults**: secrets.env 0600; config 0644; fail closed on
  parse error; MTA-STS enforce guard before publishing.
- **Vulnerable components**: see Versions above.

## Privacy / leakage
- No PII/secrets/tokens in logs, error messages, stack traces, or `-o json`.
- Redact on error paths; constant-ish behaviour (no obvious timing oracles on secrets).
- Audit log records who/what/when (actor, action, target, before/after) — but not secret values.

## Static analysis (all must pass clean)
`gofmt -l` empty · `go vet ./...` · `staticcheck ./...` · `gosec ./...` ·
`golangci-lint run` · `govulncheck ./...` · `go test -race ./...`.

## SOC 2 relevance (note gaps, not certify)
- **Security**: least privilege, input validation, secure exec.
- **Availability**: graceful errors, timeouts, no unbounded loops.
- **Processing integrity**: idempotent DNS reconcile; transactions for multi-write.
- **Confidentiality**: secret handling above.
- **Privacy**: leakage checks above.
- **Change mgmt / audit**: every mutation → audit_log; DNS takeover → snapshot first.

## Deliverable: security audit report
`docs/SECURITY-AUDIT.md` — findings sorted by CVSS (v4.0, fall back v3.1),
each with: file:line, full CVSS vector + base score + severity, mapped OWASP +
SOC 2 category, concrete remediation. Fix everything High+; document accepted
Low/Info.
