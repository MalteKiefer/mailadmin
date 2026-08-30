# mailadmin — CI/CD Security & Quality Gates

This document inventories every automated gate in `.github/workflows/` and the
`Makefile`, what each one catches, and what it would have missed. It ends with
a concrete branch-protection recommendation, since this repo currently pushes
directly to `main` with no protection configured.

Added/changed on the `feat/ergonomics-and-ci` branch (2026-08-30).

## Workflow inventory

### `.github/workflows/ci.yml` — on every push to `main`/`develop` and every PR

| Job | Step | Catches |
|-----|------|---------|
| `test` | `gofmt` | Unformatted code (style drift, noisy diffs) |
| `test` | `go build ./...` | Compile errors |
| `test` | `go vet ./...` | Suspicious constructs the compiler allows (bad `Printf` verbs, struct tag typos, unreachable code, lock-copying) |
| `test` | `go test -race ./...` | Logic bugs + data races (this repo runs subprocess/DB/DNS calls concurrently in a few places — `internal/logs.Tail`, `internal/dnsprovider.discover`) |
| `test` | `staticcheck` (pinned `2025.1.1`) | Dead code, simplifiable code, a wide class of correctness bugs (nil derefs, format-string mismatches, deprecated API use) |
| `test` | `gosec -quiet` | Security anti-patterns: hardcoded credentials, weak crypto, command injection shape, path traversal shape, etc. — the same tool `internal/sys`'s `#nosec G204` comments are written against |
| `test` | `govulncheck` | Known CVEs in the module's dependency graph, filtered to symbols actually reachable from this binary (not just "a vulnerable package is somewhere in go.sum") |
| `lint` | `golangci-lint` (pinned `v2.5.0`, config `.golangci.yml`) | See "golangci-lint policy" below — mostly things staticcheck/gosec don't specialize in: unclosed HTTP response bodies (`bodyclose`), `%w`-vs-`%v` wrapping mistakes (`errorlint`), context-less HTTP/exec calls (`noctx`), dead parameters (`unparam`), swallowed-error-then-nil-return bugs (`nilerr`), pre-Go-1.22 loop-variable capture bugs (`copyloopvar`) |
| `coverage` | `go test -coverprofile` + floor check | A large chunk of code landing with **no tests at all** (the floor is a regression guard, not a target — see "Coverage floor" below) |

**What it would NOT catch:** logic bugs with a valid-looking test that doesn't
exercise the bug; supply-chain compromise of a dependency that has no known
CVE yet; anything that only manifests against the real Postgres/Postfix/
Dovecot/CrowdSec/Caddy this CLI drives in production (there's no integration
environment in CI — deliberate, this is a root-privileged sysadmin tool with
no safe way to fake `systemctl`/`postqueue`/`doveadm` at scale in a shared
runner).

### `.github/workflows/codeql.yml` — push/PR to `main`/`develop` + weekly (Mon 03:17 UTC)

GitHub's CodeQL SAST engine for Go. Does cross-function taint-flow analysis —
the class of bug where a value looks validated at the call site but isn't
actually sanitized on the path that reaches a sink. That matters specifically
for this codebase: `internal/valid` centralizes input validation and
`internal/sys.Runner` is the single exec chokepoint, but CodeQL is what would
actually verify (rather than just document) that every path from CLI flag to
`sys.Runner.Run`'s argv goes through a `valid.*` call first, and would flag a
new command that skips it. Findings land in the repo's Security tab (Code
scanning alerts).

Weekly schedule exists so a newly-published CodeQL query (a new taint-sink
definition, a new vulnerability pattern) still gets applied to code that
hasn't changed recently — push/PR-triggered analysis alone only re-checks
what changed.

### `.github/workflows/dependency-review.yml` — on PR only

Diffs a PR's dependency changes (go.mod/go.sum) against the advisory database
and license policy, and fails if a newly-introduced (or newly-bumped-to)
dependency has a known vulnerability at or above `high` severity. **Currently
dormant**: this repo pushes directly to `main`, so no PR ever triggers this
workflow. It's added now so the check exists and is consistent the moment a
PR-based workflow is adopted (Dependabot version-bump PRs, or a human
contributor's PR) — see the branch-protection recommendation below for how to
make it actually enforced.

### `.github/workflows/fuzz.yml` — weekly (Mon 04:43 UTC) + manual dispatch

Runs Go's native fuzzer (`go test -fuzz=...`) for 60s per target against
`internal/valid`'s three most exec/DNS/SQL-adjacent validators (`FuzzDomain`,
`FuzzAddress`, `FuzzCIDR` — see "Fuzz targets" below). Catches inputs that
crash the validator or break its documented invariant (idempotency on a
successful parse), which is a different failure mode than the table-driven
unit tests catch: those check specific known-bad inputs; the fuzzer explores
inputs a human wouldn't think to write down, including ones that could hang a
regexp engine or panic `net.ParseCIDR`. Deliberately not on the push/PR path
— fuzzing needs a real time budget to find anything, and running it on every
push would slow iteration for little marginal benefit over the fixed seed
corpus already exercised by `go test` on every push.

### `.github/workflows/release.yml` — on `v*` tag push

Builds the two Linux release binaries (amd64/arm64), generates a CycloneDX
SBOM of the module's dependency graph (`anchore/sbom-action`, backed by
Syft), checksums everything into `SHA256SUMS`, and publishes a GitHub release
with all of it attached. The SBOM lets anyone consuming a release binary check
its exact dependency composition against a CVE feed without rebuilding from
source — useful for exactly this kind of tool (installed as a root-privileged
binary on a mail server).

## golangci-lint policy (`.golangci.yml`)

Config version 2, linter set deliberately layered on top of (not duplicating)
the linters `ci.yml`'s `test` job already runs separately (`staticcheck`,
`gosec`, `go vet`):

- **Enabled:** `bodyclose`, `copyloopvar`, `errorlint`, `gocritic`, `gosec`
  (kept in sync with the standalone `make gosec` step, for editor/PR-time
  feedback), `govet`, `ineffassign`, `misspell`, `nilerr`, `noctx`, `revive`,
  `staticcheck`, `unconvert`, `unparam`, `unused`.
- **Disabled:** `errcheck` — SECURITY-AUDIT.md already reviewed this
  codebase's many intentional `_ = x.Close()` / best-effort patterns; turning
  errcheck on wholesale would need a blanket per-line exclusion list that
  hides real misses rather than surfacing them.
- **revive `unused-parameter` disabled:** many functions here implement fixed
  interfaces (cobra `RunE(cmd *cobra.Command, args []string) error`, the
  `Recorder` interface) where an unused parameter is part of the contract,
  not dead code.

### Findings fixed on this branch

All were real (not suppressed) except where noted:

- `copyloopvar` (8 occurrences: `internal/dnsprovider/provider.go`,
  `internal/quota/quota_test.go`, `internal/security/{nft,parse}_test.go`) —
  removed redundant `x := x` loop-variable copies now that Go 1.22+ gives each
  iteration its own variable.
- `errorlint` (~15 occurrences across `internal/cli/{cli,mailbox,queue,
  service,stats}.go`, `internal/config/config.go`, `internal/security/
  {nft,parse}.go`) — changed `fmt.Errorf("%w: %v", Sentinel, err)` to
  `fmt.Errorf("%w: %w", Sentinel, err)` so `errors.Is`/`errors.As` can match
  the wrapped inner error too (Go has allowed multiple `%w` verbs since 1.20).
- `gocritic` `exitAfterDefer` (`cmd/mailadmin/main.go`) — `main` called
  `os.Exit` directly after `defer stop()` (the signal-forwarding context's
  cleanup), which meant `stop()` never ran. Split into `main()` / `run() int`
  so `os.Exit` only happens after `run` returns and its defers have unwound.
- `gosec` G301 (`internal/cli/version.go`, this branch's own new `man`
  subcommand) — `os.MkdirAll(dir, 0o755)` tightened to `0o750`.
- `unparam` (`internal/config/config.go`, `internal/dnsaudit/audit.go`) —
  `applyEnvOverrides` never actually returned a non-nil error, so the return
  type was dropped (call sites updated); `spfLookups`'s `domain` parameter was
  never read in the function body, so it was removed (both call sites
  updated).
- `noctx` (`internal/cli/config.go`) — `exec.Command` → `exec.CommandContext`
  for the `config edit` subprocess launch.

### Findings suppressed with `//nolint`, and why

- `internal/dnsaudit/audit.go` — `nilerr` on the DS-lookup-failure branch of
  `dnssec()`. The code intentionally returns a nil error there: a failed DS
  lookup doesn't invalidate the DNSKEY result computed just above it, and the
  function's doc comment already said so before this branch existed
  (`// DNSKEY result still usable`). Suppressed with a comment restating why.
- `internal/cli/version.go` — `unparam` on `newVersionCmd(app *App)`; `app` is
  unused today but kept for signature parity with the sibling `newXCmd(app,
  ...)` constructors in the same file (`newUpdateCmd`, `newManCmd`'s
  eventual siblings) — a natural extension point, not dead weight.

### Findings excluded by path, and why

Six specific (linter, file) pairs are excluded in `.golangci.yml` for
`internal/cli/{alias,dns,domain,security,sieve}.go`: these five files define
cobra commands that, per this branch's task brief, were **off-limits to edit**
— they were actively being extended with `--dry-run` support by parallel
in-flight branches at the time this branch was written, and touching them
risked stepping on that concurrent work or producing merge conflicts on
unrelated lines. The excluded findings are real but small and mechanical
(non-wrapping `%v` in an already-`%w`-wrapped error; an editor-invocation
helper not yet threaded with `ctx`; a couple of provider-selection helpers
with an always-same-value bool parameter) — left for whichever change next
touches these files to fix in context, with the reasoning for each exclusion
inline in `.golangci.yml`. **This is intentionally the only kind of
suppression used at file-path granularity in this config; every other
suppression is a single `//nolint:rule // reason` line at the exact site.**

### A note on local `gofmt` noise

Running golangci-lint locally on this Windows checkout intermittently flags 2-3
arbitrary, unrelated files as "not properly formatted" — a different set on
every run. This is `core.autocrlf=true` converting the working tree to CRLF on
checkout; the committed blobs (verified via `git show :path | gofmt -l -`) are
clean LF and gofmt-formatted. CI checks out on Linux with LF, so this does not
reproduce there; it's called out here only so a future contributor on Windows
doesn't chase it as a real regression.

## Coverage floor

Baseline measured 2026-08-30 on this branch: **25.1%** total statement
coverage (`go test -coverprofile=coverage.out ./...` then `go tool cover
-func`). This is pulled down by:

- `internal/db` and `internal/valid` — 0% (no test files existed before this
  branch; this branch adds `internal/valid`'s first tests via the fuzz
  targets below, which will move this baseline up on the next remeasurement).
- `internal/cli` — most cobra `RunE` bodies are exercised in practice by
  manual/integration use (a root-privileged CLI against a live mail stack)
  rather than by unit tests, which this branch does not attempt to retrofit.

**Floor set to 20%** — a few points under the measured baseline so ordinary
cross-package fluctuation doesn't false-positive the gate, while a real
regression (e.g. a large new package landing with zero tests, or an existing
package's tests being deleted/gutted) still fails CI. This is a **regression
guard, not a target** — it should be ratcheted upward over time as real
coverage improves (particularly once `internal/cli` and `internal/db` get
unit tests), not treated as an acceptable long-term number.

## Fuzz targets

Added in `internal/valid/fuzz_test.go` (previously: zero fuzz targets existed
anywhere in the repo):

- `FuzzDomain` — `valid.Domain`
- `FuzzAddress` — `valid.Address`
- `FuzzCIDR` — `valid.CIDR`

Chosen because these three sit directly between untrusted CLI input and
either an exec argv (`CIDR` feeds the `cscli`/`nft` call sites in
`internal/security`), a SQL parameter, or a DNS query (`Domain`, `Address`) —
exactly the boundary `internal/valid`'s package doc says it exists to guard.
The fuzz invariant is deliberately weak (no panic; a successful parse is
idempotent under re-validation) because the interesting failure mode here is
memory-safety/DoS (a crafted string hanging the regexp engine or panicking
`net.ParseIP`/`ParseCIDR`), not business-logic correctness — that's the job of
ordinary table-driven tests, which this package still doesn't have and is a
good next addition (tracked implicitly by the coverage floor above).

## Branch protection recommendation

This repo has no branch protection today — every push above (including this
branch's own workflow changes) is validated only because `ci.yml` also
triggers on `pull_request`, not because `main` requires it. Malte cannot
configure branch protection from `gh` without the `admin` OAuth scope this
session doesn't have; below is the exact `gh api` command (and the
equivalent Settings-UI path) to run by hand.

### Recommended rule for `main`

- **Require status checks to pass before merging**, specifically:
  - `test` (from `ci.yml`)
  - `lint` (from `ci.yml`)
  - `coverage` (from `ci.yml`)
  - `analyze` (from `codeql.yml`)
  - `dependency-review` (from `dependency-review.yml`) — only actually runs
    on PRs, so this is forward-looking until PRs are adopted
- **Require branches to be up to date before merging** — cheap given this is
  a single-maintainer repo with infrequent conflicts, and it keeps CI signal
  meaningful (no merging a green PR that's actually stale against a red
  main).
- **Require pull request reviews before merging: 0 required approvals for
  now** (single-admin repo — Malte is the only committer) but **enable the
  setting itself** so it's a one-checkbox change to require 1 approval the
  day a second admin/contributor joins, rather than a new rule to design
  later.
- **Do not enable "Require signed commits"** unless Malte already signs
  commits locally — forcing it on without local GPG/SSH signing set up would
  simply block every push.
- **Include administrators** in the restriction — otherwise the rule is
  advisory-only for the one account that pushes to `main` today, which
  defeats the purpose.

### Via `gh api` (run by an account with admin on the repo)

```sh
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  repos/MalteKiefer/mailadmin/branches/main/protection \
  -f required_status_checks.strict=true \
  -f 'required_status_checks.contexts[]=test' \
  -f 'required_status_checks.contexts[]=lint' \
  -f 'required_status_checks.contexts[]=coverage' \
  -f 'required_status_checks.contexts[]=analyze' \
  -f 'required_status_checks.contexts[]=dependency-review' \
  -F enforce_admins=true \
  -F required_pull_request_reviews.required_approving_review_count=0 \
  -F required_pull_request_reviews.dismiss_stale_reviews=true \
  -F restrictions=null
```

(`gh api` needs a token with the `repo` scope and admin rights on the
repository; the default `gh auth login` scope set usually already covers
this for the repo owner — if it 403s, the fix is `gh auth refresh -s
admin:repo_hook` or re-authenticating with a token that includes repo admin,
not adding scopes this document can't verify are safe to grant blindly.)

### Via the Settings UI (equivalent, if preferred)

1. `github.com/MalteKiefer/mailadmin` → **Settings → Branches**.
2. **Add branch protection rule**, branch name pattern `main`.
3. Check **Require a pull request before merging** (0 required approvals for
   now, per above).
4. Check **Require status checks to pass before merging** → **Require
   branches to be up to date before merging** → search for and add `test`,
   `lint`, `coverage`, `analyze`, `dependency-review` (each only appears in
   the picker after it has run at least once, so this step needs to happen
   after this branch — or any branch with these workflow files — has had a
   CI run).
5. Check **Do not allow bypassing the above settings** (this is "include
   administrators" in the UI).
6. Leave **Require signed commits** unchecked unless commit signing is
   already set up locally.
7. Save.

Adopting a PR-based workflow (even a solo-maintainer "push to a branch, open
a PR, self-merge once green" habit) is what turns `dependency-review.yml`
from dormant into an actual gate, and is the only way `pull_request`-triggered
checks ever run before code reaches `main` rather than after.
