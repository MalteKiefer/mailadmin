# DANE Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify DANE actually works end-to-end — that published TLSA still matches the live cert (`dns audit`), and that Postfix is configured to use DANE outbound with a validating resolver and a consistent smtpd cert (`doctor`).

**Architecture:** Network-only checks extend the existing `dns audit` DNS evaluator (`internal/dnsaudit`); server-side checks that need `postconf` extend the existing `doctor` health command (`internal/cli/doctor.go`). Both reuse established seams — the `resolverConn` interface for DNS test isolation, and pure parse/classify functions for `postconf` output.

**Tech Stack:** Go, `github.com/miekg/dns`, `internal/dane` (existing `3 1 1` derivation), `internal/sys.Runner` (privileged-exec chokepoint), cobra.

## Global Constraints

- DANE TLSA values are `"3 1 1 <lowerc-hex>"` (DANE-EE / SPKI / SHA-256) — the only usage mailadmin derives; never derive DANE-TA (`2 x x`).
- `internal/dane.Value(ctx, certPath, host)` returns `(dane.Result{Value, Source}, error)`; pass `certPath=""` to read the live cert via STARTTLS on port 25.
- Finding statuses: `Pass` / `Warn` / `Fail` / `Info` (`internal/dnsaudit`). Doctor statuses: `statusOK` / `statusWarn` / `statusFail` / `statusError` (`internal/cli/doctor.go`).
- Commit messages: NO Claude/AI attribution footer (a repo hook blocks it).
- Run the full suite with `go test ./...` from repo root.

---

### Task 1: `resolverConn.tlsa` returns raw record values

**Files:**
- Modify: `internal/dnsaudit/audit.go` (interface `resolverConn`, `liveConn.tlsa`, `evalDANE`, `classifyDANE`)

**Interfaces:**
- Consumes: nothing new.
- Produces: `resolverConn.tlsa(ctx, name) ([]string, bool, error)` returning raw `"u s m <hex>"` strings (lowercase hex); `classifyDANE(mxCount, tlsaCount int, authenticated bool) Finding` unchanged signature.

- [ ] **Step 1: Update the interface and `liveConn.tlsa`**

In `internal/dnsaudit/audit.go`, change the interface method (around line 91-93):

```go
	// tlsa returns the raw TLSA record values ("usage selector match hex",
	// lowercase hex) at name and reports whether the answer was
	// DNSSEC-authenticated (AD flag) — DANE requires signed TLSA (RFC 7672).
	tlsa(ctx context.Context, name string) (values []string, ad bool, err error)
```

Rewrite `liveConn.tlsa` (around line 371):

```go
func (l *liveConn) tlsa(ctx context.Context, name string) (values []string, ad bool, err error) {
	msg, err := l.exchange(ctx, name, dns.TypeTLSA, true)
	if err != nil {
		return nil, false, err
	}
	for _, rr := range msg.Answer {
		if t, ok := rr.(*dns.TLSA); ok {
			values = append(values, fmt.Sprintf("%d %d %d %s",
				t.Usage, t.Selector, t.MatchingType, strings.ToLower(t.Cert)))
		}
	}
	return values, msg.AuthenticatedData, nil
}
```

- [ ] **Step 2: Update `evalDANE` to the new signature (behavior unchanged for now)**

Rewrite the gather loop in `evalDANE` (around line 275-291) to count values:

```go
func (a *Auditor) evalDANE(ctx context.Context, domain string) Finding {
	hosts, err := a.conn.mx(ctx, domain)
	if err != nil {
		return Finding{Check: "DANE", Status: Warn, Detail: "MX lookup failed: " + err.Error()}
	}
	total, authed := 0, true
	for _, h := range hosts {
		vals, ad, terr := a.conn.tlsa(ctx, "_25._tcp."+h)
		if terr != nil {
			continue
		}
		total += len(vals)
		if len(vals) > 0 && !ad {
			authed = false
		}
	}
	return classifyDANE(len(hosts), total, authed)
}
```

- [ ] **Step 3: Update every fake `resolverConn` in tests to the new signature**

Run: `grep -rn "tlsa(" internal/dnsaudit/*_test.go`
For each fake conn's `tlsa` method, change the return from `(count int, ...)` to `([]string, ...)`. Where a test needs N records, return a slice of N placeholder `"3 1 1 aa"` strings. (If no fake currently implements `tlsa`, skip — the interface is satisfied elsewhere.)

- [ ] **Step 4: Run the suite to verify it compiles and passes**

Run: `go test ./internal/dnsaudit/...`
Expected: PASS (behavior unchanged; only the value type flows differently).

- [ ] **Step 5: Commit**

```bash
git add internal/dnsaudit/audit.go internal/dnsaudit/*_test.go
git commit -m "refactor(dnsaudit): tlsa returns raw record values"
```

---

### Task 2: `daneMatch` pure comparison

**Files:**
- Modify: `internal/dnsaudit/audit.go` (add `daneMatch`)
- Test: `internal/dnsaudit/checks_test.go`

**Interfaces:**
- Produces: `daneMatch(published []string, live string) bool` — true when `live` equals any published value (case-insensitive, whitespace-trimmed).

- [ ] **Step 1: Write the failing test**

Add to `internal/dnsaudit/checks_test.go`:

```go
func TestDaneMatch(t *testing.T) {
	live := "3 1 1 abc123"
	cases := []struct {
		name      string
		published []string
		want      bool
	}{
		{"exact", []string{"3 1 1 abc123"}, true},
		{"case-insensitive", []string{"3 1 1 ABC123"}, true},
		{"rollover overlap", []string{"3 1 1 old000", "3 1 1 abc123"}, true},
		{"stale only", []string{"3 1 1 old000"}, false},
		{"empty", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := daneMatch(tc.published, live); got != tc.want {
				t.Fatalf("daneMatch(%v,%q)=%v want %v", tc.published, live, got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/dnsaudit/ -run TestDaneMatch`
Expected: FAIL — `undefined: daneMatch`.

- [ ] **Step 3: Implement `daneMatch`**

Add to `internal/dnsaudit/audit.go` (near `classifyDANE`):

```go
// daneMatch reports whether the live-cert TLSA value equals any published value.
// Comparison is case-insensitive and whitespace-trimmed; a rollover overlap
// (old + new published together) still matches the live cert.
func daneMatch(published []string, live string) bool {
	want := strings.TrimSpace(live)
	for _, p := range published {
		if strings.EqualFold(strings.TrimSpace(p), want) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/dnsaudit/ -run TestDaneMatch`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/dnsaudit/audit.go internal/dnsaudit/checks_test.go
git commit -m "feat(dnsaudit): add daneMatch TLSA comparison helper"
```

---

### Task 3: Live-cert match in `evalDANE`

**Files:**
- Modify: `internal/dnsaudit/audit.go` (`Auditor` struct + field, `New`, `evalDANE`, add `verifyDANEMatch`)
- Test: `internal/dnsaudit/checks_test.go`

**Interfaces:**
- Consumes: `daneMatch` (Task 2); `dane.Value` (Global Constraints).
- Produces: `Auditor.probeCert func(context.Context, string) (string, error)`; `verifyDANEMatch(ctx, hosts, published []string, base Finding) Finding`.

- [ ] **Step 1: Add the `probeCert` seam**

In `internal/dnsaudit/audit.go` add the import `"mailadmin/internal/dane"`. Add a field to `Auditor` (around line 97):

```go
type Auditor struct {
	conn        resolverConn
	http        *http.Client
	selectors   []string
	speculative bool
	// probeCert reads the live cert for host and returns its "3 1 1" TLSA value.
	// Defaults to a live STARTTLS read; overridden in tests to avoid the network.
	probeCert func(ctx context.Context, host string) (string, error)
}
```

In `New`, set the default after building the struct (before `return`):

```go
	a := &Auditor{
		conn:        &liveConn{resolver: resolver, c: &dns.Client{Net: "udp", Timeout: 4 * time.Second}},
		selectors:   selectors,
		speculative: speculative,
		http:        /* keep existing http.Client literal here */,
	}
	a.probeCert = func(ctx context.Context, host string) (string, error) {
		res, err := dane.Value(ctx, "", host)
		return res.Value, err
	}
	return a
```

(Refactor the existing `return &Auditor{...}` into the `a := &Auditor{...}` form, keeping the current `http` literal.)

- [ ] **Step 2: Write the failing test**

Add to `internal/dnsaudit/checks_test.go`. Use a fake conn that returns MX + TLSA; if a shared fake exists, extend it, otherwise add this local one:

```go
type daneFakeConn struct {
	hosts    []string
	tlsaVals []string
	ad       bool
}

func (f daneFakeConn) txt(context.Context, string) ([]string, error) { return nil, nil }
func (f daneFakeConn) dnssec(context.Context, string) (bool, bool, bool, error) {
	return false, false, false, nil
}
func (f daneFakeConn) mx(context.Context, string) ([]string, error) { return f.hosts, nil }
func (f daneFakeConn) tlsa(context.Context, string) ([]string, bool, error) {
	return f.tlsaVals, f.ad, nil
}

func TestEvalDANEMatch(t *testing.T) {
	base := daneFakeConn{hosts: []string{"mx.example."}, tlsaVals: []string{"3 1 1 abc"}, ad: true}
	cases := []struct {
		name       string
		probe      func(context.Context, string) (string, error)
		wantStatus Status
	}{
		{"match", func(context.Context, string) (string, error) { return "3 1 1 abc", nil }, Pass},
		{"mismatch", func(context.Context, string) (string, error) { return "3 1 1 zzz", nil }, Fail},
		{"unreachable", func(context.Context, string) (string, error) { return "", fmt.Errorf("dial timeout") }, Warn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Auditor{conn: base, probeCert: tc.probe}
			f := a.evalDANE(context.Background(), "example.com")
			if f.Status != tc.wantStatus {
				t.Fatalf("status=%s want %s (detail %q)", f.Status, tc.wantStatus, f.Detail)
			}
		})
	}
}

func TestEvalDANENon311SkipsMatch(t *testing.T) {
	conn := daneFakeConn{hosts: []string{"mx.example."}, tlsaVals: []string{"2 0 1 abc"}, ad: true}
	probed := false
	a := &Auditor{conn: conn, probeCert: func(context.Context, string) (string, error) {
		probed = true
		return "3 1 1 abc", nil
	}}
	f := a.evalDANE(context.Background(), "example.com")
	if f.Status != Pass {
		t.Fatalf("status=%s want Pass", f.Status)
	}
	if probed {
		t.Fatal("probeCert should not be called for non-3-1-1 TLSA")
	}
}
```

- [ ] **Step 2b: Run to verify it fails**

Run: `go test ./internal/dnsaudit/ -run TestEvalDANE`
Expected: FAIL — mismatch/unreachable currently return `Pass` (no match logic yet).

- [ ] **Step 3: Add the match logic to `evalDANE`**

Extend `evalDANE` to collect hosts-with-TLSA and published values, then verify. Replace the `evalDANE` body from Task 1 with:

```go
func (a *Auditor) evalDANE(ctx context.Context, domain string) Finding {
	hosts, err := a.conn.mx(ctx, domain)
	if err != nil {
		return Finding{Check: "DANE", Status: Warn, Detail: "MX lookup failed: " + err.Error()}
	}
	total, authed := 0, true
	var published, tlsaHosts []string
	for _, h := range hosts {
		vals, ad, terr := a.conn.tlsa(ctx, "_25._tcp."+h)
		if terr != nil || len(vals) == 0 {
			continue
		}
		total += len(vals)
		tlsaHosts = append(tlsaHosts, h)
		published = append(published, vals...)
		if !ad {
			authed = false
		}
	}
	base := classifyDANE(len(hosts), total, authed)
	if base.Status != Pass {
		return base // not deployed / unsigned / no MX — nothing to match
	}
	return a.verifyDANEMatch(ctx, tlsaHosts, published, base)
}

// verifyDANEMatch confirms the DNSSEC-authenticated TLSA actually matches the
// live certificate. Only "3 1 1" values are derivable; other usages leave the
// presence verdict intact. A reachable non-match is a hard Fail (senders bounce);
// an unreachable host downgrades only to Warn.
func (a *Auditor) verifyDANEMatch(ctx context.Context, hosts, published []string, base Finding) Finding {
	has311 := false
	for _, v := range published {
		if strings.HasPrefix(v, "3 1 1 ") {
			has311 = true
			break
		}
	}
	if !has311 {
		base.Detail += "; TLSA is not 3 1 1 — live-cert match not checked"
		return base
	}
	var lastErr error
	for _, h := range hosts {
		live, err := a.probeCert(ctx, h)
		if err != nil {
			lastErr = err
			continue
		}
		if !daneMatch(published, live) {
			return Finding{Check: "DANE", Status: Fail, Value: "cert mismatch",
				Detail: "published TLSA does not match live certificate (" + h +
					") — stale after key rotation, DANE senders will reject mail"}
		}
		return Finding{Check: "DANE", Status: Pass, Value: base.Value,
			Detail: base.Detail + "; matches live certificate"}
	}
	return Finding{Check: "DANE", Status: Warn, Value: base.Value,
		Detail: "TLSA authenticated but live cert unreachable to confirm match: " + lastErr.Error()}
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/dnsaudit/...`
Expected: PASS (all cases, including the existing `classifyDANE` tests).

- [ ] **Step 5: Commit**

```bash
git add internal/dnsaudit/audit.go internal/dnsaudit/checks_test.go
git commit -m "feat(dnsaudit): verify DANE TLSA matches live certificate"
```

---

### Task 4: `doctor` outbound DANE check

**Files:**
- Modify: `internal/cli/doctor.go` (add `binPostconf`, `classifyDANEOutbound`, `daneOutboundCheck`, wire into `runDoctor`)
- Test: `internal/cli/doctor_test.go` (create)

**Interfaces:**
- Produces: `classifyDANEOutbound(level, support string) checkResult`; `daneOutboundCheck(ctx, runner) checkResult`.

- [ ] **Step 1: Write the failing test**

Create `internal/cli/doctor_test.go`:

```go
package cli

import "testing"

func TestClassifyDANEOutbound(t *testing.T) {
	cases := []struct {
		name, level, support string
		want                 checkStatus
	}{
		{"dane+dnssec", "dane", "dnssec", statusOK},
		{"dane-only+dnssec", "dane-only", "dnssec", statusOK},
		{"dane without dnssec", "dane", "enabled", statusFail},
		{"not enabled", "may", "enabled", statusWarn},
		{"empty", "", "", statusWarn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyDANEOutbound(tc.level, tc.support); got.Status != tc.want {
				t.Fatalf("status=%s want %s (detail %q)", got.Status, tc.want, got.Detail)
			}
		})
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/cli/ -run TestClassifyDANEOutbound`
Expected: FAIL — `undefined: classifyDANEOutbound`.

- [ ] **Step 3: Implement the check**

In `internal/cli/doctor.go` add the constant (near `binOpenSSL`):

```go
	binPostconf = "/usr/sbin/postconf"
```

Add the classify + wrapper:

```go
// classifyDANEOutbound grades Postfix outbound DANE from smtp_tls_security_level
// and smtp_dns_support_level. DANE requires dnssec support to function at all; a
// dane level without it is silently inactive (FAIL). The detail names the
// fallback behaviour: "dane" is opportunistic (falls back to plaintext),
// "dane-only" has no fallback.
func classifyDANEOutbound(level, support string) checkResult {
	res := checkResult{Name: "dane-outbound"}
	level = strings.TrimSpace(level)
	support = strings.TrimSpace(support)
	isDane := level == "dane" || level == "dane-only"
	switch {
	case !isDane:
		res.Status = statusWarn
		res.Detail = "smtp_tls_security_level=" + quoteEmpty(level) + " — outbound DANE not enabled"
	case support != "dnssec":
		res.Status = statusFail
		res.Detail = "smtp_tls_security_level=" + level + " but smtp_dns_support_level=" +
			quoteEmpty(support) + " — DANE inactive without dnssec"
	default:
		fallback := "opportunistic, falls back to plaintext"
		if level == "dane-only" {
			fallback = "no fallback"
		}
		res.Status = statusOK
		res.Detail = level + " + dnssec (" + fallback + ")"
	}
	return res
}

// quoteEmpty renders an empty value as (unset) so blank postconf output is clear.
func quoteEmpty(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

// daneOutboundCheck reads the two postconf keys (one value per line, in argument
// order) and classifies them.
func daneOutboundCheck(ctx context.Context, runner *sys.Runner) checkResult {
	out, err := runner.Output(ctx, binPostconf, "-h",
		"smtp_tls_security_level", "smtp_dns_support_level")
	if err != nil {
		return checkResult{Name: "dane-outbound", Status: statusError, Detail: "postconf: " + firstNonEmptyLine(err.Error())}
	}
	lines := splitNonEmptyLines(out)
	var level, support string
	if len(lines) > 0 {
		level = lines[0]
	}
	if len(lines) > 1 {
		support = lines[1]
	}
	return classifyDANEOutbound(level, support)
}
```

- [ ] **Step 4: Wire into `runDoctor`**

In `runDoctor`, after the `tlsCheck` append (line 86):

```go
	results = append(results, daneOutboundCheck(ctx, runner))
```

- [ ] **Step 5: Run to verify it passes**

Run: `go test ./internal/cli/ -run TestClassifyDANEOutbound`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/doctor.go internal/cli/doctor_test.go
git commit -m "feat(doctor): check Postfix outbound DANE configuration"
```

---

### Task 5: `doctor` smtpd-cert drift + resolver checks

**Files:**
- Modify: `internal/cli/doctor.go` (add `binCat`, `daneCertCheck`, `classifyResolver`, `resolverCheck`, wire into `runDoctor`)
- Test: `internal/cli/doctor_test.go`

**Interfaces:**
- Consumes: `cfg.Mail.TLSCert` (config); `tlsCertPath` (existing default).
- Produces: `daneCertCheck(ctx, runner, wantCert string) checkResult`; `classifyResolver(resolvConf string) checkResult`; `resolverCheck(ctx, runner) checkResult`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/cli/doctor_test.go`:

```go
func TestClassifyResolver(t *testing.T) {
	cases := []struct {
		name, conf string
		want       checkStatus
	}{
		{"loopback v4", "nameserver 127.0.0.1\n", statusOK},
		{"loopback v6", "nameserver ::1\n", statusOK},
		{"remote", "nameserver 8.8.8.8\n", statusWarn},
		{"none", "# comment only\n", statusWarn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyResolver(tc.conf); got.Status != tc.want {
				t.Fatalf("status=%s want %s (detail %q)", got.Status, tc.want, got.Detail)
			}
		})
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/cli/ -run TestClassifyResolver`
Expected: FAIL — `undefined: classifyResolver`.

- [ ] **Step 3: Implement the checks**

In `internal/cli/doctor.go` add the constant (near `binPostconf`):

```go
	binCat = "/bin/cat"
```

Add:

```go
// daneCertCheck reports whether the cert Postfix's smtpd serves is the same file
// that feeds the DANE TLSA. A mismatch means the published TLSA pins a different
// key than inbound senders actually see. wantCert is the DANE cert source
// (config mail.tls_cert, falling back to the deploy path).
func daneCertCheck(ctx context.Context, runner *sys.Runner, wantCert string) checkResult {
	res := checkResult{Name: "dane-smtpd-cert"}
	if wantCert == "" {
		wantCert = tlsCertPath
	}
	out, err := runner.Output(ctx, binPostconf, "-h", "smtpd_tls_cert_file")
	if err != nil {
		res.Status = statusError
		res.Detail = "postconf: " + firstNonEmptyLine(err.Error())
		return res
	}
	got := firstNonEmptyLine(out)
	switch {
	case got == "":
		res.Status = statusWarn
		res.Detail = "smtpd_tls_cert_file is unset"
	case got != wantCert:
		res.Status = statusWarn
		res.Detail = "smtpd serves " + got + " but DANE TLSA is derived from " + wantCert + " — cert drift"
	default:
		res.Status = statusOK
		res.Detail = "smtpd cert matches DANE source: " + got
	}
	return res
}

// classifyResolver inspects resolv.conf nameservers. Outbound DANE needs a local
// validating resolver to trust the AD flag; a loopback nameserver is the expected
// topology (OK, best-effort — true validation is not directly probeable), a
// remote resolver is flagged.
func classifyResolver(resolvConf string) checkResult {
	res := checkResult{Name: "dane-resolver"}
	var ns []string
	for _, line := range splitNonEmptyLines(resolvConf) {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			ns = append(ns, f[1])
		}
	}
	if len(ns) == 0 {
		res.Status = statusWarn
		res.Detail = "no nameserver in resolv.conf — cannot confirm a validating resolver"
		return res
	}
	for _, n := range ns {
		if n == "::1" || strings.HasPrefix(n, "127.") {
			res.Status = statusOK
			res.Detail = "local resolver " + n + " (best-effort: DANE needs it to validate DNSSEC)"
			return res
		}
	}
	res.Status = statusWarn
	res.Detail = "resolver " + strings.Join(ns, ",") + " not loopback — DANE outbound needs a local validating resolver"
	return res
}

// resolverCheck reads resolv.conf through the exec chokepoint and classifies it.
func resolverCheck(ctx context.Context, runner *sys.Runner) checkResult {
	out, err := runner.Output(ctx, binCat, "/etc/resolv.conf")
	if err != nil {
		return checkResult{Name: "dane-resolver", Status: statusWarn, Detail: "cannot read /etc/resolv.conf: " + firstNonEmptyLine(err.Error())}
	}
	return classifyResolver(out)
}
```

- [ ] **Step 4: Wire into `runDoctor`**

The `daneCertCheck` needs the DANE cert source. In `runDoctor` (`cfg` is already in scope), after the `daneOutboundCheck` append:

```go
	results = append(results, daneCertCheck(ctx, runner, cfg.Mail.TLSCert))
	results = append(results, resolverCheck(ctx, runner))
```

- [ ] **Step 5: Run to verify it passes**

Run: `go test ./internal/cli/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/doctor.go internal/cli/doctor_test.go
git commit -m "feat(doctor): check smtpd-cert drift and validating resolver for DANE"
```

---

### Task 6: Documentation

**Files:**
- Modify: `docs/DNS.md` (DANE section)
- Modify: `README.md` (doctor description)

**Interfaces:** none.

- [ ] **Step 1: Extend the DANE section in `docs/DNS.md`**

Find the DANE section and add a subsection (place after the existing certificate-renewal content):

```markdown
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
```

- [ ] **Step 2: Update `README.md` doctor line**

Find the doctor entry/description and note the DANE checks. Change the doctor mention to read:

```markdown
- **Doctor** — health check: services, ports, TLS, rspamd config, and DANE
  (outbound `smtp_tls_security_level`/`smtp_dns_support_level`, smtpd-cert drift,
  validating resolver).
```

- [ ] **Step 3: Verify the docs build/read cleanly**

Run: `git diff --stat docs/DNS.md README.md`
Expected: both files modified.

- [ ] **Step 4: Full suite + commit**

Run: `go test ./...`
Expected: PASS.

```bash
git add docs/DNS.md README.md
git commit -m "docs: document DANE verification (audit live-cert match, doctor)"
```

---

## Self-Review Notes

- **Spec coverage:** Gap 1 → Tasks 1-3; Gap 2 (outbound) → Task 4; Gap 2 (resolver) → Task 5; Gap 3 → Task 5; Gap 4 → Task 4 detail + Task 6 docs. All covered.
- **Type consistency:** `tlsa` returns `([]string, bool, error)` everywhere (Task 1 interface + liveConn + fakes; Task 3 fake). `probeCert` signature identical in struct, default, and test stubs. `checkResult`/`checkStatus` reused from existing doctor. `quoteEmpty` defined once (Task 4), reused (Task 5 uses only its own helpers).
- **No placeholders:** every code step shows complete code.
