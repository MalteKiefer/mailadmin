package dnsaudit

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// spfLookupLimit is the RFC 7208 §4.6.4 cap on DNS-querying mechanisms.
const spfLookupLimit = 10

// filterByTag returns the TXT records whose (trimmed) value begins with the
// given version tag, case-insensitively (e.g. "v=spf1", "v=DMARC1").
func filterByTag(records []string, tag string) []string {
	var out []string
	for _, r := range records {
		s := strings.TrimSpace(r)
		if len(s) >= len(tag) && strings.EqualFold(s[:len(tag)], tag) {
			out = append(out, s)
		}
	}
	return out
}

// singleSPF returns the sole SPF record if exactly one exists.
func singleSPF(records []string) (string, bool) {
	spf := filterByTag(records, "v=spf1")
	if len(spf) != 1 {
		return "", false
	}
	return spf[0], true
}

// parseTags splits a ";"-separated key=value policy string (DMARC, DKIM, BIMI,
// STS) into a lower-cased-key map. Later duplicate keys win.
func parseTags(record string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		tags[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return tags
}

// spfMechanism splits an SPF term into its mechanism name (without qualifier)
// and argument. "include:_spf.google.com" -> ("include","_spf.google.com");
// "-all" -> ("all",""); "redirect=x.com" -> ("redirect","x.com").
func spfMechanism(tok string) (mech, arg string) {
	if k, v, ok := strings.Cut(tok, "="); ok && strings.EqualFold(k, "redirect") {
		return "redirect", strings.TrimSuffix(v, ".")
	}
	// Strip a leading qualifier (+ - ~ ?).
	if len(tok) > 0 && strings.ContainsRune("+-~?", rune(tok[0])) {
		tok = tok[1:]
	}
	name, val, hasArg := strings.Cut(tok, ":")
	name = strings.ToLower(name)
	if hasArg {
		return name, strings.TrimSuffix(val, ".")
	}
	return name, ""
}

// evalSPF checks presence, uniqueness, and the trailing all-qualifier.
func evalSPF(records []string) []Finding {
	spf := filterByTag(records, "v=spf1")
	switch {
	case len(spf) == 0:
		return []Finding{{Check: "SPF", Status: Fail, Detail: "no v=spf1 record — senders can be spoofed"}}
	case len(spf) > 1:
		return []Finding{{Check: "SPF", Status: Fail, Value: fmt.Sprintf("%d records", len(spf)),
			Detail: "must be exactly one SPF record (RFC 7208 §3.2); multiple = permerror"}}
	}
	rec := spf[0]
	f := Finding{Check: "SPF", Status: Pass, Value: rec}

	qual, found := spfAllQualifier(rec)
	switch {
	case !found:
		f.Status, f.Detail = Warn, "no 'all' mechanism — policy is open-ended"
	case qual == "-":
		f.Detail = "-all (hardfail)"
	case qual == "~":
		f.Detail = "~all (softfail) — acceptable, -all is stricter"
	case qual == "?":
		f.Status, f.Detail = Warn, "?all (neutral) — provides no protection"
	case qual == "+":
		f.Status, f.Detail = Fail, "+all allows the whole internet to send as this domain"
	}
	return []Finding{f}
}

// spfAllQualifier returns the qualifier of the final `all` mechanism.
func spfAllQualifier(record string) (string, bool) {
	for _, tok := range strings.Fields(record) {
		q := "+"
		t := tok
		if len(t) > 0 && strings.ContainsRune("+-~?", rune(t[0])) {
			q, t = string(t[0]), t[1:]
		}
		if strings.EqualFold(t, "all") {
			return q, true
		}
	}
	return "", false
}

// spfLookupFinding grades the DNS-lookup count against the limit of 10.
func spfLookupFinding(n int, capped bool) Finding {
	f := Finding{Check: "SPF lookups"}
	switch {
	case capped || n > spfLookupLimit:
		f.Status = Fail
		f.Value = fmt.Sprintf(">%d", spfLookupLimit)
		f.Detail = "exceeds the 10-lookup limit (RFC 7208 §4.6.4) — permerror, SPF ignored"
	case n >= 8:
		f.Status = Warn
		f.Value = strconv.Itoa(n)
		f.Detail = "close to the 10-lookup limit"
	default:
		f.Status = Pass
		f.Value = strconv.Itoa(n)
		f.Detail = "within the 10-lookup limit"
	}
	return f
}

// evalDKIM validates a selector's key: presence, non-revocation, and strength.
// found reports whether any DKIM record exists at the selector (false lets the
// caller skip speculative, guessed selectors).
func evalDKIM(selector string, records []string) (f Finding, found bool) {
	f = Finding{Check: "DKIM " + selector}
	dk := filterByTag(records, "v=DKIM1")
	// Some publishers omit the v= tag; fall back to any p= record.
	if len(dk) == 0 {
		for _, r := range records {
			if strings.Contains(r, "p=") {
				dk = append(dk, strings.TrimSpace(r))
			}
		}
	}
	if len(dk) == 0 {
		f.Status, f.Detail = Warn, "no DKIM record at this selector"
		return f, false
	}
	tags := parseTags(dk[0])
	p, hasP := tags["p"]
	if !hasP {
		f.Status, f.Detail = Fail, "malformed record (no p= key)"
		return f, true
	}
	if p == "" {
		f.Status, f.Detail = Fail, "empty p= — key revoked"
		return f, true
	}
	alg := strings.ToLower(tags["k"])
	if alg == "" {
		alg = "rsa"
	}
	if alg == "ed25519" {
		f.Status, f.Value, f.Detail = Pass, "ed25519", "modern EdDSA key"
		return f, true
	}
	bits, ok := rsaKeyBits(p)
	if !ok {
		f.Status, f.Detail = Warn, "present but public key could not be parsed"
		return f, true
	}
	f.Value = fmt.Sprintf("rsa-%d", bits)
	switch {
	case bits < 1024:
		f.Status, f.Detail = Fail, "key shorter than 1024 bits — trivially breakable"
	case bits < 2048:
		f.Status, f.Detail = Warn, "1024-bit key — 2048 recommended"
	default:
		f.Status, f.Detail = Pass, "2048-bit or stronger"
	}
	return f, true
}

// rsaKeyBits parses a base64 DER SubjectPublicKeyInfo and returns the RSA
// modulus size in bits.
func rsaKeyBits(p string) (int, bool) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(p))
	if err != nil {
		return 0, false
	}
	pub, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return 0, false
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen(), true
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize, true
	case ed25519.PublicKey:
		return 256, true
	}
	return 0, false
}

// evalDMARC checks presence, uniqueness, policy strength, and reporting. It
// returns the parsed policy ("none"/"quarantine"/"reject"/"") for BIMI's
// cross-check plus the findings.
func evalDMARC(records []string) (policy string, findings []Finding) {
	dm := filterByTag(records, "v=DMARC1")
	switch {
	case len(dm) == 0:
		return "", []Finding{{Check: "DMARC", Status: Fail, Detail: "no _dmarc record — no spoofing policy or reporting"}}
	case len(dm) > 1:
		return "", []Finding{{Check: "DMARC", Status: Fail, Value: fmt.Sprintf("%d records", len(dm)),
			Detail: "must be exactly one DMARC record (RFC 7489)"}}
	}
	tags := parseTags(dm[0])
	policy = strings.ToLower(tags["p"])
	main := Finding{Check: "DMARC", Value: "p=" + policy}
	switch policy {
	case "reject":
		main.Status, main.Detail = Pass, "p=reject — strongest enforcement"
	case "quarantine":
		main.Status, main.Detail = Pass, "p=quarantine — enforced"
	case "none":
		main.Status, main.Detail = Warn, "p=none — monitoring only, no enforcement"
	default:
		main.Status, main.Value, main.Detail = Fail, "p="+tags["p"], "missing or invalid p= policy"
	}
	findings = append(findings, main)

	// pct downgrades enforcement coverage.
	if pct, ok := tags["pct"]; ok && pct != "100" {
		findings = append(findings, Finding{Check: "DMARC pct", Status: Warn, Value: "pct=" + pct,
			Detail: "policy applied to only part of the mail"})
	}

	// Aggregate reporting.
	rep := Finding{Check: "DMARC reporting"}
	if rua := tags["rua"]; rua != "" {
		rep.Status, rep.Value, rep.Detail = Pass, "rua set", "aggregate reports enabled"
	} else {
		rep.Status, rep.Detail = Warn, "no rua= — you receive no aggregate reports"
	}
	findings = append(findings, rep)
	return policy, findings
}

// evalMTASTSRecord checks the _mta-sts TXT record (presence, uniqueness, id).
func evalMTASTSRecord(records []string) Finding {
	f := Finding{Check: "MTA-STS record"}
	sts := filterByTag(records, "v=STSv1")
	switch {
	case len(sts) == 0:
		f.Status, f.Detail = Info, "no _mta-sts TXT — MTA-STS not deployed"
	case len(sts) > 1:
		f.Status, f.Value, f.Detail = Fail, fmt.Sprintf("%d records", len(sts)),
			"multiple _mta-sts TXT records — remove the stale one(s)"
	default:
		tags := parseTags(sts[0])
		if id := tags["id"]; id != "" {
			f.Status, f.Value, f.Detail = Pass, "id="+id, "policy record present"
		} else {
			f.Status, f.Detail = Fail, "STSv1 record without id="
		}
	}
	return f
}

// evalMTASTSPolicy checks a fetched mta-sts.txt policy body (mode, mx, max_age).
func evalMTASTSPolicy(body string) Finding {
	f := Finding{Check: "MTA-STS policy"}
	fields := map[string][]string{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		fields[key] = append(fields[key], strings.TrimSpace(v))
	}
	if len(fields["version"]) == 0 && len(fields["mode"]) == 0 {
		f.Status, f.Detail = Fail, "served but not a valid STS policy"
		return f
	}
	mode := ""
	if len(fields["mode"]) > 0 {
		mode = strings.ToLower(fields["mode"][0])
	}
	mxCount := len(fields["mx"])
	switch mode {
	case "enforce":
		f.Status, f.Value = Pass, fmt.Sprintf("enforce, %d mx", mxCount)
		f.Detail = "TLS required for delivery"
	case "testing":
		f.Status, f.Value, f.Detail = Warn, "testing", "failures reported but delivery still allowed"
	case "none":
		f.Status, f.Value, f.Detail = Warn, "none", "policy disabled"
	default:
		f.Status, f.Detail = Fail, "invalid or missing mode"
	}
	if mxCount == 0 && (mode == "enforce" || mode == "testing") {
		f.Status, f.Detail = Fail, "policy lists no mx — all delivery would fail"
	}
	return f
}

// evalTLSRPT checks the _smtp._tls TXT record.
func evalTLSRPT(records []string) Finding {
	f := Finding{Check: "TLS-RPT"}
	rpt := filterByTag(records, "v=TLSRPTv1")
	if len(rpt) == 0 {
		f.Status, f.Detail = Info, "no _smtp._tls TXT — no TLS failure reporting"
		return f
	}
	if rua := parseTags(rpt[0])["rua"]; rua != "" {
		f.Status, f.Value, f.Detail = Pass, "rua set", "TLS reporting enabled"
	} else {
		f.Status, f.Detail = Warn, "TLSRPTv1 without rua= destination"
	}
	return f
}

// evalBIMI checks the default._bimi record and cross-checks DMARC enforcement,
// which BIMI requires (p=quarantine or reject).
func evalBIMI(records []string, dmarcPolicy string) Finding {
	f := Finding{Check: "BIMI"}
	bimi := filterByTag(records, "v=BIMI1")
	if len(bimi) == 0 {
		f.Status, f.Detail = Info, "no default._bimi record (optional)"
		return f
	}
	tags := parseTags(bimi[0])
	l, a := tags["l"], tags["a"]
	if l == "" {
		f.Status, f.Detail = Fail, "BIMI1 record without l= logo URL"
		return f
	}
	if dmarcPolicy != "quarantine" && dmarcPolicy != "reject" {
		f.Status, f.Value, f.Detail = Warn, "logo set", "BIMI needs DMARC p=quarantine or reject to display"
		return f
	}
	if a != "" {
		f.Status, f.Value, f.Detail = Pass, "logo + VMC", "verified mark certificate present"
	} else {
		f.Status, f.Value, f.Detail = Warn, "logo, no VMC", "most mailbox providers require a VMC (a=)"
	}
	return f
}
