package dnsrepo

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"mailadmin/internal/dnsprovider"
)

const (
	managedBegin = "// BEGIN mailadmin-managed"
	managedEnd   = "// END mailadmin-managed"
	legacyBegin  = "// BEGIN mailadmin-tlsa"
	legacyEnd    = "// END mailadmin-tlsa"
)

// ErrMultiLine is returned for a record that spans several lines. mailadmin only
// edits single-line records and refuses to guess at the others.
var ErrMultiLine = errors.New("dnsrepo: record spans several lines, edit that zone by hand")

var reStatement = regexp.MustCompile(`^([A-Z]+)\("`)
var reQuoted = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)

// Statement is one DNSControl record line inside a D(...) call.
type Statement struct {
	Func   string   // A, AAAA, CNAME, MX, TXT, SRV, TLSA
	Quoted []string // quoted arguments; Quoted[0] is the record name
	Line   string   // the line as written, trimmed
}

// Name returns the record name (first quoted argument).
func (s Statement) Name() string {
	if len(s.Quoted) == 0 {
		return ""
	}
	return s.Quoted[0]
}

// MailScope reports whether a record belongs to mail: MX, SRV, TLSA, the SPF, DMARC,
// TLS-RPT, MTA-STS and DKIM records, and the mail host, autoconfig, autodiscover and
// MTA-STS addresses. Web records (apex A/AAAA, www, netbird wildcards) are not mail.
func MailScope(s Statement) bool {
	name := s.Name()
	switch s.Func {
	case "MX", "SRV", "TLSA":
		return true
	case "CNAME":
		return name == "autoconfig" || name == "autodiscover" || strings.HasSuffix(name, "._domainkey")
	case "A", "AAAA":
		return name == "mail" || name == "autoconfig" || name == "autodiscover" || name == "mta-sts"
	case "TXT":
		if len(s.Quoted) < 2 {
			return false
		}
		val := s.Quoted[1]
		return name == "_dmarc" || name == "_smtp._tls" || name == "_mta-sts" ||
			strings.HasSuffix(name, "._domainkey") ||
			(name == "@" && strings.HasPrefix(val, "v=spf1"))
	}
	return false
}

// parseStatement returns the statement of a line, or ok=false for lines that are
// not records (options, comments, variables).
func parseStatement(line string) (Statement, bool) {
	t := strings.TrimSpace(line)
	if !reStatement.MatchString(t) {
		return Statement{}, false
	}
	fn, _, _ := strings.Cut(t, "(")
	var q []string
	for _, m := range reQuoted.FindAllStringSubmatch(t, -1) {
		q = append(q, m[1])
	}
	return Statement{Func: fn, Quoted: q, Line: t}, true
}

// SetManaged replaces the mailadmin block of domain with lines (one DNSControl
// statement per line) and drops the legacy mailadmin-tlsa block. Records outside the
// block are kept, except those for which drop returns true; they are returned in
// removed. The block is written last, before the closing ");" of the D call.
func SetManaged(src, domain string, lines []string, drop func(Statement) bool) (out string, removed []string, err error) {
	start := strings.Index(src, `D("`+domain+`"`)
	if start < 0 {
		return "", nil, fmt.Errorf("%w: %s", ErrNoDomain, domain)
	}
	loc := reCloseCall.FindStringIndex(src[start:])
	if loc == nil {
		return "", nil, fmt.Errorf("dnsrepo: no closing ); after D(%q", domain)
	}
	end := start + loc[0]
	body := strings.Split(src[start:end], "\n")

	var keep []string
	skip := false
	for i, l := range body {
		t := strings.TrimSpace(l)
		switch {
		case t == managedBegin || t == legacyBegin:
			skip = true
			continue
		case t == managedEnd || t == legacyEnd:
			skip = false
			continue
		case skip:
			continue
		}
		if i == 0 { // the D( line itself
			keep = append(keep, l)
			continue
		}
		st, ok := parseStatement(l)
		if !ok {
			keep = append(keep, l)
			continue
		}
		if !strings.HasSuffix(st.Line, ")") && !strings.HasSuffix(st.Line, "),") {
			return "", nil, ErrMultiLine
		}
		if drop != nil && drop(st) {
			removed = append(removed, st.Line)
			continue
		}
		keep = append(keep, l)
	}

	// The last kept line needs a trailing comma before the new block.
	for i := len(keep) - 1; i > 0; i-- {
		t := strings.TrimRight(keep[i], " \t")
		if t == "" || strings.HasPrefix(strings.TrimSpace(t), "//") {
			continue
		}
		if !strings.HasSuffix(t, ",") && !strings.HasSuffix(t, "(") {
			keep[i] = t + ","
		}
		break
	}
	// Trailing empty lines are rebuilt below, so the result is the same on every run.
	for len(keep) > 1 && strings.TrimSpace(keep[len(keep)-1]) == "" {
		keep = keep[:len(keep)-1]
	}
	if len(lines) > 0 {
		keep = append(keep, "    "+managedBegin)
		for _, l := range lines {
			keep = append(keep, "    "+l+",")
		}
		keep = append(keep, "    "+managedEnd)
	}
	// The closing ");" line follows on its own line.
	return src[:start] + strings.Join(append(keep, ""), "\n") + src[end:], removed, nil
}

// RenderRecord returns the DNSControl statement for a desired record.
func RenderRecord(r dnsprovider.Record) (string, error) {
	name := r.Name
	if name == "" {
		name = "@"
	}
	switch strings.ToUpper(r.Type) {
	case "A", "AAAA":
		return fmt.Sprintf(`%s(%s, %s)`, strings.ToUpper(r.Type), js(name), js(r.Content)), nil
	case "CNAME":
		return fmt.Sprintf(`CNAME(%s, %s)`, js(name), js(fqdn(r.Content))), nil
	case "MX":
		return fmt.Sprintf(`MX(%s, %d, %s)`, js(name), r.Prio, js(fqdn(r.Content))), nil
	case "TXT":
		return fmt.Sprintf(`TXT(%s, %s)`, js(name), js(r.Content)), nil
	case "SRV":
		return fmt.Sprintf(`SRV(%s, %d, %d, %d, %s)`, js(name), r.Prio, r.Weight, r.Port, js(fqdn(r.Content))), nil
	case "TLSA":
		f := strings.Fields(r.Content)
		if len(f) != 4 {
			return "", fmt.Errorf("dnsrepo: TLSA content %q", r.Content)
		}
		u, e1 := strconv.Atoi(f[0])
		s, e2 := strconv.Atoi(f[1])
		m, e3 := strconv.Atoi(f[2])
		if e1 != nil || e2 != nil || e3 != nil {
			return "", fmt.Errorf("dnsrepo: TLSA content %q", r.Content)
		}
		return fmt.Sprintf(`TLSA(%s, %d, %d, %d, %s)`, js(name), u, s, m, js(strings.ToLower(f[3]))), nil
	}
	return "", fmt.Errorf("dnsrepo: record type %s is not supported", r.Type)
}

// js returns s as a double-quoted JavaScript string.
func js(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// fqdn ends a host name with a dot.
func fqdn(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}
