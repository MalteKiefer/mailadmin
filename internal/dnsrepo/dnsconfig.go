// Package dnsrepo edits the DNSControl repository that holds the zones (dnsconfig.js)
// and proposes the change as a pull request. mailadmin owns one marked block per
// domain inside the domain's D(...) call; everything else in the file is left alone.
package dnsrepo

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	beginMark = "// BEGIN mailadmin-tlsa"
	endMark   = "// END mailadmin-tlsa"
)

// ErrNoDomain is returned when dnsconfig.js has no D("<domain>", ...) call.
var ErrNoDomain = errors.New("dnsrepo: domain not found in dnsconfig.js")

var reCloseCall = regexp.MustCompile(`(?m)^\s*\);`)

// SetTLSA returns src with the mailadmin TLSA block of domain set to one record. The
// record is TLSA(name, usage, selector, matching, cert), name relative to the zone.
// An existing block is replaced; otherwise the block is added before the closing
// ");" of the domain's D call. The call is unchanged when the block already matches.
func SetTLSA(src, domain, name string, usage, selector, matching int, cert string) (string, error) {
	start := strings.Index(src, `D("`+domain+`"`)
	if start < 0 {
		return "", fmt.Errorf("%w: %s", ErrNoDomain, domain)
	}
	loc := reCloseCall.FindStringIndex(src[start:])
	if loc == nil {
		return "", fmt.Errorf("dnsrepo: no closing ); after D(%q", domain)
	}
	end := start + loc[0]
	call := src[start:end]

	block := fmt.Sprintf("    %s\n    TLSA(%q, %d, %d, %d, %q),\n    %s\n",
		beginMark, name, usage, selector, matching, cert, endMark)

	if b := strings.Index(call, beginMark); b >= 0 {
		e := strings.Index(call, endMark)
		if e < b {
			return "", fmt.Errorf("dnsrepo: malformed mailadmin block in D(%q)", domain)
		}
		lineStart := strings.LastIndex(call[:b], "\n") + 1
		lineEnd := e + len(endMark)
		if nl := strings.Index(call[lineEnd:], "\n"); nl >= 0 {
			lineEnd += nl + 1
		}
		newCall := call[:lineStart] + block + call[lineEnd:]
		return src[:start] + newCall + src[end:], nil
	}

	// Insert before the closing ");". The argument before it needs a trailing comma.
	prev := strings.TrimRight(call, " \t\r\n")
	if !strings.HasSuffix(prev, ",") {
		prev += ","
	}
	return src[:start] + prev + "\n" + block + src[end:], nil
}
