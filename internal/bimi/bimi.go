// Package bimi builds and validates the pieces needed to provision BIMI
// (Brand Indicators for Message Identification) for a domain: a best-effort,
// cheap sanity check of a locally-held SVG logo file, and the
// default._bimi TXT record value (RFC-draft BIMI: "v=BIMI1; l=<url>; a=<url>").
//
// mailadmin does not host the logo or VMC itself (see internal/cli/domain.go's
// runDomainSetBIMI doc comment for the reasoning) — the operator hosts both at
// a stable HTTPS URL and this package only validates a local copy of the SVG
// and assembles the record that points at it.
package bimi

import (
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
)

// maxSVGBytes bounds how much of a candidate logo file is parsed, so a
// mistakenly-huge file cannot cause unbounded work.
const maxSVGBytes = 1 << 20 // 1 MiB — a Tiny-PS BIMI SVG is expected to be a few KB

// wantBaseProfile is the SVG profile BIMI (and the Authindicators Working
// Group spec) requires: SVG Tiny Portable/Secure.
const wantBaseProfile = "tiny-ps"

// ErrTooLarge is returned by ValidateSVG when the input exceeds maxSVGBytes.
var ErrTooLarge = fmt.Errorf("bimi: svg exceeds %d bytes", maxSVGBytes)

// svgRoot captures just enough of the root <svg> element to check the
// baseProfile attribute; everything else is ignored.
type svgRoot struct {
	XMLName     xml.Name `xml:"svg"`
	BaseProfile string   `xml:"baseProfile,attr"`
}

// ValidateSVG performs a cheap, best-effort sanity check that data looks like
// a Tiny-PS BIMI logo: well-formed XML, a root <svg> element, and
// baseProfile="tiny-ps". This deliberately does NOT attempt full SVG Tiny PS
// conformance validation (no color-space, no forbidden-element, no size
// checks) — that is out of scope; it only catches the two most common
// mistakes (a non-SVG file, or a regular SVG exported without the BIMI
// profile).
func ValidateSVG(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("bimi: empty file")
	}
	if len(data) > maxSVGBytes {
		return ErrTooLarge
	}
	var root svgRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("bimi: not well-formed XML: %w", err)
	}
	if root.XMLName.Local != "svg" {
		return fmt.Errorf("bimi: root element is <%s>, not <svg>", root.XMLName.Local)
	}
	if root.BaseProfile != wantBaseProfile {
		if root.BaseProfile == "" {
			return fmt.Errorf(`bimi: <svg> is missing baseProfile=%q (required for BIMI)`, wantBaseProfile)
		}
		return fmt.Errorf("bimi: <svg> baseProfile=%q, want %q", root.BaseProfile, wantBaseProfile)
	}
	return nil
}

// Record is the desired default._bimi TXT record's owner name and value.
type Record struct {
	Name    string // always "default._bimi"
	Content string // "v=BIMI1; l=<logo-url>;" [+ " a=<vmc-url>;"]
}

// RecordName is the fixed owner name BIMI is published at (RFC draft: only
// the "default" selector is standardised; per-sender selectors are not used
// by mail providers today).
const RecordName = "default._bimi"

// BuildRecord assembles the default._bimi TXT record from a required logo URL
// and an optional Verified Mark Certificate (VMC) URL. Both, when given, must
// be https:// URLs — BIMI implementations require the logo (and any VMC) to
// be fetched over TLS.
func BuildRecord(logoURL, vmcURL string) (Record, error) {
	logoURL = strings.TrimSpace(logoURL)
	if logoURL == "" {
		return Record{}, fmt.Errorf("bimi: a logo URL is required (--logo-url)")
	}
	if err := validHTTPSURL(logoURL); err != nil {
		return Record{}, fmt.Errorf("bimi: logo url: %w", err)
	}
	content := "v=BIMI1; l=" + logoURL + ";"

	vmcURL = strings.TrimSpace(vmcURL)
	if vmcURL != "" {
		if err := validHTTPSURL(vmcURL); err != nil {
			return Record{}, fmt.Errorf("bimi: vmc url: %w", err)
		}
		content += " a=" + vmcURL + ";"
	}
	return Record{Name: RecordName, Content: content}, nil
}

// validHTTPSURL requires an absolute https:// URL with a host.
func validHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a valid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("must be an https:// URL, got %q", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("missing host in %q", raw)
	}
	return nil
}
