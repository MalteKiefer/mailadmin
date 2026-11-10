// Package rspamdconf reads and surgically edits the small subset of rspamd's
// UCL local.d config files that `mailadmin security ratelimit`/`greylist`
// tune: local.d/ratelimit.conf's `rates { ... }` block and local.d/
// greylist.conf's top-level `timeout`/`expire` scalars.
//
// rspamd's config language (UCL) is considerably more general than what these
// two files actually use in practice, includes, arrays, heredocs, implicit
// object nesting without braces, macros, etc. Pulling in a full UCL parser
// (none is already an indirect dependency of this module) to read two small,
// conventionally-formatted files would add a new third-party dependency for
// a feature that only ever needs to read/write a handful of named scalar
// settings. Corrupting an operator's hand-edited rspamd config is a much
// worse outcome than this feature not existing, so the design goes the other
// way: a narrow, well-tested, line-oriented parser that recognises exactly
// two shapes:
//
//	name { ... }              (one block open/close per line, not nested)
//	key = value;              (optionally inside one block, "dotted" as
//	                            "block.key")
//
// , and otherwise treats every line as opaque text that is preserved
// byte-for-byte on write. Any config file feature outside that narrow grammar
// (nested blocks, multi-line values, arrays, includes, macros) is simply
// invisible to Get/Set: those lines pass through unmodified, and a key that
// lives inside such a construct is reported "not found" rather than
// mis-parsed.
package rspamdconf

import (
	"errors"
	"regexp"
	"strings"
)

// ErrKeyNotFound is returned by Document.Get when keyPath has no matching
// assignment line, and by Document.Set when neither the key nor a block that
// could hold it already exists (see Document.Set for the fallback rules that
// do apply).
var ErrKeyNotFound = errors.New("rspamdconf: key not found")

// ErrUnsupportedKey is returned when keyPath is nested more than one level
// deep ("a.b.c"), which this narrow grammar does not model.
var ErrUnsupportedKey = errors.New("rspamdconf: unsupported key path")

// ErrUnknownSetting is returned for a greylist setting name outside
// GreylistSettings.
var ErrUnknownSetting = errors.New("rspamdconf: unknown greylist setting")

// reBlockOpen matches a single-line block header, e.g. "rates {" or the UCL
// object form "to = {".
var reBlockOpen = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*=?\s*\{\s*$`)

// reBlockClose matches a bare block closer, e.g. "}" (UCL does not require a
// trailing semicolon on a block, unlike a scalar assignment).
var reBlockClose = regexp.MustCompile(`^\s*\}\s*;?\s*$`)

// reAssign matches a single-line scalar assignment, e.g. `timeout = 300s;`
// or `  to = "20 / 1min"; # comment`. Groups: 1=indent, 2=key, 3=" = "
// separator (whitespace-exact), 4=value token (exact, unquoted/unquoted as
// found), 5=trailing (";" plus anything after, e.g. a comment).
var reAssign = regexp.MustCompile(`^(\s*)([A-Za-z_][A-Za-z0-9_.-]*)(\s*=\s*)(.*?)(;\s*(?:#.*)?)$`)

// line is one physical line of the file, retained verbatim (raw) so unrelated
// lines survive a Set untouched. Assignment lines additionally decompose into
// prefix/value/suffix so only the value token is ever replaced.
type line struct {
	raw string

	isAssign bool
	keyPath  string // dotted, e.g. "rates.to" or "timeout"
	prefix   string // raw text before the value token (indent + key + " = ")
	value    string // the value token exactly as found
	suffix   string // raw text from ";" onward
}

func (l line) rebuild() string {
	if !l.isAssign {
		return l.raw
	}
	return l.prefix + l.value + l.suffix
}

// Document is a parsed rspamd local.d config file: an ordered list of lines,
// most opaque, a few recognised as block markers or scalar assignments.
type Document struct {
	lines           []line
	trailingNewline bool
}

// Parse reads content into a Document. It never fails: anything outside the
// recognised grammar is kept as an opaque line, so Parse . Bytes() is always
// a byte-for-byte round trip of the input (see the parser tests).
func Parse(content []byte) *Document {
	s := string(content)
	trailingNewline := strings.HasSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\n")

	var rawLines []string
	if s == "" && !trailingNewline {
		// Empty input: zero lines, not one empty line.
		rawLines = nil
	} else {
		rawLines = strings.Split(s, "\n")
	}

	doc := &Document{trailingNewline: trailingNewline || len(content) == 0}
	var stack []string
	for _, raw := range rawLines {
		if m := reBlockOpen.FindStringSubmatch(raw); m != nil {
			stack = append(stack, m[1])
			doc.lines = append(doc.lines, line{raw: raw})
			continue
		}
		if reBlockClose.MatchString(raw) {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			doc.lines = append(doc.lines, line{raw: raw})
			continue
		}
		if m := reAssign.FindStringSubmatch(raw); m != nil {
			key := m[2]
			keyPath := key
			if len(stack) > 0 {
				keyPath = strings.Join(append(append([]string{}, stack...), key), ".")
			}
			doc.lines = append(doc.lines, line{
				raw:      raw,
				isAssign: true,
				keyPath:  keyPath,
				prefix:   m[1] + m[2] + m[3],
				value:    m[4],
				suffix:   m[5],
			})
			continue
		}
		doc.lines = append(doc.lines, line{raw: raw})
	}
	return doc
}

// Bytes reassembles the document, reproducing the original input exactly
// wherever it was not modified via Set.
func (d *Document) Bytes() []byte {
	parts := make([]string, len(d.lines))
	for i, l := range d.lines {
		parts[i] = l.rebuild()
	}
	out := strings.Join(parts, "\n")
	if d.trailingNewline && len(d.lines) > 0 {
		out += "\n"
	}
	return []byte(out)
}

// Get returns the raw value token for keyPath (e.g. `"20 / 1min"` or `300s`,
// exactly as it appears in the file, quotes included if present).
func (d *Document) Get(keyPath string) (value string, found bool) {
	for _, l := range d.lines {
		if l.isAssign && l.keyPath == keyPath {
			return l.value, true
		}
	}
	return "", false
}

// Set replaces the value token of the assignment matching keyPath, leaving
// every other line byte-for-byte unchanged, and returns the previous value.
//
// If keyPath does not exist yet, Set falls back to creating it, in order of
// preference:
//  1. keyPath is "block.key" and "block { ... }" already exists: a new
//     "  key = value;" line is inserted just before that block's closing
//     brace.
//  2. keyPath is "block.key" and no such block exists: a new block is
//     appended at the end of the file.
//  3. keyPath has no dot (top-level): a new "key = value;" line is appended
//     at the end of the file.
//
// keyPath with more than one dot is rejected with ErrUnsupportedKey, this
// parser only ever models one level of nesting, matching what ratelimit.conf
// and greylist.conf actually use.
func (d *Document) Set(keyPath, newValue string) (oldValue string, err error) {
	parts := strings.Split(keyPath, ".")
	if len(parts) > 2 {
		return "", ErrUnsupportedKey
	}

	for i, l := range d.lines {
		if l.isAssign && l.keyPath == keyPath {
			old := l.value
			d.lines[i].value = newValue
			return old, nil
		}
	}

	if len(parts) == 1 {
		d.appendLine(parts[0] + " = " + newValue + ";")
		return "", nil
	}

	block, key := parts[0], parts[1]
	if _, closeIdx, ok := d.findBlock(block); ok {
		newLine := line{
			raw:      "  " + key + " = " + newValue + ";",
			isAssign: true,
			keyPath:  keyPath,
			prefix:   "  " + key + " = ",
			value:    newValue,
			suffix:   ";",
		}
		rest := append([]line{newLine}, d.lines[closeIdx:]...)
		d.lines = append(d.lines[:closeIdx:closeIdx], rest...)
		return "", nil
	}

	// No such block: append a fresh one at the end of the file.
	d.appendLine(block + " {")
	d.appendLine("  " + key + " = " + newValue + ";")
	d.appendLine("}")
	return "", nil
}

// appendLine adds a new opaque-shaped raw line at the end of the document.
func (d *Document) appendLine(raw string) {
	d.lines = append(d.lines, line{raw: raw})
	d.trailingNewline = true
}

// findBlock locates a top-level "name {" ... "}" pair (not nested), returning
// the index of the open line and the index of the matching close line.
func (d *Document) findBlock(name string) (openIdx, closeIdx int, ok bool) {
	for i, l := range d.lines {
		if m := reBlockOpen.FindStringSubmatch(l.raw); m != nil && m[1] == name {
			// Nested objects (to = { ... }) have their own closers.
			depth := 0
			for j := i + 1; j < len(d.lines); j++ {
				switch {
				case reBlockOpen.MatchString(d.lines[j].raw):
					depth++
				case reBlockClose.MatchString(d.lines[j].raw):
					if depth == 0 {
						return i, j, true
					}
					depth--
				}
			}
			return i, -1, false
		}
	}
	return -1, -1, false
}
