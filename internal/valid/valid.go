// Package valid centralises validation/normalisation of every external token
// that reaches an exec argv, a DNS query, or a SQL parameter. Injection defence
// per REQUIREMENTS: local-part, domain, address, queue-id, IP, port, systemd
// unit and DKIM selector are all validated here so no ad-hoc regexps drift.
package valid

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	// ErrInvalid is the sentinel wrapped by every validator.
	ErrInvalid = errors.New("invalid input")

	reDomain   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	reLocal    = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,63}$`)
	reQueueID  = regexp.MustCompile(`^[A-F0-9]{6,16}$`)
	reSelector = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	reUnit     = regexp.MustCompile(`^[a-zA-Z0-9@._-]{1,128}$`)
	reDuration = regexp.MustCompile(`^[0-9]{1,8}(s|m|h|d)$`)
)

func fail(what, v string) error { return fmt.Errorf("%w: %s %q", ErrInvalid, what, v) }

// Domain lower-cases and validates a DNS domain name.
func Domain(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
	if !reDomain.MatchString(s) {
		return "", fail("domain", s)
	}
	return s, nil
}

// Address validates a mailbox address and returns (local, domain).
func Address(s string) (local, domain string, err error) {
	s = strings.ToLower(strings.TrimSpace(s))
	parts := strings.Split(s, "@")
	if len(parts) != 2 || !reLocal.MatchString(parts[0]) {
		return "", "", fail("address", s)
	}
	d, err := Domain(parts[1])
	if err != nil {
		return "", "", fail("address", s)
	}
	return parts[0], d, nil
}

// AliasSource validates an alias source: a full address or "@domain" catch-all.
func AliasSource(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(s, "@") {
		d, err := Domain(s[1:])
		if err != nil {
			return "", fail("alias source", s)
		}
		return "@" + d, nil
	}
	if _, _, err := Address(s); err != nil {
		return "", fail("alias source", s)
	}
	return s, nil
}

// QueueID validates a Postfix queue id.
func QueueID(s string) (string, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !reQueueID.MatchString(s) {
		return "", fail("queue id", s)
	}
	return s, nil
}

// Selector validates a DKIM selector.
func Selector(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !reSelector.MatchString(s) {
		return "", fail("selector", s)
	}
	return s, nil
}

// Unit validates a systemd unit name (allowlist enforcement is the caller's job).
func Unit(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !reUnit.MatchString(s) {
		return "", fail("unit", s)
	}
	return s, nil
}

// CIDR validates a bare IP or CIDR (for ban/allowlist entries).
func CIDR(s string) (string, error) {
	s = strings.TrimSpace(s)
	if net.ParseIP(s) != nil {
		return s, nil
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return s, nil
	}
	return "", fail("ip/cidr", s)
}

// Port validates a TCP/UDP port (1-65535).
func Port(n int) (int, error) {
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("%w: port %d", ErrInvalid, n)
	}
	return n, nil
}

// Proto validates a firewall protocol ("tcp"|"udp").
func Proto(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s != "tcp" && s != "udp" {
		return "", fail("proto", s)
	}
	return s, nil
}

// Duration validates a ban duration like "4h" or "30m".
func Duration(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !reDuration.MatchString(s) {
		return "", fail("duration", s)
	}
	return s, nil
}
