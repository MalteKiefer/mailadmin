// Package quota reads mailbox quota usage via doveadm quota through
// internal/sys. Addresses are validated before use.
package quota

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"mailadmin/internal/sys"
	"mailadmin/internal/valid"
)

const binDoveadm = "/usr/bin/doveadm"

// ErrParse is returned when doveadm quota output cannot be parsed.
var ErrParse = errors.New("quota: unparseable doveadm output")

// Usage is a mailbox's storage quota usage.
type Usage struct {
	Address    string `json:"address"`
	UsedBytes  int64  `json:"used_bytes"`
	LimitBytes int64  `json:"limit_bytes"`
	UsedPct    int    `json:"used_pct"`
}

// Service runs doveadm quota.
type Service struct {
	runner *sys.Runner
}

// New builds a Service.
func New(runner *sys.Runner) *Service { return &Service{runner: runner} }

// Get returns storage quota usage for the mailbox address.
//
// It runs `doveadm -f flat quota get -u <address>` through the privileged-exec
// chokepoint (argv slice, context timeout, capped output) and parses the
// STORAGE row. A missing/unlimited limit ("-") is reported as LimitBytes 0 and
// UsedPct 0.
func (s *Service) Get(ctx context.Context, address string) (Usage, error) {
	addr, err := normalizeAddress(address)
	if err != nil {
		return Usage{}, err
	}

	res, err := s.runner.Run(ctx, nil,
		binDoveadm, "-f", "flat", "quota", "get", "-u", addr)
	if err != nil {
		return Usage{}, fmt.Errorf("quota.Get: run doveadm: %w", err)
	}
	if res.ExitCode != 0 {
		return Usage{}, fmt.Errorf("quota.Get: doveadm exit %d: %s",
			res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}

	used, limit, err := parseStorage(res.Stdout)
	if err != nil {
		return Usage{}, fmt.Errorf("quota.Get: %w", err)
	}

	return Usage{
		Address:    addr,
		UsedBytes:  used,
		LimitBytes: limit,
		UsedPct:    percent(used, limit),
	}, nil
}

// normalizeAddress validates and canonicalises a mailbox address before it is
// placed in an exec argv.
func normalizeAddress(address string) (string, error) {
	local, domain, err := valid.Address(address)
	if err != nil {
		return "", fmt.Errorf("quota.Get: %w", err)
	}
	return local + "@" + domain, nil
}

// parseStorage extracts the STORAGE row's (value, limit) from doveadm's flat
// quota output. Each data line's last three whitespace-separated fields are
// Type, Value, Limit; the leading "Quota name" column may contain spaces, so
// fields are counted from the right. A "-" or empty limit means unlimited and
// is reported as 0.
//
// Example (`doveadm -f flat quota get -u u@d`):
//
//	Quota name Type    Value Limit %
//	User quota STORAGE 12345 102400 12
//	User quota MESSAGE 42    -      0
func parseStorage(out []byte) (used, limit int64, err error) {
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		typ, valStr, limStr, ok := lastThree(line)
		if !ok || !strings.EqualFold(typ, "STORAGE") {
			continue
		}
		used, err = strconv.ParseInt(valStr, 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("%w: value %q", ErrParse, valStr)
		}
		limit, err = parseLimit(limStr)
		if err != nil {
			return 0, 0, fmt.Errorf("%w: limit %q", ErrParse, limStr)
		}
		return used, limit, nil
	}
	return 0, 0, fmt.Errorf("%w: no STORAGE row", ErrParse)
}

// lastThree returns the Type, Value and Limit fields (the trailing three
// columns) of a doveadm data line, skipping the header row. Some doveadm builds
// append a trailing "%" column; when the third-from-last field is not the
// expected Type token, it retries one column to the left.
func lastThree(line string) (typ, val, lim string, ok bool) {
	f := strings.Fields(line)
	n := len(f)
	if n < 3 {
		return "", "", "", false
	}
	typ, val, lim = f[n-3], f[n-2], f[n-1]
	if strings.EqualFold(typ, "Type") {
		return "", "", "", false
	}
	if !isQuotaType(typ) && n >= 4 {
		typ, val, lim = f[n-4], f[n-3], f[n-2]
	}
	return typ, val, lim, isQuotaType(typ)
}

// isQuotaType reports whether typ names a doveadm quota resource row.
func isQuotaType(typ string) bool {
	return strings.EqualFold(typ, "STORAGE") || strings.EqualFold(typ, "MESSAGE")
}

// parseLimit parses a doveadm limit field. "-" or empty means unlimited (0).
func parseLimit(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return 0, nil
	}
	return strconv.ParseInt(s, 10, 64)
}

// percent returns used/limit as a 0-100 integer, clamped. An unlimited or
// zero limit yields 0.
func percent(used, limit int64) int {
	if limit <= 0 || used <= 0 {
		return 0
	}
	p := used * 100 / limit
	if p > 100 {
		return 100
	}
	return int(p)
}
