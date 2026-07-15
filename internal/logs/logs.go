// Package logs reads unit logs via journalctl (and Caddy access logs) through
// internal/sys, restricted to the configured unit allowlist.
//
// journalctl is invoked with structured JSON output (--output=json), and every
// entry is parsed from its __REALTIME_TIMESTAMP (microseconds since the Unix
// epoch) and MESSAGE fields. The unit is always constrained to the caller-
// configured allowlist before it reaches the command line: a wildcard or
// operator-supplied unit can never be passed to journalctl.
//
// Show buffers a bounded number of lines through sys.Runner. Tail follows the
// journal (journalctl --follow) and therefore cannot use the buffered Runner
// API; it streams argv-only (never "sh -c"), from an absolute binary path, and
// stops the moment ctx is cancelled — matching the same no-shell, allowlist,
// context-timeout guarantees as the rest of the tool.
package logs

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"mailadmin/internal/sys"
	"mailadmin/internal/valid"
)

const binJournalctl = "/usr/bin/journalctl"

// maxLines caps the number of lines Show will request, guarding against
// pathological -n values.
const maxLines = 100_000

// tailBuffer bounds the Tail channel so a slow consumer applies backpressure
// rather than growing memory without limit.
const tailBuffer = 256

// ErrNotAllowed is returned when a unit is not on the configured allowlist.
var ErrNotAllowed = errors.New("logs: unit not allowed")

// Line is one log line.
type Line struct {
	Timestamp string `json:"timestamp"`
	Unit      string `json:"unit"`
	Message   string `json:"message"`
}

// Reader fetches logs for allowlisted units.
type Reader struct {
	runner  *sys.Runner
	allowed map[string]struct{}
}

// New builds a Reader allowing only the named units. Each name is validated and
// normalized via valid.Unit before it enters the allowlist; malformed names are
// dropped so they can never reach the command line (matching internal/services).
func New(runner *sys.Runner, allowedUnits []string) *Reader {
	set := make(map[string]struct{}, len(allowedUnits))
	for _, u := range allowedUnits {
		name, err := valid.Unit(u)
		if err != nil {
			continue
		}
		set[name] = struct{}{}
	}
	return &Reader{runner: runner, allowed: set}
}

// Allowed reports whether unit is in the allowlist.
func (r *Reader) Allowed(unit string) bool {
	_, ok := r.allowed[strings.TrimSpace(unit)]
	return ok
}

// Show returns the last n log lines for an allowlisted unit. n is clamped to
// the range [1, maxLines].
func (r *Reader) Show(ctx context.Context, unit string, n int) ([]Line, error) {
	if !r.Allowed(unit) {
		return nil, fmt.Errorf("%w: %q", ErrNotAllowed, unit)
	}
	if n < 1 {
		n = 1
	}
	if n > maxLines {
		n = maxLines
	}

	argv := []string{
		binJournalctl,
		"--no-pager",
		"--output=json",
		"--unit", unit,
		"--lines", strconv.Itoa(n),
	}

	out, err := r.runner.Output(ctx, argv...)
	if err != nil {
		return nil, fmt.Errorf("logs: journalctl show %q: %w", unit, err)
	}

	lines, err := parseLines(strings.NewReader(out), unit)
	if err != nil {
		return nil, fmt.Errorf("logs: parse journalctl output: %w", err)
	}
	return lines, nil
}

// Tail streams new log lines for an allowlisted unit until ctx is cancelled,
// sending each to the returned channel. The channel is closed when ctx ends or
// journalctl exits. journalctl --follow produces an unbounded stream, which the
// buffered sys.Runner cannot represent, so Tail streams stdout directly; it
// still uses an argv slice (no shell), an absolute binary path, and honours ctx.
func (r *Reader) Tail(ctx context.Context, unit string) (<-chan Line, error) {
	if !r.Allowed(unit) {
		return nil, fmt.Errorf("%w: %q", ErrNotAllowed, unit)
	}

	// #nosec G204 -- binJournalctl is a fixed absolute const; unit is
	// allowlist-gated above; no shell is involved (argv slice only).
	cmd := exec.CommandContext(ctx, binJournalctl,
		"--no-pager",
		"--output=json",
		"--follow",
		"--lines", "0",
		"--unit", unit,
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("logs: journalctl tail stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("logs: journalctl tail start: %w", err)
	}

	out := make(chan Line, tailBuffer)
	go func() {
		defer close(out)
		streamLines(ctx, stdout, unit, out)
		// Drain and reap the process; ctx cancellation kills it via
		// CommandContext, so Wait returns promptly.
		_ = cmd.Wait()
	}()

	return out, nil
}

// streamLines reads newline-delimited journalctl JSON from rd and forwards each
// decoded Line to out, stopping when ctx is cancelled or rd is exhausted.
func streamLines(ctx context.Context, rd io.Reader, unit string, out chan<- Line) {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if ctx.Err() != nil {
			return
		}
		line, ok := decodeLine(sc.Bytes(), unit)
		if !ok {
			continue
		}
		select {
		case out <- line:
		case <-ctx.Done():
			return
		}
	}
}

// parseLines decodes newline-delimited journalctl JSON records from rd.
func parseLines(rd io.Reader, unit string) ([]Line, error) {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var lines []Line
	for sc.Scan() {
		if line, ok := decodeLine(sc.Bytes(), unit); ok {
			lines = append(lines, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("logs: read journalctl output: %w", err)
	}
	return lines, nil
}

// journalEntry captures the journalctl JSON fields we need. journalctl encodes
// most fields as strings, but non-UTF-8 or binary payloads become a JSON array
// of byte values; jsonField normalises both forms.
type journalEntry struct {
	Realtime json.RawMessage `json:"__REALTIME_TIMESTAMP"`
	Unit     json.RawMessage `json:"_SYSTEMD_UNIT"`
	Message  json.RawMessage `json:"MESSAGE"`
}

// decodeLine parses one journalctl JSON record into a Line. It reports ok=false
// for blank lines or records it cannot parse, so a single malformed entry never
// aborts the whole read. fallbackUnit is used when the record omits
// _SYSTEMD_UNIT.
func decodeLine(raw []byte, fallbackUnit string) (Line, bool) {
	raw = trimSpace(raw)
	if len(raw) == 0 {
		return Line{}, false
	}
	var e journalEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return Line{}, false
	}

	unit := jsonField(e.Unit)
	if unit == "" {
		unit = fallbackUnit
	}

	return Line{
		Timestamp: formatRealtime(jsonField(e.Realtime)),
		Unit:      unit,
		Message:   jsonField(e.Message),
	}, true
}

// jsonField normalises a journalctl field, which is either a JSON string or a
// JSON array of byte values (for binary/non-UTF-8 data).
func jsonField(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var b []byte
	if err := json.Unmarshal(raw, &b); err == nil {
		return string(b)
	}
	return ""
}

// formatRealtime converts a __REALTIME_TIMESTAMP (microseconds since the Unix
// epoch, as a decimal string) to RFC3339 in UTC. Unparseable input is returned
// unchanged so operators still see the raw value.
func formatRealtime(us string) string {
	if us == "" {
		return ""
	}
	micros, err := strconv.ParseInt(us, 10, 64)
	if err != nil {
		return us
	}
	sec := micros / 1_000_000
	nsec := (micros % 1_000_000) * 1_000
	return time.Unix(sec, nsec).UTC().Format(time.RFC3339)
}

// trimSpace strips leading/trailing ASCII whitespace without allocating.
func trimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && isSpace(b[start]) {
		start++
	}
	end := len(b)
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
