// Package stats parses postfix and rspamd logs into time-series/summary data
// for the stats commands (inbound, outbound, spam, per-domain).
//
// Log lines are fetched through internal/sys (no shell, context timeout) using
// journalctl in a syslog-style ("short-iso") output so each line carries a
// timestamp and the postfix/rspamd program tag. All line interpretation lives
// in pure, host-independent helpers (see parse.go) so it is unit-testable
// without journalctl or a running mail server.
package stats

import (
	"context"
	"fmt"
	"strings"

	"mailadmin/internal/sys"
)

const binJournalctl = "/usr/bin/journalctl"

// defaultWindow is how far back the collector reads logs by default. journalctl
// accepts this relative form directly in --since.
const defaultWindow = "7 days ago"

// topRecipients caps how many recipient rows the per-domain view keeps.
const topRecipients = 10

// Point is one (label, value) sample in a series.
type Point struct {
	Label string `json:"label"`
	Value int64  `json:"value"`
}

// Series is a named sequence of points.
type Series struct {
	Name   string  `json:"name"`
	Points []Point `json:"points"`
}

// Summary aggregates message counts for a stats view.
type Summary struct {
	Kind     string   `json:"kind"` // inbound|outbound|spam|domain
	Accepted int64    `json:"accepted"`
	Rejected int64    `json:"rejected"`
	Deferred int64    `json:"deferred"`
	Spam     int64    `json:"spam"`
	Series   []Series `json:"series,omitempty"`
}

// BounceEntry is one bounced delivery, parsed from the Postfix log
// (`queue bounces`). It is a read-only diagnostic view — there is nothing to
// act on here; the message was already returned to its sender.
type BounceEntry struct {
	Timestamp string `json:"timestamp"`
	QueueID   string `json:"queue_id,omitempty"`
	Recipient string `json:"recipient"`
	DSN       string `json:"dsn,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// QuarantineEntry is one reject/soft-reject/greylist verdict, parsed from the
// rspamd log (`security quarantine list`). rspamd does not store the message
// anywhere in this setup — this is a log-derived diagnostic view, not a
// message store: there is nothing to release, since a rejected message was
// never accepted onto disk. From/To/Subject are best-effort: they are only
// populated when rspamd's configured log_format happens to include them.
type QuarantineEntry struct {
	Timestamp string `json:"timestamp"`
	MessageID string `json:"message_id,omitempty"`
	QueueID   string `json:"queue_id,omitempty"`
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
	Subject   string `json:"subject,omitempty"`
	Score     string `json:"score,omitempty"`
	Action    string `json:"action"`
}

// Collector parses logs into stats.
type Collector struct {
	runner *sys.Runner
	units  []string
	// window is the journalctl --since value; overridable in tests.
	window string
}

// New builds a Collector reading the given journalctl units.
func New(runner *sys.Runner, units []string) *Collector {
	return &Collector{runner: runner, units: units, window: defaultWindow}
}

// Inbound returns inbound-message stats: messages accepted for local delivery
// versus rejected/deferred, with an accepted-per-day series.
func (c *Collector) Inbound(ctx context.Context) (Summary, error) {
	events, err := c.postfixEvents(ctx)
	if err != nil {
		return Summary{}, err
	}
	return summarizeInbound(events), nil
}

// Outbound returns outbound-message stats: messages this host relayed out
// (status=sent to a remote relay) versus bounced/deferred.
func (c *Collector) Outbound(ctx context.Context) (Summary, error) {
	events, err := c.postfixEvents(ctx)
	if err != nil {
		return Summary{}, err
	}
	return summarizeOutbound(events), nil
}

// Spam returns rspamd action stats (no action/greylist/add header/rewrite
// subject/soft reject/reject), counting reject+soft-reject as spam.
func (c *Collector) Spam(ctx context.Context) (Summary, error) {
	lines, err := c.readUnit(ctx, rspamdUnit(c.units))
	if err != nil {
		return Summary{}, err
	}
	return summarizeSpam(parseRspamd(lines)), nil
}

// Domain returns per-domain delivery stats for domain (matched on the
// recipient's domain), including a top-recipients series.
func (c *Collector) Domain(ctx context.Context, domain string) (Summary, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return Summary{}, fmt.Errorf("stats.Domain: %w: empty domain", errInvalid)
	}
	events, err := c.postfixEvents(ctx)
	if err != nil {
		return Summary{}, err
	}
	return summarizeDomain(events, domain, topRecipients), nil
}

// Bounces returns every bounced delivery from the Postfix log within since
// (e.g. "2h", "3d"; empty uses the default 7-day window). Read-only: this
// reports what already happened, nothing here is actionable.
func (c *Collector) Bounces(ctx context.Context, since string) ([]BounceEntry, error) {
	window, err := windowFromDuration(since)
	if err != nil {
		return nil, err
	}
	lines, err := c.readUnitWindow(ctx, postfixUnit(c.units), window)
	if err != nil {
		return nil, err
	}
	parsed := parseBounces(lines)
	out := make([]BounceEntry, 0, len(parsed))
	for _, b := range parsed {
		out = append(out, BounceEntry{
			Timestamp: b.Timestamp,
			QueueID:   b.QueueID,
			Recipient: b.Recipient,
			DSN:       b.DSN,
			Reason:    b.Reason,
		})
	}
	return out, nil
}

// Quarantine returns every reject/soft-reject/greylist verdict from the
// rspamd log within since (e.g. "2h", "3d"; empty uses the default 7-day
// window). This is a log-derived diagnostic view, not a message store: rspamd
// has no built-in quarantine here, so there is nothing to release.
func (c *Collector) Quarantine(ctx context.Context, since string) ([]QuarantineEntry, error) {
	window, err := windowFromDuration(since)
	if err != nil {
		return nil, err
	}
	lines, err := c.readUnitWindow(ctx, rspamdUnit(c.units), window)
	if err != nil {
		return nil, err
	}
	verdicts := parseRspamdVerdicts(lines)
	out := make([]QuarantineEntry, 0, len(verdicts))
	for _, v := range verdicts {
		if !quarantineActions[v.Action] {
			continue
		}
		out = append(out, QuarantineEntry{
			Timestamp: v.Timestamp,
			MessageID: v.MessageID,
			QueueID:   v.QueueID,
			From:      v.From,
			To:        v.To,
			Subject:   v.Subject,
			Score:     v.Score,
			Action:    v.Action,
		})
	}
	return out, nil
}

// postfixEvents fetches and parses postfix delivery/reject lines across the
// configured postfix units.
func (c *Collector) postfixEvents(ctx context.Context) ([]postfixEvent, error) {
	lines, err := c.readUnit(ctx, postfixUnit(c.units))
	if err != nil {
		return nil, err
	}
	return parsePostfix(lines), nil
}

// readUnit runs journalctl for one unit over the Collector's default window
// and returns its raw lines.
func (c *Collector) readUnit(ctx context.Context, unit string) ([]string, error) {
	window := c.window
	if window == "" {
		window = defaultWindow
	}
	return c.readUnitWindow(ctx, unit, window)
}

// readUnitWindow runs journalctl for one unit over an explicit --since window
// and returns its raw lines. argv is a fixed slice (no shell); window and unit
// are the only variable parts, and unit comes from our own configured
// allowlist (postfixUnit/rspamdUnit).
func (c *Collector) readUnitWindow(ctx context.Context, unit, window string) ([]string, error) {
	argv := []string{
		binJournalctl,
		"--unit=" + unit,
		"--since=" + window,
		"--output=short-iso",
		"--no-pager",
	}
	out, err := c.runner.Output(ctx, argv...)
	if err != nil {
		return nil, fmt.Errorf("stats: journalctl %s: %w", unit, err)
	}
	return splitLines(out), nil
}

// postfixUnit picks the postfix unit from the configured list, defaulting to the
// conventional service name when absent.
func postfixUnit(units []string) string { return pickUnit(units, "postfix") }

// rspamdUnit picks the rspamd unit from the configured list.
func rspamdUnit(units []string) string { return pickUnit(units, "rspamd") }

// pickUnit returns the configured unit whose base name matches want (so both
// "postfix" and "postfix.service" resolve), else want as a bare unit.
func pickUnit(units []string, want string) string {
	for _, u := range units {
		if strings.EqualFold(unitBase(u), want) {
			return u
		}
	}
	return want
}

// unitBase strips a trailing ".service" (or other type suffix) from a unit name.
func unitBase(u string) string {
	if i := strings.LastIndexByte(u, '.'); i > 0 {
		return u[:i]
	}
	return u
}
