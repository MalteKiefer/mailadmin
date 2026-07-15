package stats

import (
	"errors"
	"sort"
	"strings"
)

// errInvalid is returned for bad caller input (e.g. empty domain).
var errInvalid = errors.New("invalid input")

// postfixEvent is one parsed postfix delivery or reject line.
//
// Postfix logs delivery attempts with a syslog identifier like "postfix/smtp"
// (outbound relay), "postfix/lmtp" or "postfix/local" (inbound local delivery),
// "postfix/smtpd" (reject at receive time) and "postfix/qmgr" (expiry). The
// message body carries "status=<x>", "to=<addr>" and "relay=<host>[...]" fields.
type postfixEvent struct {
	Day    string // YYYY-MM-DD bucket from the log timestamp
	Prog   string // postfix subprogram, e.g. "smtp", "smtpd", "lmtp", "local"
	Status string // sent | bounced | deferred | expired | reject
	To     string // recipient address, lowercased (may be empty)
	ToDom  string // recipient domain, lowercased (may be empty)
	Local  bool   // delivery was to a local transport (lmtp/local/virtual)
}

// splitLines splits raw command output into non-empty trimmed lines.
func splitLines(s string) []string {
	raw := strings.Split(s, "\n")
	out := make([]string, 0, len(raw))
	for _, l := range raw {
		if l = strings.TrimRight(l, "\r"); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// splitSyslog splits a syslog-style ("short-iso") journalctl line into its
// leading ISO timestamp, the "ident[pid]:" program tag and the remaining
// message. It returns ok=false for lines that don't look like syslog.
//
// Example:
//
//	2026-07-14T10:00:00+0200 mail postfix/smtp[123]: ABC1: to=<a@b>, status=sent
func splitSyslog(line string) (ts, ident, msg string, ok bool) {
	// timestamp: first whitespace-delimited field.
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return "", "", "", false
	}
	ts = line[:sp]
	rest := strings.TrimLeft(line[sp+1:], " ")

	// host: next field, skipped.
	sp = strings.IndexByte(rest, ' ')
	if sp <= 0 {
		return "", "", "", false
	}
	rest = strings.TrimLeft(rest[sp+1:], " ")

	// ident[pid]: — up to the first ": ".
	colon := strings.Index(rest, ": ")
	if colon <= 0 {
		return "", "", "", false
	}
	tag := rest[:colon]
	msg = rest[colon+2:]

	// strip [pid] from the tag.
	if b := strings.IndexByte(tag, '['); b >= 0 {
		tag = tag[:b]
	}
	if tag == "" {
		return "", "", "", false
	}
	return ts, tag, msg, true
}

// dayOf extracts the YYYY-MM-DD prefix of an ISO-8601 timestamp.
func dayOf(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}

// parsePostfix turns raw journalctl lines into postfix events, keeping only
// lines that carry a delivery status (or a reject at receive time).
func parsePostfix(lines []string) []postfixEvent {
	events := make([]postfixEvent, 0, len(lines))
	for _, line := range lines {
		ts, ident, msg, ok := splitSyslog(line)
		if !ok {
			continue
		}
		prog, ok := postfixProg(ident)
		if !ok {
			continue
		}
		ev, ok := parsePostfixMsg(prog, msg)
		if !ok {
			continue
		}
		ev.Day = dayOf(ts)
		events = append(events, ev)
	}
	return events
}

// postfixProg returns the postfix subprogram name for a syslog identifier of
// the form "postfix/<prog>" or "postfix-<instance>/<prog>".
func postfixProg(ident string) (string, bool) {
	slash := strings.IndexByte(ident, '/')
	if slash < 0 {
		return "", false
	}
	head, prog := ident[:slash], ident[slash+1:]
	if head != "postfix" && !strings.HasPrefix(head, "postfix-") {
		return "", false
	}
	if prog == "" {
		return "", false
	}
	return prog, true
}

// parsePostfixMsg parses the body of a postfix log line for the given
// subprogram. It returns ok=false for lines without a status/reject we track.
func parsePostfixMsg(prog, msg string) (postfixEvent, bool) {
	// Reject at receive time: smtpd logs "NOQUEUE: reject: ...".
	if prog == "smtpd" {
		if strings.Contains(msg, ": reject: ") || strings.HasPrefix(msg, "reject: ") {
			return postfixEvent{Prog: prog, Status: "reject"}, true
		}
		return postfixEvent{}, false
	}

	status := fieldValue(msg, "status=")
	if status == "" {
		return postfixEvent{}, false
	}
	// status can be "sent (...)"; keep just the token.
	if sp := strings.IndexByte(status, ' '); sp >= 0 {
		status = status[:sp]
	}

	to := strings.ToLower(unbracket(fieldValue(msg, "to=")))
	relay := fieldValue(msg, "relay=")

	ev := postfixEvent{
		Prog:   prog,
		Status: status,
		To:     to,
		ToDom:  domainOf(to),
		Local:  isLocalDelivery(prog, relay),
	}
	return ev, true
}

// isLocalDelivery reports whether a delivery was to a local mailbox transport
// rather than relayed to a remote host.
func isLocalDelivery(prog, relay string) bool {
	switch prog {
	case "lmtp", "local", "virtual", "pipe":
		return true
	}
	// smtp deliveries to the loopback dovecot LMTP count as local too.
	switch {
	case strings.HasPrefix(relay, "127.0.0.1"),
		strings.HasPrefix(relay, "[127.0.0.1]"),
		strings.HasPrefix(relay, "local"),
		strings.HasPrefix(relay, "dovecot"):
		return true
	}
	return false
}

// fieldValue extracts the value following key (e.g. "status=") from a postfix
// message, stopping at the next comma or whitespace. It returns "" if absent.
func fieldValue(msg, key string) string {
	i := strings.Index(msg, key)
	if i < 0 {
		return ""
	}
	v := msg[i+len(key):]
	// value ends at ", " (postfix field separator) or end of string.
	if j := strings.Index(v, ", "); j >= 0 {
		v = v[:j]
	}
	return strings.TrimSpace(v)
}

// unbracket strips surrounding angle brackets from an address like "<a@b>".
func unbracket(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	return s
}

// domainOf returns the lowercased domain part of an email address, or "".
func domainOf(addr string) string {
	if at := strings.LastIndexByte(addr, '@'); at >= 0 && at < len(addr)-1 {
		return strings.ToLower(addr[at+1:])
	}
	return ""
}

// summarizeInbound aggregates inbound delivery outcomes and an accepted-per-day
// series. Accepted = messages delivered to a local transport; deferred/bounced
// counted separately; smtpd rejects counted as rejected.
func summarizeInbound(events []postfixEvent) Summary {
	s := Summary{Kind: "inbound"}
	perDay := map[string]int64{}
	for _, e := range events {
		switch {
		case e.Status == "reject":
			s.Rejected++
		case e.Local && e.Status == "sent":
			s.Accepted++
			perDay[e.Day]++
		case e.Local && e.Status == "bounced":
			s.Rejected++
		case e.Local && e.Status == "deferred":
			s.Deferred++
		}
	}
	s.Series = []Series{{Name: "accepted", Points: dailySeries(perDay)}}
	return s
}

// summarizeOutbound aggregates outbound relay outcomes and a sent-per-day
// series. Only non-local deliveries count as outbound.
func summarizeOutbound(events []postfixEvent) Summary {
	s := Summary{Kind: "outbound"}
	perDay := map[string]int64{}
	for _, e := range events {
		if e.Local || e.Prog == "smtpd" {
			continue
		}
		switch e.Status {
		case "sent":
			s.Accepted++
			perDay[e.Day]++
		case "bounced":
			s.Rejected++
		case "deferred":
			s.Deferred++
		case "expired":
			s.Rejected++
		}
	}
	s.Series = []Series{{Name: "sent", Points: dailySeries(perDay)}}
	return s
}

// summarizeDomain aggregates delivery outcomes for recipients in domain and a
// top-n recipients series (by accepted message count).
func summarizeDomain(events []postfixEvent, domain string, topN int) Summary {
	s := Summary{Kind: "domain"}
	perRcpt := map[string]int64{}
	for _, e := range events {
		if e.ToDom != domain {
			continue
		}
		switch e.Status {
		case "sent":
			s.Accepted++
			perRcpt[e.To]++
		case "bounced":
			s.Rejected++
		case "deferred":
			s.Deferred++
		case "expired":
			s.Rejected++
		}
	}
	s.Series = []Series{{Name: "top-recipients", Points: topPoints(perRcpt, topN)}}
	return s
}

// dailySeries turns a day→count map into points sorted chronologically by day.
func dailySeries(perDay map[string]int64) []Point {
	points := make([]Point, 0, len(perDay))
	for day, n := range perDay {
		points = append(points, Point{Label: day, Value: n})
	}
	sort.Slice(points, func(i, j int) bool { return points[i].Label < points[j].Label })
	return points
}

// topPoints returns the topN highest-value entries, sorted by value desc then
// label asc for deterministic output.
func topPoints(counts map[string]int64, topN int) []Point {
	points := make([]Point, 0, len(counts))
	for label, n := range counts {
		points = append(points, Point{Label: label, Value: n})
	}
	sort.Slice(points, func(i, j int) bool {
		if points[i].Value != points[j].Value {
			return points[i].Value > points[j].Value
		}
		return points[i].Label < points[j].Label
	})
	if topN > 0 && len(points) > topN {
		points = points[:topN]
	}
	return points
}

// --- rspamd ---

// rspamdAction is one parsed rspamd verdict.
type rspamdAction struct {
	Day    string
	Action string // no action | greylist | add header | rewrite subject | soft reject | reject
}

// rspamd action strings, as logged by rspamd's proxy/controller.
const (
	actNoAction  = "no action"
	actGreylist  = "greylist"
	actAddHeader = "add header"
	actRewrite   = "rewrite subject"
	actSoftRej   = "soft reject"
	actReject    = "reject"
)

var rspamdActions = []string{
	// order matters: longer/more-specific phrases first so "reject" does not
	// shadow "soft reject".
	actRewrite, actAddHeader, actSoftRej, actNoAction, actGreylist, actReject,
}

// parseRspamd extracts action verdicts from rspamd journal lines. rspamd logs a
// summary line per message containing e.g. 'F (reject): ...' or
// '(default: ... [score]): [no action]' depending on version; we match on the
// canonical action phrase after a '(...): ' or 'action=' marker.
func parseRspamd(lines []string) []rspamdAction {
	out := make([]rspamdAction, 0, len(lines))
	for _, line := range lines {
		ts, ident, msg, ok := splitSyslog(line)
		if !ok {
			// rspamd lines may arrive without a syslog tag depending on
			// output mode; fall back to scanning the whole line.
			ts, msg = "", line
		} else if !strings.HasPrefix(ident, "rspamd") {
			continue
		}
		act, ok := rspamdActionOf(msg)
		if !ok {
			continue
		}
		out = append(out, rspamdAction{Day: dayOf(ts), Action: act})
	}
	return out
}

// rspamdActionOf finds a known rspamd action phrase in a message. It looks for
// the explicit "action=" form first, then any bracketed/parenthesised verdict.
func rspamdActionOf(msg string) (string, bool) {
	lower := strings.ToLower(msg)
	if v := fieldValue(lower, "action="); v != "" {
		// take the action token (rspamd uses underscore forms like
		// "rewrite_subject"), stopping at the first space.
		if sp := strings.IndexByte(v, ' '); sp >= 0 {
			v = v[:sp]
		}
		v = strings.TrimSpace(strings.Trim(v, "\"'"))
		if a, ok := matchAction(v); ok {
			return a, true
		}
	}
	for _, a := range rspamdActions {
		if strings.Contains(lower, "("+a+")") ||
			strings.Contains(lower, "["+a+"]") ||
			strings.Contains(lower, ": "+a) {
			return a, true
		}
	}
	return "", false
}

// matchAction normalizes an action token (underscores or spaces) to a canonical
// rspamd action.
func matchAction(v string) (string, bool) {
	norm := strings.ReplaceAll(v, "_", " ")
	for _, a := range rspamdActions {
		if norm == a {
			return a, true
		}
	}
	return "", false
}

// summarizeSpam aggregates rspamd actions. Spam = reject + soft reject;
// Accepted = no action; the rest are grouped by action in the series.
func summarizeSpam(actions []rspamdAction) Summary {
	s := Summary{Kind: "spam"}
	perAction := map[string]int64{}
	for _, a := range actions {
		perAction[a.Action]++
		switch a.Action {
		case actNoAction:
			s.Accepted++
		case actReject, actSoftRej:
			s.Spam++
			s.Rejected++
		case actGreylist:
			s.Deferred++
		}
	}
	s.Series = []Series{{Name: "actions", Points: actionSeries(perAction)}}
	return s
}

// actionSeries emits one point per rspamd action in canonical order (only for
// actions that occurred).
func actionSeries(perAction map[string]int64) []Point {
	points := make([]Point, 0, len(perAction))
	for _, a := range rspamdActions {
		if n, ok := perAction[a]; ok {
			points = append(points, Point{Label: a, Value: n})
		}
	}
	return points
}
