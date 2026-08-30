package sieve

import (
	"fmt"
	"strings"
	"time"

	"mailadmin/internal/valid"
)

// dateLayout is the accepted form for --start/--end: a bare calendar date, as
// used by Sieve's "date" extension currentdate comparisons.
const dateLayout = "2006-01-02"

// maxVacationDays bounds the :days reply-interval tag (RFC 5230 requires an
// implementation minimum of 1; we bound the top end to something sane for an
// operator-supplied value reaching a generated script).
const maxVacationDays = 365

// VacationOptions configures a generated vacation autoresponder script.
type VacationOptions struct {
	// Start and End are optional "YYYY-MM-DD" bounds. Both must be given
	// together (or both omitted for an always-on responder); End must be
	// strictly after Start.
	Start, End string
	// Subject is optional; when empty, the :subject tag is omitted and the
	// Sieve implementation's default subject applies.
	Subject string
	// Message is the reply body. Required.
	Message string
	// Days is the :days reply-interval (minimum time between repeat replies
	// to the same sender). 0 defaults to 7.
	Days int
}

// GenerateVacation renders an RFC 5230 vacation Sieve script from opts. With
// Start/End set, the vacation action is wrapped in a date-bounded
// `if currentdate ...` guard (requiring the "date" and "relational"
// extensions in addition to "vacation"); without them it generates an
// always-on vacation block.
func GenerateVacation(opts VacationOptions) (string, error) {
	msg := strings.TrimSpace(opts.Message)
	if msg == "" {
		return "", fmt.Errorf("%w: vacation message must not be empty", valid.ErrInvalid)
	}
	days := opts.Days
	if days <= 0 {
		days = 7
	}
	if days > maxVacationDays {
		return "", fmt.Errorf("%w: --days must be <= %d, got %d", valid.ErrInvalid, maxVacationDays, days)
	}
	subject := strings.TrimSpace(opts.Subject)

	start := strings.TrimSpace(opts.Start)
	end := strings.TrimSpace(opts.End)
	windowed := start != "" || end != ""

	var b strings.Builder
	if !windowed {
		b.WriteString("require [\"vacation\"];\n\n")
		writeVacationAction(&b, "", days, subject, msg)
		return b.String(), nil
	}

	if start == "" || end == "" {
		return "", fmt.Errorf("%w: --start and --end must be given together", valid.ErrInvalid)
	}
	startT, err := time.Parse(dateLayout, start)
	if err != nil {
		return "", fmt.Errorf("%w: --start: %w", valid.ErrInvalid, err)
	}
	endT, err := time.Parse(dateLayout, end)
	if err != nil {
		return "", fmt.Errorf("%w: --end: %w", valid.ErrInvalid, err)
	}
	if !endT.After(startT) {
		return "", fmt.Errorf("%w: --end must be after --start", valid.ErrInvalid)
	}

	b.WriteString("require [\"vacation\", \"date\", \"relational\"];\n\n")
	fmt.Fprintf(&b, "if allof(currentdate :value \"ge\" \"date\" \"%s\",\n", start)
	fmt.Fprintf(&b, "         currentdate :value \"le\" \"date\" \"%s\")\n", end)
	b.WriteString("{\n")
	writeVacationAction(&b, "    ", days, subject, msg)
	b.WriteString("}\n")
	return b.String(), nil
}

// writeVacationAction appends one `vacation ... ;` action to b, indented by
// indent. The reply body is emitted as a Sieve multi-line ("text:") literal so
// arbitrary message text (newlines, quotes) needs no escaping — only the
// dot-stuffing RFC 5228 §2.4.2 requires for a line that would otherwise be
// mistaken for the terminator. The multi-line literal's content lines and
// terminating "." are never indented: Sieve matches the terminator line
// exactly, and indentation would otherwise become part of the message text.
func writeVacationAction(b *strings.Builder, indent string, days int, subject, msg string) {
	fmt.Fprintf(b, "%svacation\n", indent)
	fmt.Fprintf(b, "%s    :days %d\n", indent, days)
	if subject != "" {
		fmt.Fprintf(b, "%s    :subject %s\n", indent, quoteSieveString(subject))
	}
	fmt.Fprintf(b, "%s    text:\n", indent)
	for _, line := range strings.Split(msg, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, ".") {
			line = "." + line
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString(".\n")
	fmt.Fprintf(b, "%s;\n", indent)
}

// quoteSieveString renders s as a Sieve quoted-string literal, escaping the
// two characters RFC 5228 §2.4.1 requires (backslash and double quote).
func quoteSieveString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// disabledScript is the no-op script vacation-off installs. mailadmin only
// tracks one managed script per mailbox (see managedName) and does not keep a
// history of prior script bodies, so disabling overwrites in place rather
// than restoring a previous version — `sieve set` from a saved file remains
// the way to reinstate a specific prior script.
const disabledScript = "# vacation disabled by `mailadmin sieve vacation-off`\nkeep;\n"

// GenerateDisabled returns the minimal passthrough script vacation-off
// installs in place of an active vacation autoresponder.
func GenerateDisabled() string {
	return disabledScript
}
