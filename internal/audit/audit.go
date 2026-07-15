// Package audit records every mutation to the append-only audit_log by wrapping
// db.Log. It captures actor/action/target and optional before/after snapshots,
// but never secret values.
//
// This is a console-only CLI running as a unix user (typically root or the
// mailadmin service account), so there is no network peer: the IP and
// user-agent fields that db.Log accepts are always empty for CLI-originated
// entries. The actor is the invoking unix user, resolved from the effective
// uid.
package audit

import (
	"context"
	"errors"
	"fmt"
	"os/user"
	"strconv"
	"strings"
)

// Logger is the minimal db surface audit needs (satisfied by *db.DB).
type Logger interface {
	Log(ctx context.Context, actor, action, target string, before, after any, ip, ua string) error
}

// ErrNoLogger is returned when a Recorder is built without a backing Logger.
var ErrNoLogger = errors.New("audit: nil logger")

// Recorder writes audit entries for CLI mutations.
type Recorder struct {
	log   Logger
	actor string
}

// New builds a Recorder. actor is the invoking unix user (see CurrentActor).
// A nil log is permitted here so callers can wire the Recorder eagerly; Record
// reports ErrNoLogger at call time instead.
func New(log Logger, actor string) *Recorder {
	return &Recorder{log: log, actor: sanitizeActor(actor)}
}

// Record appends one audit entry describing a single mutation. action names the
// operation (e.g. "domain.add"), target identifies the object it acted on
// (e.g. "example.com"), and before/after are optional JSON-serialisable
// snapshots — pass nil where a side is not meaningful (before for a create,
// after for a delete).
//
// Callers must never place secret values (passwords, hashes, tokens) in
// before/after; those are redacted at the source, not here.
//
// The ip and user-agent columns are always empty for console entries.
func (r *Recorder) Record(ctx context.Context, action, target string, before, after any) error {
	if r == nil || r.log == nil {
		return ErrNoLogger
	}
	action = strings.TrimSpace(action)
	if action == "" {
		return fmt.Errorf("audit.Record: %w: empty action", errInvalid)
	}
	target = strings.TrimSpace(target)
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("audit.Record: %w", err)
	}
	if err := r.log.Log(ctx, r.actor, action, target, before, after, "", ""); err != nil {
		return fmt.Errorf("audit.Record %q %q: %w", action, target, err)
	}
	return nil
}

// Actor returns the actor this Recorder attributes entries to.
func (r *Recorder) Actor() string {
	if r == nil {
		return unknownActor
	}
	return r.actor
}

var errInvalid = errors.New("invalid audit entry")

const unknownActor = "unknown"

// CurrentActor resolves the invoking unix user for audit attribution. It looks
// up the effective uid's account name and falls back to "uid:<n>" when the
// name cannot be resolved (e.g. no /etc/passwd entry, cgo-less lookup), so an
// audit entry is always attributable to a concrete uid.
func CurrentActor() string {
	uid, name := currentUID, currentUsername
	if name != "" {
		return name
	}
	return "uid:" + strconv.Itoa(uid)
}

// resolved once at package init; uid/name lookup does not change within a run.
var (
	currentUID      = lookupUID()
	currentUsername = lookupUsername(currentUID)
)

func lookupUID() int {
	u, err := user.Current()
	if err == nil {
		if n, convErr := strconv.Atoi(u.Uid); convErr == nil {
			return n
		}
	}
	return -1
}

func lookupUsername(uid int) string {
	// Prefer the current-user lookup: it carries the name directly.
	if u, err := user.Current(); err == nil {
		if n := sanitizeActor(u.Username); n != "" {
			return n
		}
	}
	if uid >= 0 {
		if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
			return sanitizeActor(u.Username)
		}
	}
	return ""
}

// sanitizeActor trims whitespace and rejects control characters so the actor
// string cannot smuggle newlines or terminal escapes into logs or the DB.
func sanitizeActor(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return s
}
