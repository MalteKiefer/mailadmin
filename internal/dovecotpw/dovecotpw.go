// Package dovecotpw hashes mailbox passwords with argon2id via `doveadm pw`
// through internal/sys. The plaintext is passed only on stdin (never in argv)
// and is never logged.
package dovecotpw

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"mailadmin/internal/sys"
)

const binDoveadm = "/usr/bin/doveadm"

// Scheme is the password hashing scheme (locked to argon2id).
const Scheme = "ARGON2ID"

// maxPlaintext bounds the accepted password length. doveadm/argon2id have no
// hard upper bound, but an unbounded value only wastes work and memory; this is
// generously above any sane passphrase.
const maxPlaintext = 1024

// Errors returned by this package. Callers may match them with errors.Is; none
// of them ever embed the plaintext.
var (
	// ErrEmptyPassword is returned when the supplied plaintext is empty.
	ErrEmptyPassword = errors.New("dovecotpw: empty password")
	// ErrInvalidPassword is returned when the plaintext contains bytes that
	// cannot be safely delivered over the stdin prompt protocol (NUL or a
	// newline would desynchronise doveadm's two-prompt read).
	ErrInvalidPassword = errors.New("dovecotpw: password contains newline or NUL")
	// ErrTooLong is returned when the plaintext exceeds maxPlaintext bytes.
	ErrTooLong = errors.New("dovecotpw: password too long")
	// ErrNoHash is returned when doveadm exits successfully but produces no
	// usable hash, or output that is not a valid dovecot scheme string.
	ErrNoHash = errors.New("dovecotpw: no hash in doveadm output")
)

// Hasher produces argon2id hashes via doveadm.
type Hasher struct {
	runner *sys.Runner
}

// New builds a Hasher.
func New(runner *sys.Runner) *Hasher { return &Hasher{runner: runner} }

// Hash returns the argon2id hash of plaintext. The plaintext is written to
// doveadm's stdin (which prompts for it twice) and never appears in argv, the
// process table, logs, or any returned error. The context bounds the call.
func (h *Hasher) Hash(ctx context.Context, plaintext string) (string, error) {
	if err := validatePlaintext(plaintext); err != nil {
		return "", err
	}

	// doveadm pw prompts "Enter new password:" then "Retype new password:";
	// both reads consume one newline-terminated line from stdin.
	stdin := []byte(stdinPayload(plaintext))

	res, err := h.runner.Run(ctx, stdin, binDoveadm, "pw", "-s", Scheme)
	// Zero the stdin copy as soon as the child has consumed it.
	for i := range stdin {
		stdin[i] = 0
	}
	if err != nil {
		return "", fmt.Errorf("dovecotpw: doveadm pw: %w", err)
	}

	hash, perr := parseHash(string(res.Stdout))
	if perr != nil {
		return "", perr
	}
	return hash, nil
}

// validatePlaintext rejects passwords that are empty, too long, or that carry
// bytes which would corrupt the stdin prompt protocol.
func validatePlaintext(plaintext string) error {
	if plaintext == "" {
		return ErrEmptyPassword
	}
	if len(plaintext) > maxPlaintext {
		return ErrTooLong
	}
	if strings.ContainsAny(plaintext, "\n\r\x00") {
		return ErrInvalidPassword
	}
	return nil
}

// stdinPayload builds the two-line answer doveadm expects for its enter/retype
// prompts.
func stdinPayload(plaintext string) string {
	return plaintext + "\n" + plaintext + "\n"
}

// parseHash extracts the dovecot scheme string from doveadm's stdout. doveadm
// echoes only the hash on success; we defend against stray prompt text and
// require the argon2id marker so a malformed line never reaches the database.
func parseHash(stdout string) (string, error) {
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// doveadm may emit either a bare "$argon2id$..." string or, with
		// -r/other builds, a "{ARGON2ID}$argon2id$..." prefixed form. Accept
		// both, but require the argon2id modular-crypt marker.
		candidate := strings.TrimPrefix(line, "{"+Scheme+"}")
		if strings.HasPrefix(candidate, "$argon2id$") {
			return candidate, nil
		}
	}
	return "", ErrNoHash
}
