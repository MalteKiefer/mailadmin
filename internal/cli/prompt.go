package cli

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// ErrPasswordMismatch is returned when the two password entries differ.
var ErrPasswordMismatch = errors.New("passwords do not match")

// ErrEmptyPassword is returned when an empty password is entered.
var ErrEmptyPassword = errors.New("empty password")

// readPassword prompts for a password twice (no echo when stdin is a terminal)
// and returns it only if both entries match and are non-empty. When stdin is not
// a terminal (piped/tested), a single line is read without the confirmation
// prompt so the command stays scriptable. The plaintext is never logged.
func (a *App) readPassword(prompt string) (string, error) {
	if f, ok := a.stdin().(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		_, _ = fmt.Fprintf(a.stderr(), "%s: ", prompt)
		p1, err := term.ReadPassword(int(f.Fd()))
		_, _ = fmt.Fprintln(a.stderr())
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		_, _ = fmt.Fprintf(a.stderr(), "%s (again): ", prompt)
		p2, err := term.ReadPassword(int(f.Fd()))
		_, _ = fmt.Fprintln(a.stderr())
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		s1, s2 := string(p1), string(p2)
		if s1 == "" {
			return "", ErrEmptyPassword
		}
		if s1 != s2 {
			return "", ErrPasswordMismatch
		}
		return s1, nil
	}

	sc := bufio.NewScanner(a.stdin())
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		return "", ErrEmptyPassword
	}
	line := strings.TrimRight(sc.Text(), "\r\n")
	if line == "" {
		return "", ErrEmptyPassword
	}
	return line, nil
}

// interactive reports whether stdin is a real terminal, so commands can offer
// interactive prompts (select/confirm) only when a human is present.
func (a *App) interactive() bool {
	f, ok := a.stdin().(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// readLine reads one line from stdin. On a terminal it uses raw mode so that
// Esc and Ctrl+C abort immediately (returning ErrDeclined) — matching the
// user's expectation that either key cancels a prompt — while Enter submits and
// Backspace edits. Off a terminal (scripts/tests) it falls back to a plain
// buffered line read.
func (a *App) readLine(prompt string) (string, error) {
	_, _ = fmt.Fprint(a.stderr(), prompt)
	f, ok := a.stdin().(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		sc := bufio.NewScanner(a.stdin())
		if !sc.Scan() {
			return "", ErrDeclined
		}
		return strings.TrimSpace(sc.Text()), sc.Err()
	}

	old, err := term.MakeRaw(int(f.Fd()))
	if err != nil {
		return "", fmt.Errorf("read line: %w", err)
	}
	defer func() { _ = term.Restore(int(f.Fd()), old) }()

	var buf []rune
	one := make([]byte, 1)
	for {
		if _, err := f.Read(one); err != nil {
			return "", ErrDeclined
		}
		switch b := one[0]; b {
		case 0x03, 0x1b: // Ctrl+C, Esc → cancel
			_, _ = fmt.Fprint(a.stderr(), "\r\n")
			return "", ErrDeclined
		case '\r', '\n': // submit
			_, _ = fmt.Fprint(a.stderr(), "\r\n")
			return strings.TrimSpace(string(buf)), nil
		case 0x7f, 0x08: // backspace
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				_, _ = fmt.Fprint(a.stderr(), "\b \b")
			}
		default:
			if b >= 0x20 && b < 0x7f { // printable ASCII
				buf = append(buf, rune(b))
				_, _ = fmt.Fprintf(a.stderr(), "%c", b)
			}
		}
	}
}

// selectIndices shows a numbered list and reads a selection: comma/space
// separated 1-based indices (e.g. "1,3 5"), "all", or empty for none. Returned
// indices are 0-based, sorted, de-duplicated, and range-checked.
func (a *App) selectIndices(prompt string, items []string) ([]int, error) {
	for i, it := range items {
		_, _ = fmt.Fprintf(a.stderr(), "  %2d) %s\n", i+1, it)
	}
	line, err := a.readLine(fmt.Sprintf("%s [numbers / all / none]: ", prompt))
	if err != nil {
		return nil, err
	}
	if line == "" || strings.EqualFold(line, "none") {
		return nil, nil
	}
	if strings.EqualFold(line, "all") {
		out := make([]int, len(items))
		for i := range items {
			out[i] = i
		}
		return out, nil
	}
	seen := make(map[int]struct{})
	var out []int
	for _, tok := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' }) {
		n, err := strconv.Atoi(tok)
		if err != nil || n < 1 || n > len(items) {
			return nil, fmt.Errorf("%w: invalid selection %q", ErrUsage, tok)
		}
		if _, dup := seen[n-1]; dup {
			continue
		}
		seen[n-1] = struct{}{}
		out = append(out, n-1)
	}
	sort.Ints(out)
	return out, nil
}

// generatePassword returns a cryptographically-random alphanumeric string of
// length n, used for application passwords (shown once, then only stored
// hashed).
func generatePassword(n int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// Rejection sampling keeps the distribution uniform: draw fresh random bytes
	// and discard any byte in the biased tail above the largest multiple of the
	// alphabet length that fits in a byte.
	const max = 256 - (256 % len(alphabet))
	out := make([]byte, 0, n)
	buf := make([]byte, n)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("generate password: %w", err)
		}
		for _, b := range buf {
			if int(b) < max {
				out = append(out, alphabet[int(b)%len(alphabet)])
				if len(out) == n {
					break
				}
			}
		}
	}
	return string(out), nil
}
