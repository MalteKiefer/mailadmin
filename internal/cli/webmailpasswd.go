package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"mailadmin/internal/dovecotpw"
	"mailadmin/internal/valid"
)

// errWrongPassword is returned when the current password does not match. It is
// a usage-class refusal so the webmail reports it as such.
var errWrongPassword = errors.New("current password does not match")

func newWebmailPasswdCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "webmail-passwd <address>",
		Short: "Change a mailbox password for the webmail (alps). Reads the current and the new password from stdin, one per line.",
		Long: "Called by the webmail through sudo, as root. It reads two lines from stdin:\n" +
			"the current password, then the new one. The current password is checked\n" +
			"against the stored hash before anything changes. Passwords never go on the\n" +
			"command line.",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			// sudo passes the arguments through, so a caller could append a global
			// flag such as --config and point the root process at its own config. The
			// only argument this command takes is the address, so the argument vector
			// must be exactly: mailadmin webmail-passwd <address>.
			if len(os.Args) != 3 || os.Args[1] != "webmail-passwd" || strings.HasPrefix(os.Args[2], "-") {
				return fmt.Errorf("%w: webmail-passwd takes exactly one address and no flags", ErrUsage)
			}
			return app.webmailPasswd(c, args[0])
		},
	}
}

// readPasswordPair reads the current and the new password, one per line. A line is
// limited to the longest password the hasher accepts.
func readPasswordPair(r io.Reader) (current, next string, err error) {
	br := bufio.NewReaderSize(r, 4096)
	current, err = readPasswordLine(br)
	if err != nil {
		return "", "", fmt.Errorf("read current password: %w", err)
	}
	next, err = readPasswordLine(br)
	if err != nil {
		return "", "", fmt.Errorf("read new password: %w", err)
	}
	return current, next, nil
}

func readPasswordLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", err
	}
	line = strings.TrimSuffix(line, "\n")
	if line == "" {
		return "", errors.New("empty line")
	}
	return line, nil
}

func (a *App) webmailPasswd(cmd *cobra.Command, address string) error {
	c := ctx(cmd)
	local, dom, verr := valid.Address(address)
	if verr != nil {
		return fmt.Errorf("%w: %w", ErrUsage, verr)
	}
	current, next, rerr := readPasswordPair(a.stdin())
	if rerr != nil {
		return fmt.Errorf("%w: %w", ErrUsage, rerr)
	}

	d, err := a.db(c)
	if err != nil {
		return err
	}
	stored, gerr := d.MailboxPasswordHash(c, local, dom)
	if gerr != nil {
		return fmt.Errorf("mailbox %s: %w", address, ErrNotFound)
	}

	hasher := dovecotpw.New(a.runner())
	ok, verr2 := hasher.Verify(c, stored, current)
	if verr2 != nil {
		return verr2
	}
	if !ok {
		return errWrongPassword
	}
	hash, herr := hasher.Hash(c, next)
	if herr != nil {
		return herr
	}
	if err := d.UpdateMailboxPassword(c, local, dom, hash); err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	// The hash is never recorded; only the fact of a change.
	if aerr := a.recordAudit(c, "webmail.passwd", local+"@"+dom, nil, nil); aerr != nil {
		return fmt.Errorf("change applied but not audited: %w", aerr)
	}
	r, rerr2 := a.Renderer()
	if rerr2 != nil {
		return rerr2
	}
	r.Message("password for %s@%s updated", local, dom)
	return nil
}
