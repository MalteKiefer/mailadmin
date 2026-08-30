package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"mailadmin/internal/output"
	"mailadmin/internal/sieve"
)

// maxSieveFile bounds a Sieve script read from a file so a runaway path cannot
// stream unbounded data into memory (mirrors the backend's own cap).
const maxSieveFile = 1 << 16 // 64 KiB

func newSieveCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "sieve", Short: "Manage per-mailbox Sieve scripts"}

	show := &cobra.Command{
		Use:   "show <address>",
		Short: "Show the active Sieve script",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return app.sieveShow(c, args[0]) },
	}

	set := &cobra.Command{
		Use:   "set <address> <file>",
		Short: "Replace the active Sieve script from a file",
		Args:  cobra.ExactArgs(2),
		RunE:  func(c *cobra.Command, args []string) error { return app.sieveSet(c, args[0], args[1]) },
	}

	edit := &cobra.Command{
		Use:   "edit <address>",
		Short: "Edit the active Sieve script in $EDITOR",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return app.sieveEdit(c, args[0]) },
	}

	var vac vacationFlags
	vacation := &cobra.Command{
		Use:   "vacation <address>",
		Short: "Install an RFC 5230 vacation autoresponder for a mailbox",
		Long: "Generates a Sieve `vacation` script and installs it as the mailbox's\n" +
			"active script (replacing whatever was active before — mailadmin manages a\n" +
			"single script per mailbox, see `sieve set`). With --start/--end, the\n" +
			"responder is wrapped in a date guard so it only fires within that window;\n" +
			"without them it is always on. --message accepts literal text or @file to\n" +
			"read the body from a file.",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error { return app.sieveVacation(c, args[0], vac) },
	}
	vacation.Flags().StringVar(&vac.start, "start", "", "vacation window start (YYYY-MM-DD); requires --end")
	vacation.Flags().StringVar(&vac.end, "end", "", "vacation window end (YYYY-MM-DD); requires --start")
	vacation.Flags().StringVar(&vac.subject, "subject", "", "reply subject (default: the Sieve implementation's default)")
	vacation.Flags().StringVar(&vac.message, "message", "", "reply body text, or @file to read it from a file (required)")
	vacation.Flags().IntVar(&vac.days, "days", 7, "minimum days between repeat replies to the same sender")

	vacationOff := &cobra.Command{
		Use:   "vacation-off <address>",
		Short: "Disable the vacation autoresponder",
		Long: "Replaces the mailbox's active Sieve script with a minimal `keep;`\n" +
			"passthrough. mailadmin does not keep a history of prior script bodies (it\n" +
			"manages a single script per mailbox), so this cannot restore whatever was\n" +
			"active before the vacation responder — reinstall a saved script with\n" +
			"`sieve set` if you need that.",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error { return app.sieveVacationOff(c, args[0]) },
	}

	cmd.AddCommand(show, set, edit, vacation, vacationOff)
	return cmd
}

// vacationFlags holds the `sieve vacation` flag values.
type vacationFlags struct {
	start, end string
	subject    string
	message    string
	days       int
}

// sieveShow renders the active Sieve script for a mailbox.
func (a *App) sieveShow(cmd *cobra.Command, address string) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	svc := sieve.New(a.runner())
	script, err := svc.Show(ctx(cmd), address)
	if err != nil {
		if errors.Is(err, sieve.ErrNotFound) {
			return fmt.Errorf("%w: no active Sieve script for %s", ErrNotFound, address)
		}
		return err
	}
	return r.Value(script)
}

// sieveSet replaces the managed Sieve script from a file, confirming first
// (unless --yes) and recording the change in the audit log.
func (a *App) sieveSet(cmd *cobra.Command, address, file string) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	body, err := readSieveFile(file)
	if err != nil {
		return err
	}

	if a.flags.dryRun {
		r.Message("dry-run: would replace Sieve script for %s from %s (%d bytes)", address, file, len(body))
		return nil
	}

	if err := a.confirm(fmt.Sprintf("Replace active Sieve script for %s from %s?", address, file)); err != nil {
		return err
	}

	c := ctx(cmd)
	rec, err := a.auditor(c)
	if err != nil {
		return err
	}

	svc := sieve.New(a.runner())
	var before any
	if cur, err := svc.Show(c, address); err == nil {
		before = sieveMeta(len(cur.Body))
	} else if !errors.Is(err, sieve.ErrNotFound) {
		return err
	}

	if err := svc.Set(c, address, body); err != nil {
		return err
	}
	if err := rec.Record(c, "sieve.set", address, before, sieveMeta(len(body))); err != nil {
		return err
	}
	r.Message("Sieve script for %s updated (%d bytes)", address, len(body))
	return nil
}

// sieveEdit fetches the active script, opens it in $EDITOR, and writes it back
// if it changed. It reuses the same validation, confirm, and audit path as set.
func (a *App) sieveEdit(cmd *cobra.Command, address string) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	if a.flags.output == string(output.FormatJSON) {
		return fmt.Errorf("%w: sieve edit is interactive and cannot be used with -o json", ErrUsage)
	}

	c := ctx(cmd)
	svc := sieve.New(a.runner())

	original := ""
	if script, err := svc.Show(c, address); err == nil {
		original = script.Body
	} else if !errors.Is(err, sieve.ErrNotFound) {
		return err
	}

	if a.flags.dryRun {
		r.Message("dry-run: would edit Sieve script for %s", address)
		return nil
	}

	edited, err := editInEditor(original)
	if err != nil {
		return err
	}
	if edited == original {
		r.Message("No changes; Sieve script for %s left unchanged", address)
		return nil
	}
	if err := a.confirm(fmt.Sprintf("Save edited Sieve script for %s?", address)); err != nil {
		return err
	}

	rec, err := a.auditor(c)
	if err != nil {
		return err
	}
	if err := svc.Set(c, address, edited); err != nil {
		return err
	}
	if err := rec.Record(c, "sieve.set", address, sieveMeta(len(original)), sieveMeta(len(edited))); err != nil {
		return err
	}
	r.Message("Sieve script for %s updated (%d bytes)", address, len(edited))
	return nil
}

// sieveMeta is the audit before/after payload: script size only, never the body.
func sieveMeta(size int) map[string]int {
	return map[string]int{"bytes": size}
}

// sieveVacation generates a vacation autoresponder script from opts and
// installs it as address's active script via the same sieve.Service.Set path
// `sieve set` uses.
func (a *App) sieveVacation(cmd *cobra.Command, address string, opts vacationFlags) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	message, err := resolveVacationMessage(opts.message)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUsage, err)
	}
	body, err := sieve.GenerateVacation(sieve.VacationOptions{
		Start:   opts.start,
		End:     opts.end,
		Subject: opts.subject,
		Message: message,
		Days:    opts.days,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUsage, err)
	}

	if a.flags.dryRun {
		r.Message("dry-run: would install vacation autoresponder for %s (%d bytes)", address, len(body))
		return nil
	}
	if err := a.confirm(fmt.Sprintf("Install vacation autoresponder for %s (replaces the active Sieve script)?", address)); err != nil {
		return err
	}

	c := ctx(cmd)
	svc := sieve.New(a.runner())
	before, err := currentSieveMeta(c, svc, address)
	if err != nil {
		return err
	}
	rec, err := a.auditor(c)
	if err != nil {
		return err
	}
	if err := svc.Set(c, address, body); err != nil {
		return err
	}
	if err := rec.Record(c, "sieve.vacation-on", address, before, sieveMeta(len(body))); err != nil {
		return err
	}
	r.Message("vacation autoresponder installed for %s (%d bytes)", address, len(body))
	return nil
}

// sieveVacationOff replaces address's active Sieve script with a minimal
// `keep;` passthrough, disabling any autoresponder. mailadmin manages a
// single script per mailbox (see sieveSet), so this cannot restore whatever
// script was active before — reinstalling a saved copy via `sieve set` is the
// way to do that.
func (a *App) sieveVacationOff(cmd *cobra.Command, address string) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	body := sieve.GenerateDisabled()

	if a.flags.dryRun {
		r.Message("dry-run: would disable vacation autoresponder for %s", address)
		return nil
	}
	if err := a.confirm(fmt.Sprintf("Disable vacation autoresponder for %s (replaces the active Sieve script with keep;)?", address)); err != nil {
		return err
	}

	c := ctx(cmd)
	svc := sieve.New(a.runner())
	before, err := currentSieveMeta(c, svc, address)
	if err != nil {
		return err
	}
	rec, err := a.auditor(c)
	if err != nil {
		return err
	}
	if err := svc.Set(c, address, body); err != nil {
		return err
	}
	if err := rec.Record(c, "sieve.vacation-off", address, before, sieveMeta(len(body))); err != nil {
		return err
	}
	r.Message("vacation autoresponder disabled for %s", address)
	return nil
}

// currentSieveMeta returns the audit "before" snapshot (script size only) for
// address's current active script, or nil if it has none.
func currentSieveMeta(c context.Context, svc *sieve.Service, address string) (any, error) {
	cur, err := svc.Show(c, address)
	if err == nil {
		return sieveMeta(len(cur.Body)), nil
	}
	if errors.Is(err, sieve.ErrNotFound) {
		return nil, nil
	}
	return nil, err
}

// resolveVacationMessage returns the vacation message body: raw is used
// literally, unless it starts with "@", in which case the rest is a file path
// to read the body from (mirroring the common curl/-d @file convention).
func resolveVacationMessage(raw string) (string, error) {
	if !strings.HasPrefix(raw, "@") {
		if strings.TrimSpace(raw) == "" {
			return "", fmt.Errorf("--message is required")
		}
		return raw, nil
	}
	path := strings.TrimPrefix(raw, "@")
	if path == "" {
		return "", fmt.Errorf("--message: @ given with no file path")
	}
	return readSieveVacationMessageFile(path)
}

// readSieveVacationMessageFile reads and size-caps a vacation message body
// file (same cap and confinement discipline as readSieveFile).
func readSieveVacationMessageFile(path string) (string, error) {
	clean := filepath.Clean(path)
	fi, err := os.Stat(clean)
	if err != nil {
		return "", fmt.Errorf("read message file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("read message file: %s is not a regular file", clean)
	}
	if fi.Size() > maxSieveFile {
		return "", fmt.Errorf("read message file: %s is %d bytes (max %d)", clean, fi.Size(), maxSieveFile)
	}
	b, err := os.ReadFile(clean) // #nosec G304 -- operator-supplied local message file path (root CLI), cleaned and stat-checked
	if err != nil {
		return "", fmt.Errorf("read message file: %w", err)
	}
	return string(b), nil
}

// readSieveFile reads and size-caps a Sieve script file. The path is cleaned and
// must resolve to a regular file.
func readSieveFile(path string) (string, error) {
	clean := filepath.Clean(path)
	fi, err := os.Stat(clean)
	if err != nil {
		return "", fmt.Errorf("read sieve file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("read sieve file: %s is not a regular file", clean)
	}
	if fi.Size() > maxSieveFile {
		return "", fmt.Errorf("read sieve file: %s is %d bytes (max %d)", clean, fi.Size(), maxSieveFile)
	}
	b, err := os.ReadFile(clean) // #nosec G304 -- operator-supplied local Sieve file path (root CLI), cleaned and stat-checked
	if err != nil {
		return "", fmt.Errorf("read sieve file: %w", err)
	}
	return string(b), nil
}

// editInEditor writes initial into a temp file, opens it in $EDITOR (falling
// back to a sensible default), and returns the edited contents. The editor is
// launched via internal exec with the operator's terminal attached; it is a
// local interactive tool, not a privileged mail command, so it does not go
// through internal/sys.
func editInEditor(initial string) (string, error) {
	f, err := os.CreateTemp("", "mailadmin-sieve-*.sieve")
	if err != nil {
		return "", fmt.Errorf("edit: temp file: %w", err)
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()

	if _, err := f.WriteString(initial); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("edit: write temp: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("edit: close temp: %w", err)
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		editor = "vi"
	}
	editorPath, err := exec.LookPath(editor)
	if err != nil {
		return "", fmt.Errorf("edit: editor %q not found: %w", editor, err)
	}

	// editorPath is resolved from the operator's own $EDITOR/$VISUAL (root's
	// interactive session), and name is a temp file this process created; neither
	// argument is attacker-controlled. This is a local editor launch, not a
	// privileged mail command, so it deliberately does not go through internal/sys.
	ed := exec.Command(editorPath, name) // #nosec G204 G702 -- operator's own $EDITOR on a self-created temp file
	ed.Stdin, ed.Stdout, ed.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := ed.Run(); err != nil {
		return "", fmt.Errorf("edit: editor exited: %w", err)
	}

	b, err := os.ReadFile(name) // #nosec G304 -- reading back the temp file this function created
	if err != nil {
		return "", fmt.Errorf("edit: read back: %w", err)
	}
	return string(b), nil
}
