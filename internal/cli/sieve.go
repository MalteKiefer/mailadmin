package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

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

	cmd.AddCommand(show, set, edit)
	return cmd
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
