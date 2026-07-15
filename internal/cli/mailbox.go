package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/spf13/cobra"

	"mailadmin/internal/db"
	"mailadmin/internal/dovecotpw"
	"mailadmin/internal/maildir"
	"mailadmin/internal/output"
	"mailadmin/internal/quota"
	"mailadmin/internal/valid"
)

// DefaultQuotaBytes is applied when `mailbox add` is given no --quota (5 GiB),
// matching the legacy CLI default.
const DefaultQuotaBytes int64 = 5 << 30

// appPasswordLen is the length of a generated application password.
const appPasswordLen = 20

func newMailboxCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "mailbox", Short: "Manage mailboxes"}

	var listDomain string
	list := &cobra.Command{
		Use:   "list",
		Short: "List mailboxes",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, args []string) error { return app.mailboxList(c, listDomain) },
	}
	list.Flags().StringVar(&listDomain, "domain", "", "filter by domain")

	show := &cobra.Command{
		Use:   "show <address>",
		Short: "Show a mailbox (quota usage, state)",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return app.mailboxShow(c, args[0]) },
	}

	var addQuota int64
	add := &cobra.Command{
		Use:   "add <address>",
		Short: "Add a mailbox (prompts for password)",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return app.mailboxAdd(c, args[0], addQuota) },
	}
	add.Flags().Int64Var(&addQuota, "quota", 0, "quota in bytes (0 = default)")

	var removePurge bool
	remove := &cobra.Command{
		Use:   "remove <address>",
		Short: "Remove a mailbox",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return app.mailboxRemove(c, args[0], removePurge) },
	}
	remove.Flags().BoolVar(&removePurge, "purge", false, "also delete the maildir")

	passwd := &cobra.Command{
		Use:   "passwd <address>",
		Short: "Change a mailbox password (prompts)",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return app.mailboxPasswd(c, args[0]) },
	}

	setQuota := &cobra.Command{
		Use:   "set-quota <address> <bytes>",
		Short: "Set a mailbox quota in bytes",
		Args:  cobra.ExactArgs(2),
		RunE:  func(c *cobra.Command, args []string) error { return app.mailboxSetQuota(c, args[0], args[1]) },
	}

	enable := &cobra.Command{
		Use:   "enable <address>",
		Short: "Enable a mailbox",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return app.mailboxSetActive(c, args[0], true) },
	}

	disable := &cobra.Command{
		Use:   "disable <address>",
		Short: "Disable a mailbox",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return app.mailboxSetActive(c, args[0], false) },
	}

	var dedupeDryRun bool
	dedupe := &cobra.Command{
		Use:   "dedupe <address>",
		Short: "Deduplicate a mailbox's messages",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return app.mailboxDedupe(c, args[0], dedupeDryRun || app.flags.dryRun)
		},
	}
	dedupe.Flags().BoolVar(&dedupeDryRun, "dry-run", false, "report duplicates without deleting")

	for _, sc := range []*cobra.Command{show, remove, passwd, setQuota, enable, disable, dedupe} {
		sc.ValidArgsFunction = app.completeMailbox
	}

	cmd.AddCommand(list, show, add, remove, passwd, setQuota, enable, disable, dedupe, newAppPasswordCmd(app))
	return cmd
}

// completeMailbox is a cobra ValidArgsFunction completing the first argument with
// every mailbox address (best-effort; silent on error).
func (a *App) completeMailbox(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) != 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	database, err := a.db(ctx(cmd))
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	boxes, err := database.ListMailboxes(ctx(cmd), "")
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var out []string
	for _, m := range boxes {
		if addr := m.Address(); strings.HasPrefix(addr, toComplete) {
			out = append(out, addr)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// mailboxList prints all mailboxes, optionally filtered by domain.
func (a *App) mailboxList(cmd *cobra.Command, domainFilter string) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	c := ctx(cmd)

	if domainFilter != "" {
		dom, verr := valid.Domain(domainFilter)
		if verr != nil {
			return fmt.Errorf("%w: %v", ErrUsage, verr)
		}
		domainFilter = dom
	}

	d, err := a.db(c)
	if err != nil {
		return err
	}
	boxes, err := d.ListMailboxes(c, domainFilter)
	if err != nil {
		return fmt.Errorf("list mailboxes: %w", err)
	}

	t := output.Table{Columns: []string{"address", "quota_bytes", "active"}}
	for _, m := range boxes {
		t.Rows = append(t.Rows, []string{m.Address(), strconv.FormatInt(m.QuotaBytes, 10), boolYesNo(m.Active)})
	}
	return r.StatusTable(t, 2)
}

// mailboxView is the single-mailbox view rendered by `show`.
type mailboxView struct {
	Address    string `json:"address"`
	Active     bool   `json:"active"`
	QuotaBytes int64  `json:"quota_bytes"`
	UsedBytes  int64  `json:"used_bytes"`
	UsedPct    int    `json:"used_pct"`
	Created    string `json:"created_at"`
}

// mailboxShow prints a single mailbox with live quota usage.
func (a *App) mailboxShow(cmd *cobra.Command, address string) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	c := ctx(cmd)

	local, dom, verr := valid.Address(address)
	if verr != nil {
		return fmt.Errorf("%w: %v", ErrUsage, verr)
	}

	d, err := a.db(c)
	if err != nil {
		return err
	}
	m, err := d.GetMailbox(c, local, dom)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("mailbox %s: %w", address, ErrNotFound)
		}
		return fmt.Errorf("get mailbox: %w", err)
	}

	view := mailboxView{
		Address:    m.Address(),
		Active:     m.Active,
		QuotaBytes: m.QuotaBytes,
		Created:    m.CreatedAt.Format("2006-01-02 15:04:05"),
	}
	// Live usage is best-effort: doveadm may be unavailable in some contexts, so
	// a usage error degrades to the stored quota rather than failing the show.
	if usage, uerr := quota.New(a.runner()).Get(c, m.Address()); uerr == nil {
		view.UsedBytes = usage.UsedBytes
		view.UsedPct = usage.UsedPct
		if usage.LimitBytes > 0 {
			view.QuotaBytes = usage.LimitBytes
		}
	}
	return r.Value(view)
}

// mailboxAdd creates a mailbox, prompting for its password.
func (a *App) mailboxAdd(cmd *cobra.Command, address string, quotaBytes int64) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	c := ctx(cmd)

	local, dom, verr := valid.Address(address)
	if verr != nil {
		return fmt.Errorf("%w: %v", ErrUsage, verr)
	}
	if quotaBytes < 0 {
		return fmt.Errorf("%w: quota must be >= 0", ErrUsage)
	}
	if quotaBytes == 0 {
		quotaBytes = DefaultQuotaBytes
	}

	d, err := a.db(c)
	if err != nil {
		return err
	}
	// The domain must exist so a mailbox is never orphaned.
	if _, gerr := d.GetDomain(c, dom); gerr != nil {
		if errors.Is(gerr, pgx.ErrNoRows) {
			return fmt.Errorf("domain %s: %w", dom, ErrNotFound)
		}
		return fmt.Errorf("get domain: %w", gerr)
	}

	plaintext, err := a.readPassword("New password for " + local + "@" + dom)
	if err != nil {
		return err
	}
	hash, err := dovecotpw.New(a.runner()).Hash(c, plaintext)
	if err != nil {
		return err
	}

	mb := db.Mailbox{Username: local, Domain: dom, Password: hash, QuotaBytes: quotaBytes}
	if err := d.CreateMailbox(c, mb); err != nil {
		return fmt.Errorf("create mailbox: %w", err)
	}

	if rec, aerr := a.auditor(c); aerr == nil {
		_ = rec.Record(c, "mailbox.add", local+"@"+dom, nil, map[string]any{"quota_bytes": quotaBytes})
	}
	r.Message("mailbox %s@%s created (quota %d bytes)", local, dom, quotaBytes)
	return nil
}

// mailboxRemove deletes a mailbox (and, with --purge, its maildir).
func (a *App) mailboxRemove(cmd *cobra.Command, address string, purge bool) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	c := ctx(cmd)

	local, dom, verr := valid.Address(address)
	if verr != nil {
		return fmt.Errorf("%w: %v", ErrUsage, verr)
	}

	d, err := a.db(c)
	if err != nil {
		return err
	}
	m, err := d.GetMailbox(c, local, dom)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("mailbox %s: %w", address, ErrNotFound)
		}
		return fmt.Errorf("get mailbox: %w", err)
	}

	md := maildir.New("")
	present, mderr := md.Exists(local, dom)
	if mderr != nil {
		return fmt.Errorf("check maildir: %w", mderr)
	}
	if present && !purge {
		return fmt.Errorf("%w: maildir for %s still exists — pass --purge to delete it too",
			ErrUsage, m.Address())
	}

	action := "delete mailbox " + m.Address()
	if purge {
		action += " and its maildir"
	}
	if err := a.confirm(action + "?"); err != nil {
		return err
	}

	if purge && present {
		if err := md.Purge(local, dom); err != nil {
			return fmt.Errorf("purge maildir: %w", err)
		}
	}
	if err := d.DeleteAppPasswordsByMailbox(c, local, dom); err != nil {
		return fmt.Errorf("delete app passwords: %w", err)
	}
	if err := d.DeleteMailbox(c, local, dom); err != nil {
		return fmt.Errorf("delete mailbox: %w", err)
	}

	if rec, aerr := a.auditor(c); aerr == nil {
		_ = rec.Record(c, "mailbox.remove", m.Address(),
			map[string]any{"quota_bytes": m.QuotaBytes, "active": m.Active, "purged": purge && present}, nil)
	}
	r.Message("mailbox %s removed", m.Address())
	return nil
}

// mailboxPasswd changes a mailbox password.
func (a *App) mailboxPasswd(cmd *cobra.Command, address string) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	c := ctx(cmd)

	local, dom, verr := valid.Address(address)
	if verr != nil {
		return fmt.Errorf("%w: %v", ErrUsage, verr)
	}

	d, err := a.db(c)
	if err != nil {
		return err
	}
	if _, gerr := d.GetMailbox(c, local, dom); gerr != nil {
		if errors.Is(gerr, pgx.ErrNoRows) {
			return fmt.Errorf("mailbox %s: %w", address, ErrNotFound)
		}
		return fmt.Errorf("get mailbox: %w", gerr)
	}

	plaintext, err := a.readPassword("New password for " + local + "@" + dom)
	if err != nil {
		return err
	}
	hash, err := dovecotpw.New(a.runner()).Hash(c, plaintext)
	if err != nil {
		return err
	}
	if err := d.UpdateMailboxPassword(c, local, dom, hash); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	if rec, aerr := a.auditor(c); aerr == nil {
		// The hash is never recorded; only the fact of a rotation.
		_ = rec.Record(c, "mailbox.passwd", local+"@"+dom, nil, nil)
	}
	r.Message("password for %s@%s updated", local, dom)
	return nil
}

// mailboxSetQuota sets a mailbox's stored quota in bytes.
func (a *App) mailboxSetQuota(cmd *cobra.Command, address, bytesArg string) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	c := ctx(cmd)

	local, dom, verr := valid.Address(address)
	if verr != nil {
		return fmt.Errorf("%w: %v", ErrUsage, verr)
	}
	bytesVal, perr := strconv.ParseInt(bytesArg, 10, 64)
	if perr != nil || bytesVal < 0 {
		return fmt.Errorf("%w: quota bytes must be a non-negative integer", ErrUsage)
	}

	d, err := a.db(c)
	if err != nil {
		return err
	}
	m, gerr := d.GetMailbox(c, local, dom)
	if gerr != nil {
		if errors.Is(gerr, pgx.ErrNoRows) {
			return fmt.Errorf("mailbox %s: %w", address, ErrNotFound)
		}
		return fmt.Errorf("get mailbox: %w", gerr)
	}
	if err := d.UpdateMailboxQuota(c, local, dom, bytesVal); err != nil {
		return fmt.Errorf("update quota: %w", err)
	}

	if rec, aerr := a.auditor(c); aerr == nil {
		_ = rec.Record(c, "mailbox.set-quota", m.Address(),
			map[string]any{"quota_bytes": m.QuotaBytes}, map[string]any{"quota_bytes": bytesVal})
	}
	r.Message("quota for %s set to %d bytes", m.Address(), bytesVal)
	return nil
}

// mailboxSetActive enables or disables a mailbox.
func (a *App) mailboxSetActive(cmd *cobra.Command, address string, active bool) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	c := ctx(cmd)

	local, dom, verr := valid.Address(address)
	if verr != nil {
		return fmt.Errorf("%w: %v", ErrUsage, verr)
	}

	d, err := a.db(c)
	if err != nil {
		return err
	}
	m, gerr := d.GetMailbox(c, local, dom)
	if gerr != nil {
		if errors.Is(gerr, pgx.ErrNoRows) {
			return fmt.Errorf("mailbox %s: %w", address, ErrNotFound)
		}
		return fmt.Errorf("get mailbox: %w", gerr)
	}
	if err := d.SetMailboxActive(c, local, dom, active); err != nil {
		return fmt.Errorf("set active: %w", err)
	}

	verb := "enabled"
	action := "mailbox.enable"
	if !active {
		verb = "disabled"
		action = "mailbox.disable"
	}
	if rec, aerr := a.auditor(c); aerr == nil {
		_ = rec.Record(c, action, m.Address(),
			map[string]any{"active": m.Active}, map[string]any{"active": active})
	}
	r.Message("mailbox %s %s", m.Address(), verb)
	return nil
}

// mailboxDedupe removes duplicate messages from a mailbox's maildir.
func (a *App) mailboxDedupe(cmd *cobra.Command, address string, dryRun bool) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	c := ctx(cmd)

	local, dom, verr := valid.Address(address)
	if verr != nil {
		return fmt.Errorf("%w: %v", ErrUsage, verr)
	}

	d, err := a.db(c)
	if err != nil {
		return err
	}
	if _, gerr := d.GetMailbox(c, local, dom); gerr != nil {
		if errors.Is(gerr, pgx.ErrNoRows) {
			return fmt.Errorf("mailbox %s: %w", address, ErrNotFound)
		}
		return fmt.Errorf("get mailbox: %w", gerr)
	}

	if !dryRun {
		if err := a.confirm(fmt.Sprintf("delete duplicate messages in %s@%s?", local, dom)); err != nil {
			return err
		}
	}

	rep, derr := maildir.New("").Dedupe(local, dom, dryRun)
	if derr != nil {
		if errors.Is(derr, maildir.ErrNotFound) {
			return fmt.Errorf("maildir for %s@%s: %w", local, dom, ErrNotFound)
		}
		return fmt.Errorf("dedupe: %w", derr)
	}

	if !dryRun && rep.Deleted > 0 {
		if rec, aerr := a.auditor(c); aerr == nil {
			_ = rec.Record(c, "mailbox.dedupe", local+"@"+dom, nil,
				map[string]any{"deleted": rep.Deleted, "reclaimed_bytes": rep.Bytes})
		}
	}
	return r.Value(rep)
}

func newAppPasswordCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "app-password", Short: "Manage per-mailbox application passwords"}

	list := &cobra.Command{
		Use:   "list <address>",
		Short: "List application passwords",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return app.appPasswordList(c, args[0]) },
	}

	add := &cobra.Command{
		Use:   "add <address> <label>",
		Short: "Create an application password",
		Args:  cobra.ExactArgs(2),
		RunE:  func(c *cobra.Command, args []string) error { return app.appPasswordAdd(c, args[0], args[1]) },
	}

	remove := &cobra.Command{
		Use:   "remove <address> <label>",
		Short: "Remove an application password",
		Args:  cobra.ExactArgs(2),
		RunE:  func(c *cobra.Command, args []string) error { return app.appPasswordRemove(c, args[0], args[1]) },
	}

	cmd.AddCommand(list, add, remove)
	return cmd
}

// appPasswordList lists a mailbox's application passwords (never their hashes).
func (a *App) appPasswordList(cmd *cobra.Command, address string) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	c := ctx(cmd)

	local, dom, verr := valid.Address(address)
	if verr != nil {
		return fmt.Errorf("%w: %v", ErrUsage, verr)
	}

	d, err := a.db(c)
	if err != nil {
		return err
	}
	pws, err := d.ListAppPasswords(c, local, dom)
	if err != nil {
		return fmt.Errorf("list app passwords: %w", err)
	}

	t := output.Table{Columns: []string{"label", "active", "created_at", "last_used"}}
	for _, p := range pws {
		last := "-"
		if p.LastUsed != nil {
			last = p.LastUsed.Format("2006-01-02 15:04:05")
		}
		t.Rows = append(t.Rows, []string{
			p.Label, boolYesNo(p.Active), p.CreatedAt.Format("2006-01-02 15:04:05"), last,
		})
	}
	return r.Table(t)
}

// appPasswordResult is the one-time reveal of a newly created app password.
type appPasswordResult struct {
	Address  string `json:"address"`
	Label    string `json:"label"`
	Password string `json:"password"`
}

// appPasswordAdd creates a random application password and reveals it once.
func (a *App) appPasswordAdd(cmd *cobra.Command, address, label string) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	c := ctx(cmd)

	local, dom, verr := valid.Address(address)
	if verr != nil {
		return fmt.Errorf("%w: %v", ErrUsage, verr)
	}
	label, verr = validLabel(label)
	if verr != nil {
		return fmt.Errorf("%w: %v", ErrUsage, verr)
	}

	d, err := a.db(c)
	if err != nil {
		return err
	}
	// The mailbox must exist and be active before it can own app passwords.
	m, gerr := d.GetMailbox(c, local, dom)
	if gerr != nil {
		if errors.Is(gerr, pgx.ErrNoRows) {
			return fmt.Errorf("mailbox %s: %w", address, ErrNotFound)
		}
		return fmt.Errorf("get mailbox: %w", gerr)
	}
	if !m.Active {
		return fmt.Errorf("%w: mailbox %s is disabled", ErrUsage, m.Address())
	}

	plaintext, err := generatePassword(appPasswordLen)
	if err != nil {
		return err
	}
	hash, err := dovecotpw.New(a.runner()).Hash(c, plaintext)
	if err != nil {
		return err
	}
	if err := d.CreateAppPassword(c, local, dom, label, hash); err != nil {
		return fmt.Errorf("create app password: %w", err)
	}

	if rec, aerr := a.auditor(c); aerr == nil {
		// Only the label is recorded; the password/hash never touches the log.
		_ = rec.Record(c, "mailbox.app-password.add", local+"@"+dom, nil, map[string]any{"label": label})
	}

	res := appPasswordResult{Address: m.Address(), Label: label, Password: plaintext}
	if r.Format() != output.FormatJSON {
		r.Message("app password for %s (label: %s):", m.Address(), label)
		r.Message("  %s", plaintext)
		r.Message("(store it now — it cannot be retrieved again)")
		return nil
	}
	return r.JSON(res)
}

// appPasswordRemove deletes a mailbox's application password by label.
func (a *App) appPasswordRemove(cmd *cobra.Command, address, label string) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	c := ctx(cmd)

	local, dom, verr := valid.Address(address)
	if verr != nil {
		return fmt.Errorf("%w: %v", ErrUsage, verr)
	}
	label, verr = validLabel(label)
	if verr != nil {
		return fmt.Errorf("%w: %v", ErrUsage, verr)
	}

	if err := a.confirm(fmt.Sprintf("remove app password %q for %s@%s?", label, local, dom)); err != nil {
		return err
	}

	d, err := a.db(c)
	if err != nil {
		return err
	}
	n, derr := d.DeleteAppPassword(c, local, dom, label)
	if derr != nil {
		return fmt.Errorf("delete app password: %w", derr)
	}
	if n == 0 {
		return fmt.Errorf("app password %q for %s@%s: %w", label, local, dom, ErrNotFound)
	}

	if rec, aerr := a.auditor(c); aerr == nil {
		_ = rec.Record(c, "mailbox.app-password.remove", local+"@"+dom,
			map[string]any{"label": label}, nil)
	}
	r.Message("app password %q removed for %s@%s", label, local, dom)
	return nil
}
