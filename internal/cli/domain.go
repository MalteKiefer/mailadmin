package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/spf13/cobra"

	"mailadmin/internal/config"
	"mailadmin/internal/db"
	"mailadmin/internal/mail"
	"mailadmin/internal/output"
	"mailadmin/internal/valid"
)

func newDomainCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "domain", Short: "Manage mail domains"}

	list := &cobra.Command{
		Use:   "list",
		Short: "List domains",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, args []string) error { return runDomainList(app, c) },
	}

	show := &cobra.Command{
		Use:   "show <domain>",
		Short: "Show a domain and its DKIM/DNS state",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return runDomainShow(app, c, args[0]) },
	}

	var addSelector, addDNS string
	var addNoDNS bool
	add := &cobra.Command{
		Use:   "add <domain>",
		Short: "Add a domain (creates DKIM key; auto-sets DNS for automated (njalla|desec) domains)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runDomainAdd(app, c, args[0], addSelector, addDNS, addNoDNS)
		},
	}
	add.Flags().StringVar(&addSelector, "selector", "", "DKIM selector (default from config)")
	add.Flags().StringVar(&addDNS, "dns", "manual", "DNS backend: manual|njalla|desec")
	add.Flags().BoolVar(&addNoDNS, "no-dns", false, "skip automatic DNS publishing for automated domains")

	remove := &cobra.Command{
		Use:   "remove <domain>",
		Short: "Remove a domain (must have no mailboxes)",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return runDomainRemove(app, c, args[0]) },
	}

	enable := &cobra.Command{
		Use:   "enable <domain>",
		Short: "Enable a domain",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return runDomainSetActive(app, c, args[0], true) },
	}

	disable := &cobra.Command{
		Use:   "disable <domain>",
		Short: "Disable a domain",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return runDomainSetActive(app, c, args[0], false) },
	}

	setDKIM := &cobra.Command{
		Use:   "set-dkim <domain> <selector>",
		Short: "Set the DKIM selector for a domain",
		Args:  cobra.ExactArgs(2),
		RunE:  func(c *cobra.Command, args []string) error { return runDomainSetDKIM(app, c, args[0], args[1]) },
	}

	regenDKIM := &cobra.Command{
		Use:   "regen-dkim <domain>",
		Short: "Regenerate the DKIM key for a domain",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return runDomainRegenDKIM(app, c, args[0]) },
	}

	for _, sc := range []*cobra.Command{show, remove, enable, disable, setDKIM, regenDKIM} {
		sc.ValidArgsFunction = app.completeDomain
	}

	cmd.AddCommand(list, show, add, remove, enable, disable, setDKIM, regenDKIM)
	return cmd
}

// domainManager builds the DKIM/mail manager from config, using the shared
// privileged-exec runner (no direct exec; mail goes through internal/sys).
func (a *App) domainManager() (*mail.Manager, *config.Config, error) {
	cfg, _, err := a.Config()
	if err != nil {
		return nil, nil, err
	}
	m := mail.New(a.runner(), cfg.Mail.DKIMDir, cfg.Mail.Hostname, cfg.Server.IPv4, cfg.Server.IPv6)
	return m, cfg, nil
}

// loadDomain fetches a domain, mapping a missing row to ErrNotFound (exit 3).
func loadDomain(ctx context.Context, database *db.DB, name string) (db.Domain, error) {
	d, err := database.GetDomain(ctx, name)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Domain{}, fmt.Errorf("domain %s: %w", name, ErrNotFound)
		}
		return db.Domain{}, err
	}
	return d, nil
}

// runDomainList renders every domain as a table (or json/plain via -o).
func runDomainList(app *App, c *cobra.Command) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	database, err := app.db(ctx(c))
	if err != nil {
		return err
	}
	domains, err := database.ListDomains(ctx(c))
	if err != nil {
		return err
	}
	t := output.Table{Columns: []string{"NAME", "ACTIVE", "SELECTOR", "DNS", "CREATED"}}
	for _, d := range domains {
		t.Rows = append(t.Rows, []string{
			d.Name,
			yesNo(d.Active),
			d.DKIMSelector,
			d.DNSProvider,
			d.CreatedAt.Format("2006-01-02"),
		})
	}
	return r.StatusTable(t, 1)
}

// domainView is the redacted, presentable form of a domain plus its live DKIM
// record value for `domain show`.
type domainView struct {
	Name        string `json:"name"`
	Active      bool   `json:"active"`
	Selector    string `json:"selector"`
	DNSProvider string `json:"dns_provider"`
	Created     string `json:"created"`
	DKIM        string `json:"dkim"`
}

// runDomainShow renders one domain with its on-disk DKIM record value. A missing
// domain maps to exit 3; a missing/unreadable DKIM key is surfaced inline (not
// an error) so the operator can regenerate it.
func runDomainShow(app *App, c *cobra.Command, rawDomain string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	name, err := valid.Domain(rawDomain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	database, err := app.db(ctx(c))
	if err != nil {
		return err
	}
	d, err := loadDomain(ctx(c), database, name)
	if err != nil {
		return err
	}

	view := domainView{
		Name:        d.Name,
		Active:      d.Active,
		Selector:    d.DKIMSelector,
		DNSProvider: d.DNSProvider,
		Created:     d.CreatedAt.Format("2006-01-02"),
		DKIM:        "(no selector set)",
	}
	if d.DKIMSelector != "" {
		mgr, _, mErr := app.domainManager()
		if mErr != nil {
			return mErr
		}
		key, kErr := mgr.ReadDKIM(d.Name, d.DKIMSelector)
		switch {
		case kErr == nil:
			view.DKIM = key.PublicKey
		case errors.Is(kErr, mail.ErrNoDKIMKey):
			view.DKIM = "(key missing — run: mailadmin domain regen-dkim " + d.Name + ")"
		default:
			return kErr
		}
	}
	return r.Value(view)
}

// runDomainAdd creates a domain: it generates the DKIM key (idempotent), inserts
// the domain, sets the DNS provider, and records an audit entry. The selector
// defaults to mail.default_selector from config.
func runDomainAdd(app *App, c *cobra.Command, rawDomain, rawSelector, rawDNS string, noDNS bool) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	name, err := valid.Domain(rawDomain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	provider, err := validDNSProvider(rawDNS)
	if err != nil {
		return err
	}
	mgr, cfg, err := app.domainManager()
	if err != nil {
		return err
	}
	selector := rawSelector
	if selector == "" {
		selector = cfg.Mail.DefaultSelector
	}
	selector, err = valid.Selector(selector)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}

	database, err := app.db(ctx(c))
	if err != nil {
		return err
	}
	rec, err := app.auditor(ctx(c))
	if err != nil {
		return err
	}

	// Generate the DKIM key first so a publishable record exists before the row
	// is written; the helper is idempotent (only creates a missing key).
	key, err := mgr.GenerateDKIM(ctx(c), name, selector)
	if err != nil {
		return err
	}
	if err := database.CreateDomain(ctx(c), name, selector); err != nil {
		return err
	}
	if err := database.SetDomainDNSProvider(ctx(c), name, provider); err != nil {
		return err
	}
	if err := rec.Record(ctx(c), "domain.add", name, nil, map[string]any{
		"selector":     selector,
		"dns_provider": provider,
	}); err != nil {
		return err
	}

	r.Message("added domain %s (selector %s, dns %s)", name, selector, provider)

	// Autoconfig/autodiscover applies to every domain (not just automated DNS):
	// regenerate the managed Caddy include so autoconfig.<domain> /
	// autodiscover.<domain> are served. A reload failure is a soft warning — the
	// domain is already created.
	if err := app.syncAutodiscovery(ctx(c)); err != nil {
		r.Message("warning: could not update Caddy autodiscovery: %v", err)
	}

	// For an automated registrar, publish the mail record-set straight away so a
	// new domain is live without a second manual step. MTA-STS is withheld until
	// the policy endpoint is confirmed (dnsPublish's guard). --no-dns opts out;
	// a missing token is a soft skip, not a failure (the domain is already added).
	if automatedDNS(provider) && !noDNS {
		_, secrets, cerr := app.Config()
		configured := (provider == dnsProviderNjalla && secrets.HasNjalla()) ||
			(provider == dnsProviderDeSEC && secrets.HasDeSEC())
		switch {
		case cerr != nil:
			return cerr
		case !configured:
			r.Message("note: %s token not set — skipping DNS; run `mailadmin dns publish %s` once configured", provider, name)
		default:
			r.Message("publishing DNS for %s at %s ...", name, provider)
			return app.dnsPublish(c, name, false)
		}
	}

	return r.Value(domainView{
		Name:        name,
		Active:      true,
		Selector:    selector,
		DNSProvider: provider,
		DKIM:        key.PublicKey,
	})
}

// runDomainRemove deletes a domain after confirming it has no mailboxes. It is
// destructive: it confirms unless --yes and records an audit entry.
func runDomainRemove(app *App, c *cobra.Command, rawDomain string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	name, err := valid.Domain(rawDomain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	database, err := app.db(ctx(c))
	if err != nil {
		return err
	}
	if _, err := loadDomain(ctx(c), database, name); err != nil {
		return err
	}
	n, err := database.CountMailboxesInDomain(ctx(c), name)
	if err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("domain %s has %d mailbox(es) — remove them first", name, n)
	}

	if err := app.confirm("Remove domain " + name + " (irreversible)?"); err != nil {
		return err
	}
	rec, err := app.auditor(ctx(c))
	if err != nil {
		return err
	}
	if err := database.DeleteDomain(ctx(c), name); err != nil {
		return err
	}
	if err := rec.Record(ctx(c), "domain.remove", name, map[string]any{"name": name}, nil); err != nil {
		return err
	}
	r.Message("removed domain %s", name)
	if err := app.syncAutodiscovery(ctx(c)); err != nil {
		r.Message("warning: could not update Caddy autodiscovery: %v", err)
	}
	return nil
}

// runDomainSetActive enables or disables a domain and records an audit entry.
func runDomainSetActive(app *App, c *cobra.Command, rawDomain string, active bool) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	name, err := valid.Domain(rawDomain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	database, err := app.db(ctx(c))
	if err != nil {
		return err
	}
	before, err := loadDomain(ctx(c), database, name)
	if err != nil {
		return err
	}
	action := "domain.enable"
	verb := "enabled"
	if !active {
		action = "domain.disable"
		verb = "disabled"
		if err := app.confirm("Disable domain " + name + " (stops mail for all its mailboxes)?"); err != nil {
			return err
		}
	}

	rec, err := app.auditor(ctx(c))
	if err != nil {
		return err
	}
	if err := database.SetDomainActive(ctx(c), name, active); err != nil {
		return err
	}
	if err := rec.Record(ctx(c), action, name,
		map[string]any{"active": before.Active},
		map[string]any{"active": active}); err != nil {
		return err
	}
	r.Message("%s domain %s", verb, name)
	return nil
}

// runDomainSetDKIM points a domain at a new DKIM selector. It ensures the key
// material for the new selector exists (idempotent generate) so the published
// record is valid, then updates the row and audits the change.
func runDomainSetDKIM(app *App, c *cobra.Command, rawDomain, rawSelector string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	name, err := valid.Domain(rawDomain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	selector, err := valid.Selector(rawSelector)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	database, err := app.db(ctx(c))
	if err != nil {
		return err
	}
	before, err := loadDomain(ctx(c), database, name)
	if err != nil {
		return err
	}
	mgr, _, err := app.domainManager()
	if err != nil {
		return err
	}
	rec, err := app.auditor(ctx(c))
	if err != nil {
		return err
	}

	key, err := mgr.GenerateDKIM(ctx(c), name, selector)
	if err != nil {
		return err
	}
	if err := database.SetDKIMSelector(ctx(c), name, selector); err != nil {
		return err
	}
	if err := rec.Record(ctx(c), "domain.set-dkim", name,
		map[string]any{"selector": before.DKIMSelector},
		map[string]any{"selector": selector}); err != nil {
		return err
	}
	r.Message("set DKIM selector for %s to %s", name, selector)
	return r.Value(domainView{
		Name:        name,
		Active:      before.Active,
		Selector:    selector,
		DNSProvider: before.DNSProvider,
		DKIM:        key.PublicKey,
	})
}

// runDomainRegenDKIM (re)generates the DKIM key for a domain's current selector
// and audits it. It reads the selector from the row, so an unknown domain maps
// to exit 3.
func runDomainRegenDKIM(app *App, c *cobra.Command, rawDomain string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	name, err := valid.Domain(rawDomain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	database, err := app.db(ctx(c))
	if err != nil {
		return err
	}
	d, err := loadDomain(ctx(c), database, name)
	if err != nil {
		return err
	}
	if d.DKIMSelector == "" {
		return fmt.Errorf("domain %s has no DKIM selector — set one with: mailadmin domain set-dkim %s <selector>", name, name)
	}
	if err := app.confirm("Regenerate the DKIM key for " + name + " (selector " + d.DKIMSelector + ")?"); err != nil {
		return err
	}
	mgr, _, err := app.domainManager()
	if err != nil {
		return err
	}
	rec, err := app.auditor(ctx(c))
	if err != nil {
		return err
	}

	key, err := mgr.GenerateDKIM(ctx(c), name, d.DKIMSelector)
	if err != nil {
		return err
	}
	if err := rec.Record(ctx(c), "domain.regen-dkim", name, nil,
		map[string]any{"selector": d.DKIMSelector}); err != nil {
		return err
	}
	r.Message("regenerated DKIM key for %s (selector %s)", name, d.DKIMSelector)
	return r.Value(domainView{
		Name:        name,
		Active:      d.Active,
		Selector:    d.DKIMSelector,
		DNSProvider: d.DNSProvider,
		DKIM:        key.PublicKey,
	})
}

// validDNSProvider validates the --dns backend flag against the supported set.
func validDNSProvider(s string) (string, error) {
	switch s {
	case "manual", dnsProviderNjalla, dnsProviderDeSEC:
		return s, nil
	default:
		return "", fmt.Errorf("%w: --dns must be manual|njalla|desec, got %q", ErrUsage, s)
	}
}
