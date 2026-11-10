package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spf13/cobra"

	"mailadmin/internal/bimi"
	"mailadmin/internal/config"
	"mailadmin/internal/db"
	"mailadmin/internal/dnsprovider"
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
		Short: "Add a domain (creates DKIM key; auto-sets DNS for automated-provider domains)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runDomainAdd(app, c, args[0], addSelector, addDNS, addNoDNS)
		},
	}
	add.Flags().StringVar(&addSelector, "selector", "", "DKIM selector (default from config)")
	add.Flags().StringVar(&addDNS, "dns", "manual", "DNS backend: manual|njalla|desec|cloudflare|inwx|servercow|servfail")
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

	setProvider := &cobra.Command{
		Use:   "set-provider <domain> <provider>",
		Short: "Set a domain's DNS provider (manual|njalla|desec|cloudflare|inwx|servercow|servfail)",
		Long: "Point a domain at a DNS backend so `dns publish` (and DANE) manage its\n" +
			"zone via that provider's API. Use after `dns migrate` moved the zone —\n" +
			"migrate copies records but leaves the provider unchanged.",
		Args: cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error { return runDomainSetProvider(app, c, args[0], args[1]) },
	}

	var bimiLogoURL, bimiLogoFile, bimiVMCURL string
	setBIMI := &cobra.Command{
		Use:   "set-bimi <domain>",
		Short: "Compute and publish the default._bimi TXT record for a domain",
		Long: "Publishes the default._bimi TXT record (v=BIMI1; l=<logo-url>[; a=<vmc-url>]).\n\n" +
			"mailadmin does not host the logo itself: host the SVG (and VMC, if you have\n" +
			"one) somewhere with a stable HTTPS URL first — a static bucket, your own\n" +
			"web root, whatever — then point --logo-url (and optionally --vmc-url) at\n" +
			"it. --logo-file is optional and only used locally: it validates that a\n" +
			"copy of the SVG you are about to publish is well-formed XML with\n" +
			"baseProfile=\"tiny-ps\" (the two most common mistakes), catching an\n" +
			"obviously wrong file before it is published. It is not a full SVG Tiny PS\n" +
			"conformance check.\n\n" +
			"BIMI only displays once DMARC enforces (p=quarantine or reject) — see\n" +
			"`dns audit`. Publishing follows the same path as `dns publish`: the\n" +
			"domain's dns_provider decides whether the record is actually written\n" +
			"(manual just prints it) or only shown; --dry-run always just shows it.",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runDomainSetBIMI(app, c, args[0], bimiLogoURL, bimiLogoFile, bimiVMCURL)
		},
	}
	setBIMI.Flags().StringVar(&bimiLogoURL, "logo-url", "", "https:// URL where the BIMI SVG logo is hosted (required)")
	setBIMI.Flags().StringVar(&bimiLogoFile, "logo-file", "", "local path to that same SVG, validated before publishing (optional)")
	setBIMI.Flags().StringVar(&bimiVMCURL, "vmc-url", "", "https:// URL where the Verified Mark Certificate is hosted (optional)")

	var rotateSelector string
	dkimRotateStart := &cobra.Command{
		Use:   "dkim-rotate-start <domain>",
		Short: "Begin a DKIM rotation: generate a new key and publish it alongside the current one",
		Long: "Generates a NEW DKIM key under a NEW selector and publishes BOTH the\n" +
			"current and new selector's DNS TXT records. The domain keeps SIGNING\n" +
			"with the current (old) selector throughout, so mail keeps flowing\n" +
			"correctly while the new key propagates — no overlap window, unlike\n" +
			"`set-dkim`/`regen-dkim`, which cut over instantly in one step.\n\n" +
			"Once DNS has propagated (wait at least the record TTL, longer for a\n" +
			"comfortable margin), run `dkim-rotate-finish <domain> <new-selector>`\n" +
			"to switch signing over. This command prints the exact selector to pass\n" +
			"it — mailadmin does not persist rotation state between the two steps.",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runDomainDKIMRotateStart(app, c, args[0], rotateSelector)
		},
	}
	dkimRotateStart.Flags().StringVar(&rotateSelector, "selector", "", "new DKIM selector (default: <current-selector>-<YYYYMMDD>)")

	var rotateRemoveOld bool
	dkimRotateFinish := &cobra.Command{
		Use:   "dkim-rotate-finish <domain> <new-selector>",
		Short: "Complete a DKIM rotation: switch signing to the new selector",
		Long: "Switches Dovecot/Rspamd signing over to <new-selector> — the DB cutover\n" +
			"that `set-dkim`/`regen-dkim` perform instantly, now split out as an\n" +
			"explicit second step. <new-selector> must already have a published key\n" +
			"(run `dkim-rotate-start` first).\n\n" +
			"By default the OLD selector's DNS record is left in place for a grace\n" +
			"period: harmless (an unused TXT record), and safer in case any mail\n" +
			"still queued or being verified was signed with it right before cutover.\n" +
			"Pass --remove-old to delete it immediately instead.",
		Args: cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			return runDomainDKIMRotateFinish(app, c, args[0], args[1], rotateRemoveOld)
		},
	}
	dkimRotateFinish.Flags().BoolVar(&rotateRemoveOld, "remove-old", false, "also remove the old selector's DNS record immediately, instead of leaving it for a grace period")

	for _, sc := range []*cobra.Command{show, remove, enable, disable, setDKIM, regenDKIM, setProvider, setBIMI, dkimRotateStart, dkimRotateFinish} {
		sc.ValidArgsFunction = app.completeDomain
	}

	cmd.AddCommand(list, show, add, remove, enable, disable, setDKIM, regenDKIM, setProvider, setBIMI, dkimRotateStart, dkimRotateFinish)
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
	if _, gerr := database.GetDomain(ctx(c), name); gerr == nil {
		return alreadyExistsErr("domain", name, "use domain set-provider to change its DNS provider, or domain enable if it is disabled")
	} else if !errors.Is(gerr, pgx.ErrNoRows) {
		return fmt.Errorf("get domain: %w", gerr)
	}
	if app.flags.dryRun {
		r.Message("dry-run: would add domain %s (selector %s, dns %s)", name, selector, provider)
		return nil
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
	if err := database.CreateDomain(ctx(c), name, selector); errors.Is(err, db.ErrExists) {
		return alreadyExistsErr("domain", name, "use domain set-provider to change its DNS provider, or domain enable if it is disabled")
	} else if err != nil {
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
	if err := app.syncRspamdSelectors(ctx(c)); err != nil {
		r.Message("warning: could not update the rspamd DKIM selector map: %v", err)
	}
	if err := app.syncAutodiscovery(ctx(c)); err != nil {
		r.Message("warning: could not update Caddy autodiscovery: %v", err)
	}
	// Bring up the MTA-STS policy endpoint (mta-sts.<domain>) in the same step so
	// a later `dns publish --with-mta-sts` finds a live enforce policy. A reload
	// failure is a soft warning — the domain is already created.
	if err := app.syncMTASTS(ctx(c)); err != nil {
		r.Message("warning: could not update Caddy MTA-STS: %v", err)
	}

	// For an automated registrar, publish the mail record-set straight away so a
	// new domain is live without a second manual step. MTA-STS is withheld until
	// the policy endpoint is confirmed (dnsPublish's guard). --no-dns opts out;
	// a missing token is a soft skip, not a failure (the domain is already added).
	if automatedDNS(provider) && !noDNS {
		_, secrets, cerr := app.Config()
		configured := cerr == nil && providerConfigured(provider, secrets)
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

	if app.flags.dryRun {
		r.Message("dry-run: would remove domain %s", name)
		return nil
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
	if err := app.syncRspamdSelectors(ctx(c)); err != nil {
		r.Message("warning: could not update the rspamd DKIM selector map: %v", err)
	}
	if err := app.syncAutodiscovery(ctx(c)); err != nil {
		r.Message("warning: could not update Caddy autodiscovery: %v", err)
	}
	if err := app.syncMTASTS(ctx(c)); err != nil {
		r.Message("warning: could not update Caddy MTA-STS: %v", err)
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
	}

	if app.flags.dryRun {
		r.Message("dry-run: would set domain %s active=%v", name, active)
		return nil
	}

	if !active {
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
	// MTA-STS is active-gated: enabling must publish the policy endpoint, disabling
	// must withdraw it. Regenerate the include from the new active set.
	if err := app.syncRspamdSelectors(ctx(c)); err != nil {
		r.Message("warning: could not update the rspamd DKIM selector map: %v", err)
	}
	if err := app.syncMTASTS(ctx(c)); err != nil {
		r.Message("warning: could not update Caddy MTA-STS: %v", err)
	}
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
	if app.flags.dryRun {
		r.Message("dry-run: would set DKIM selector for %s to %s", name, selector)
		return nil
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
	if err := app.syncRspamdSelectors(ctx(c)); err != nil {
		r.Message("warning: could not update the rspamd DKIM selector map: %v", err)
	}
	return r.Value(domainView{
		Name:        name,
		Active:      before.Active,
		Selector:    selector,
		DNSProvider: before.DNSProvider,
		DKIM:        key.PublicKey,
	})
}

// runDomainSetProvider changes a domain's DNS backend and audits the change.
// It does not publish records — the operator runs `dns publish` afterwards.
func runDomainSetProvider(app *App, c *cobra.Command, rawDomain, rawProvider string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	name, err := valid.Domain(rawDomain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	provider, err := validDNSProvider(strings.ToLower(strings.TrimSpace(rawProvider)))
	if err != nil {
		return err
	}
	database, err := app.db(ctx(c))
	if err != nil {
		return err
	}
	before, err := loadDomain(ctx(c), database, name)
	if err != nil {
		return err
	}

	if app.flags.dryRun {
		r.Message("dry-run: would set DNS provider for %s to %s", name, provider)
		return nil
	}

	rec, err := app.auditor(ctx(c))
	if err != nil {
		return err
	}
	if err := database.SetDomainDNSProvider(ctx(c), name, provider); err != nil {
		return err
	}
	if err := rec.Record(ctx(c), "domain.set-provider", name,
		map[string]any{"dns_provider": before.DNSProvider},
		map[string]any{"dns_provider": provider}); err != nil {
		return err
	}
	r.Message("set DNS provider for %s to %s", name, provider)
	if provider != "manual" {
		r.Message("run `mailadmin dns publish %s` to publish the mail record-set at %s", name, provider)
	}
	return r.Value(domainView{
		Name:        name,
		Active:      before.Active,
		Selector:    before.DKIMSelector,
		DNSProvider: provider,
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
	if app.flags.dryRun {
		r.Message("dry-run: would regenerate DKIM key for %s (selector %s)", name, d.DKIMSelector)
		return nil
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

// runDomainSetBIMI computes the default._bimi TXT record from an
// operator-hosted logo URL (and optional VMC URL) and publishes it through
// the same dnsprovider Plan/Reconcile path `dns publish` uses, so it respects
// --dry-run and the domain's configured dns_provider.
//
// Design note (hosting): mailadmin does NOT host the BIMI logo/VMC itself.
// The alternative — a managed Caddy web root at /srv/caddy/bimi, mirroring
// internal/webserver's autodiscovery/MTA-STS include pattern — was
// considered, but BIMI logos need to satisfy stricter, external constraints
// (SVG Tiny PS conformance, and for the checkmark-in-mailbox display a VMC
// signed by a commercial CA against the *exact* hosted bytes) that mailadmin
// cannot validate or obtain on the operator's behalf. Emitting the DNS record
// for an externally-hosted logo is the lower-risk option: no new Caddy
// include, no new reload path, and no false sense that mailadmin "handles"
// BIMI compliance end-to-end when the CA/VMC step still requires the
// operator regardless.
func runDomainSetBIMI(app *App, c *cobra.Command, rawDomain, logoURL, logoFile, vmcURL string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}

	if logoFile != "" {
		data, ferr := os.ReadFile(logoFile) // #nosec G304 -- operator-supplied path on a root CLI
		if ferr != nil {
			return fmt.Errorf("%w: read --logo-file: %v", ErrUsage, ferr)
		}
		if verr := bimi.ValidateSVG(data); verr != nil {
			return fmt.Errorf("%w: --logo-file: %v", ErrUsage, verr)
		}
		r.Message("logo file %s looks like a valid Tiny-PS BIMI SVG (well-formed, baseProfile=\"tiny-ps\")", logoFile)
	}

	rec, err := bimi.BuildRecord(logoURL, vmcURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	desired := []dnsprovider.Record{{Type: "TXT", Name: rec.Name, Content: rec.Content}}

	be, domain, err := app.dnsMutableBackends(c, rawDomain, false)
	if err != nil {
		return err
	}
	defer be.db.Close()

	if app.flags.dryRun {
		r.Message("dry-run: would publish BIMI record for %s", domain)
		return r.TypeTable(recordsTable(desired), 0)
	}

	if be.provider == nil {
		r.Message("%s has no automated DNS provider — add this record yourself:", domain)
		return r.TypeTable(recordsTable(desired), 0)
	}

	if err := app.confirm(fmt.Sprintf("Publish BIMI record for %s at %s?", domain, be.provider.Name())); err != nil {
		return err
	}
	applied, err := dnsprovider.Reconcile(ctx(c), be.provider, domain, desired)
	if err != nil && len(applied) == 0 {
		return fmt.Errorf("domain set-bimi %s: %w", domain, err)
	}
	if rerr := be.rec.Record(ctx(c), "domain.set-bimi", domain, nil, changeSummary(applied)); rerr != nil && err == nil {
		return rerr
	}
	if err != nil {
		return fmt.Errorf("domain set-bimi %s: %w", domain, err)
	}
	r.Message("published BIMI record for %s at %s", domain, be.provider.Name())
	return r.Table(changesTable(applied))
}

// autoRotateSelector derives a default new selector for a DKIM rotation when
// the operator does not pass --selector: the current selector with today's
// date appended, so successive rotations sort naturally and never collide
// within a day.
func autoRotateSelector(current string) string {
	sel := current + "-" + time.Now().UTC().Format("20060102")
	if len(sel) > 63 {
		sel = sel[:63]
	}
	return sel
}

// resolveRotateSelector picks and validates the new DKIM selector for a
// rotation: the operator's --selector if given, else one auto-generated from
// the current selector — always validated and always distinct from current.
// Pure (no I/O) so it is unit-testable without a DB or DKIM keys on disk.
func resolveRotateSelector(current, requested string) (string, error) {
	newSelector := strings.TrimSpace(requested)
	if newSelector == "" {
		newSelector = autoRotateSelector(current)
	}
	newSelector, err := valid.Selector(newSelector)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if newSelector == current {
		return "", fmt.Errorf("%w: new selector must differ from the current selector %s", ErrUsage, current)
	}
	return newSelector, nil
}

// runDomainDKIMRotateStart generates a new DKIM key under a new selector and
// publishes it alongside the still-signing old selector's record, so both are
// live in DNS during the propagation window. It never touches the domain row
// (that is dkim-rotate-finish's job) — the domain keeps signing with the old
// selector until the operator explicitly cuts over.
func runDomainDKIMRotateStart(app *App, c *cobra.Command, rawDomain, rawSelector string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}

	be, domain, err := app.dnsMutableBackends(c, rawDomain, false)
	if err != nil {
		return err
	}
	defer be.db.Close()

	before, err := getDomain(ctx(c), be.db, domain)
	if err != nil {
		return err
	}
	if before.DKIMSelector == "" {
		return fmt.Errorf("%w: %s has no DKIM selector yet — run: mailadmin domain set-dkim %s <selector>", ErrUsage, domain, domain)
	}

	newSelector, err := resolveRotateSelector(before.DKIMSelector, rawSelector)
	if err != nil {
		return err
	}

	if app.flags.dryRun {
		r.Message("dry-run: would generate a DKIM key for %s at selector %s and publish it alongside the current selector %s", domain, newSelector, before.DKIMSelector)
		return nil
	}

	newKey, err := be.mgr.GenerateDKIM(ctx(c), domain, newSelector)
	if err != nil {
		return err
	}
	oldKey, err := be.mgr.ReadDKIM(domain, before.DKIMSelector)
	if err != nil {
		return fmt.Errorf("domain dkim-rotate-start %s: read current key: %w", domain, err)
	}

	desired := []dnsprovider.Record{
		{Type: "TXT", Name: before.DKIMSelector + "._domainkey", Content: oldKey.PublicKey},
		{Type: "TXT", Name: newSelector + "._domainkey", Content: newKey.PublicKey},
	}

	if err := be.rec.Record(ctx(c), "domain.dkim-rotate-start", domain,
		map[string]any{"selector": before.DKIMSelector},
		map[string]any{"new_selector": newSelector}); err != nil {
		return err
	}

	if be.provider == nil {
		r.Message("%s is on manual DNS — add both DKIM TXT records below (keep %s published during the overlap):", domain, before.DKIMSelector)
		r.Message("once DNS has propagated, run: mailadmin domain dkim-rotate-finish %s %s", domain, newSelector)
		return r.Table(recordsTable(desired))
	}

	if err := app.confirm(fmt.Sprintf("Publish DKIM key for new selector %s at %s (domain keeps signing with %s until you run dkim-rotate-finish)?",
		newSelector, be.provider.Name(), before.DKIMSelector)); err != nil {
		return err
	}
	applied, err := dnsprovider.Reconcile(ctx(c), be.provider, domain, desired)
	if err != nil {
		if len(applied) > 0 {
			r.Message("partially published DKIM selector %s for %s at %s", newSelector, domain, be.provider.Name())
			_ = r.Table(changesTable(applied))
		}
		return fmt.Errorf("domain dkim-rotate-start %s: %w", domain, err)
	}
	r.Message("published DKIM selector %s for %s at %s — still signing with %s", newSelector, domain, be.provider.Name(), before.DKIMSelector)
	r.Message("once DNS has propagated, run: mailadmin domain dkim-rotate-finish %s %s", domain, newSelector)
	return r.Table(changesTable(applied))
}

// runDomainDKIMRotateFinish switches DKIM signing over to newSelector (the
// cutover that set-dkim/regen-dkim perform instantly) and, by default, leaves
// the old selector's DNS record in place for a grace period. --remove-old
// deletes it immediately instead (best-effort at an automated provider; a
// manual domain is told to remove it by hand).
func runDomainDKIMRotateFinish(app *App, c *cobra.Command, rawDomain, rawNewSelector string, removeOld bool) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	newSelector, err := valid.Selector(rawNewSelector)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}

	be, domain, err := app.dnsMutableBackends(c, rawDomain, false)
	if err != nil {
		return err
	}
	defer be.db.Close()

	before, err := getDomain(ctx(c), be.db, domain)
	if err != nil {
		return err
	}
	if before.DKIMSelector == newSelector {
		return fmt.Errorf("%w: %s already signs with selector %s", ErrUsage, domain, newSelector)
	}
	if _, err := be.mgr.ReadDKIM(domain, newSelector); err != nil {
		return fmt.Errorf("domain dkim-rotate-finish %s: no key for selector %s (run dkim-rotate-start first): %w", domain, newSelector, err)
	}

	if app.flags.dryRun {
		r.Message("dry-run: would switch %s DKIM signing from %s to %s", domain, before.DKIMSelector, newSelector)
		if removeOld && before.DKIMSelector != "" {
			r.Message("dry-run: --remove-old would also remove the %s._domainkey DNS record", before.DKIMSelector)
		}
		return nil
	}

	if err := app.confirm(fmt.Sprintf("Switch %s DKIM signing from %s to %s?", domain, before.DKIMSelector, newSelector)); err != nil {
		return err
	}

	if err := be.db.SetDKIMSelector(ctx(c), domain, newSelector); err != nil {
		return err
	}
	if err := be.rec.Record(ctx(c), "domain.dkim-rotate-finish", domain,
		map[string]any{"selector": before.DKIMSelector},
		map[string]any{"selector": newSelector}); err != nil {
		return err
	}
	r.Message("switched %s DKIM signing to selector %s", domain, newSelector)
	if err := app.syncRspamdSelectors(ctx(c)); err != nil {
		r.Message("warning: could not update the rspamd DKIM selector map: %v", err)
	}

	switch {
	case before.DKIMSelector == "":
		// nothing to clean up
	case removeOld && be.provider != nil:
		if rerr := removeDKIMDNSRecord(ctx(c), be.provider, domain, before.DKIMSelector); rerr != nil {
			r.Message("warning: could not remove old DKIM DNS record for selector %s: %v", before.DKIMSelector, rerr)
		} else {
			r.Message("removed old DKIM DNS record for selector %s", before.DKIMSelector)
		}
	case removeOld:
		r.Message("note: %s is manual DNS — remove the old %s._domainkey TXT record yourself", domain, before.DKIMSelector)
	default:
		r.Message("old selector %s DNS record left in place for a grace period — remove it later (manually, or rerun finish with --remove-old) once you're sure no in-flight mail still needs it", before.DKIMSelector)
	}

	return r.Value(domainView{
		Name:        domain,
		Active:      before.Active,
		Selector:    newSelector,
		DNSProvider: before.DNSProvider,
	})
}

// removeDKIMDNSRecord deletes the live DNS record(s) at selector._domainkey
// for domain via the provider API. Used by dkim-rotate-finish --remove-old.
func removeDKIMDNSRecord(ctx context.Context, p dnsprovider.Provider, domain, selector string) error {
	name := selector + "._domainkey"
	live, err := p.ListRecords(ctx, domain)
	if err != nil {
		return err
	}
	removed := 0
	for _, rec := range live {
		if !strings.EqualFold(rec.Type, "TXT") {
			continue
		}
		if !strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(rec.Name), "."), name) {
			continue
		}
		if rec.ID == "" {
			continue
		}
		if err := p.RemoveRecord(ctx, domain, rec.ID); err != nil {
			// Earlier removals in this loop are already live. Rectify them before returning.
			if ferr := dnsprovider.FlushBatch(ctx, p, domain); ferr != nil {
				return fmt.Errorf("%w; rectify: %v", err, ferr)
			}
			return err
		}
		removed++
	}
	if ferr := dnsprovider.FlushBatch(ctx, p, domain); ferr != nil {
		return ferr
	}
	if removed == 0 {
		return fmt.Errorf("no DNS record found at %s", name)
	}
	return nil
}

// validDNSProvider validates the --dns backend flag against the supported set.
func validDNSProvider(s string) (string, error) {
	if s == "manual" || automatedDNS(s) {
		return s, nil
	}
	return "", fmt.Errorf("%w: DNS provider must be manual|%s, got %q", ErrUsage, strings.Join(automatedProviders, "|"), s)
}
