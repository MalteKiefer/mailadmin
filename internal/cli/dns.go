package cli

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spf13/cobra"

	"mailadmin/internal/audit"
	"mailadmin/internal/config"
	"mailadmin/internal/db"
	"mailadmin/internal/dnsaudit"
	"mailadmin/internal/dnscheck"
	"mailadmin/internal/dnsprovider"
	"mailadmin/internal/mail"
	"mailadmin/internal/output"
	"mailadmin/internal/sys"
	"mailadmin/internal/valid"
)

// dns_provider values that enable registrar automation.
const (
	dnsProviderNjalla = "njalla"
	dnsProviderDeSEC  = "desec"
)

// errManualDNS explains that a domain is not wired to an automated registrar.
var errManualDNS = errors.New("domain is not managed by an automated DNS provider")

func newDNSCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "dns", Short: "Show, check and publish DNS records"}

	var showMTASTS bool
	show := &cobra.Command{
		Use:   "show <domain>",
		Short: "Print the desired DNS record-set for a domain",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return app.dnsShow(c, args[0], showMTASTS) },
	}
	show.Flags().BoolVar(&showMTASTS, "with-mta-sts", false, "include MTA-STS records in the printed set")

	var checkNjalla, checkMTASTS bool
	check := &cobra.Command{
		Use:   "check <domain>",
		Short: "Verify live DNS (SPF/DKIM/DMARC/MX/MTA-STS/TLS-RPT)",
		Long: "Compare the desired mail record-set against what is actually live.\n\n" +
			"By default it resolves the public DNS via the configured resolver.\n" +
			"With --njalla it queries the registrar API instead and reports, per\n" +
			"record, whether it matches, drifts, or is missing at the zone.",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if checkNjalla {
				return app.dnsCheckNjalla(c, args[0], checkMTASTS)
			}
			return app.dnsCheck(c, args[0])
		},
	}
	check.Flags().BoolVar(&checkNjalla, "njalla", false, "compare against live records at the Njalla registrar instead of public DNS")
	check.Flags().BoolVar(&checkMTASTS, "with-mta-sts", false, "include MTA-STS records in the comparison (with --njalla)")

	var publishMTASTS bool
	publish := &cobra.Command{
		Use:   "publish <domain>",
		Short: "Reconcile the desired record-set at the registrar",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return app.dnsPublish(c, args[0], publishMTASTS) },
	}
	publish.Flags().BoolVar(&publishMTASTS, "with-mta-sts", false, "also publish MTA-STS records (requires a live enforce policy)")

	var takeoverKeepWeb, takeoverMTASTS bool
	takeover := &cobra.Command{
		Use:   "takeover <domain>",
		Short: "Snapshot then replace the whole zone with the mail record-set",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return app.dnsTakeover(c, args[0], takeoverKeepWeb, takeoverMTASTS)
		},
	}
	takeover.Flags().BoolVar(&takeoverKeepWeb, "keep-web", false, "preserve apex/www A/AAAA/CNAME records")
	takeover.Flags().BoolVar(&takeoverMTASTS, "with-mta-sts", false, "also publish MTA-STS records (requires a live enforce policy)")

	restore := &cobra.Command{
		Use:   "restore <domain> <backup>",
		Short: "Restore a zone from a saved snapshot",
		Args:  cobra.ExactArgs(2),
		RunE:  func(c *cobra.Command, args []string) error { return app.dnsRestore(c, args[0], args[1]) },
	}

	var migTo, migAXFR, migZonefile, migFrom string
	var migCreate, migProbe bool
	migrate := &cobra.Command{
		Use:   "migrate <domain>",
		Short: "Copy an existing zone into njalla/desec to support a registrar move",
		Long: "Pull every record of a zone and create it at the target provider\n" +
			"(the domain's dns_provider, or --to). Choose one source:\n" +
			"  --axfr <ns>        zone transfer from a nameserver (works for any host that allows it)\n" +
			"  --zonefile <file>  a BIND-format zone export\n" +
			"  --from njalla|desec  read via that provider's API\n" +
			"With --create the zone is created at the target first (deSEC), and the\n" +
			"nameservers + DNSSEC DS records to set at your registrar are printed.\n" +
			"Existing target records are left untouched; nothing is deleted.",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return app.dnsMigrate(c, args[0], migTo, migFrom, migAXFR, migZonefile, migCreate, migProbe)
		},
	}
	migrate.Flags().StringVar(&migTo, "to", "", "target provider: njalla|desec (default: the domain's dns_provider)")
	migrate.Flags().StringVar(&migAXFR, "axfr", "", "source: pull the zone from this nameserver via AXFR")
	migrate.Flags().StringVar(&migZonefile, "zonefile", "", "source: import records from a BIND zone file")
	migrate.Flags().StringVar(&migFrom, "from", "", "source: read via this provider's API (njalla|desec)")
	migrate.Flags().BoolVar(&migProbe, "probe", false, "source: best-effort discovery via public DNS (fallback when AXFR/zonefile are unavailable)")
	migrate.Flags().BoolVar(&migCreate, "create", false, "create the zone at the target first (deSEC) and print delegation info")

	var auditSelectors []string
	audit := &cobra.Command{
		Use:   "audit <domain>",
		Short: "Grade a domain's mail-security posture (SPF/DKIM/DMARC/DNSSEC/MTA-STS/TLS-RPT/BIMI)",
		Long: "Evaluate live public DNS for correctness and policy strength per RFC —\n" +
			"not a desired/actual diff (that is `dns check`). Works for any domain,\n" +
			"including externally hosted ones. DKIM selectors are taken from --selector,\n" +
			"else the domain's configured selector, else a common-provider set.",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error { return app.dnsAudit(c, args[0], auditSelectors) },
	}
	audit.Flags().StringArrayVar(&auditSelectors, "selector", nil, "DKIM selector to check (repeatable)")

	var zoneProvider string
	zone := &cobra.Command{Use: "zone", Short: "Manage hosted zones at the DNS provider"}
	zoneCreate := &cobra.Command{
		Use:   "create <domain>",
		Short: "Create the DNS zone at the provider and print nameservers + DS records",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return app.dnsZoneCreate(c, args[0], zoneProvider) },
	}
	zoneCreate.Flags().StringVar(&zoneProvider, "provider", "", "provider to create the zone at: desec (default: the domain's dns_provider)")
	zone.AddCommand(zoneCreate)

	for _, sc := range []*cobra.Command{show, check, publish, takeover, migrate, audit} {
		sc.ValidArgsFunction = app.completeDomain
	}
	zoneCreate.ValidArgsFunction = app.completeDomain

	cmd.AddCommand(show, check, publish, takeover, restore, migrate, audit, zone)
	return cmd
}

// completeDomain is a cobra ValidArgsFunction that completes the first argument
// with the managed domain names (best-effort; returns nothing on any error so
// shell completion never emits noise). Used by the domain-taking commands.
func (a *App) completeDomain(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) != 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	cfg, _, err := a.Config()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	database, err := a.openDB(cmd, cfg)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	defer database.Close()
	domains, err := database.ListDomains(ctx(cmd))
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var out []string
	for _, d := range domains {
		if strings.HasPrefix(d.Name, toComplete) {
			out = append(out, d.Name)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// commonAuditSelectors are DKIM selectors probed when auditing a domain with no
// known selector (major providers + self-hosted defaults).
var commonAuditSelectors = []string{"default", "google", "selector1", "selector2", "mail", "k1", "fm1", "sig1"}

// dnsAudit grades a domain's mail-security posture from live public DNS.
func (a *App) dnsAudit(cmd *cobra.Command, rawDomain string, userSelectors []string) error {
	cfg, _, err := a.Config()
	if err != nil {
		return err
	}
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	domain, err := valid.Domain(rawDomain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}

	selectors := userSelectors
	if len(selectors) == 0 {
		if database, derr := a.openDB(cmd, cfg); derr == nil {
			if dom, gerr := getDomain(ctx(cmd), database, domain); gerr == nil && dom.DKIMSelector != "" {
				selectors = []string{dom.DKIMSelector}
			}
			database.Close()
		}
	}
	speculative := false
	if len(selectors) == 0 {
		selectors = commonAuditSelectors
		speculative = true // guessed set: skip selectors that do not exist
	}

	report, err := dnsaudit.New(cfg.DNS.Resolver, selectors, speculative).Audit(ctx(cmd), domain)
	if err != nil {
		return fmt.Errorf("dns audit %s: %w", domain, err)
	}
	if r.Format() == output.FormatJSON {
		return r.JSON(report)
	}
	pass, warn, fail := report.Counts()
	r.Message("%s — mail-security audit: %s (%d pass, %d warn, %d fail)",
		domain, strings.ToUpper(string(report.Grade())), pass, warn, fail)
	return r.StatusTable(dnsAuditTable(report), 1)
}

// auditTable renders a report as a coloured status table (status drives colour).
func dnsAuditTable(report dnsaudit.Report) output.Table {
	t := output.Table{Columns: []string{"Check", "Status", "Value", "Detail"}}
	for _, f := range report.Findings {
		t.Rows = append(t.Rows, []string{f.Check, string(f.Status), f.Value, f.Detail})
	}
	return t
}

// zoneManagerFor resolves the target provider and asserts it can host zones.
func (a *App) zoneManagerFor(cmd *cobra.Command, domain, provider string) (dnsprovider.ZoneManager, string, error) {
	cfg, secrets, err := a.Config()
	if err != nil {
		return nil, "", err
	}
	if provider == "" {
		database, derr := a.openDB(cmd, cfg)
		if derr != nil {
			return nil, "", derr
		}
		dom, derr := getDomain(ctx(cmd), database, domain)
		if derr != nil {
			return nil, "", derr
		}
		provider = dom.DNSProvider
	}
	p, err := newProvider(provider, secrets)
	if err != nil {
		return nil, "", err
	}
	zm, ok := p.(dnsprovider.ZoneManager)
	if !ok {
		return nil, "", fmt.Errorf("%w: provider %q cannot create zones (add the domain in its account first)", ErrUsage, provider)
	}
	return zm, provider, nil
}

// dnsZoneCreate creates the zone at the provider and prints the delegation info
// the operator must set at their registrar.
func (a *App) dnsZoneCreate(cmd *cobra.Command, rawDomain, provider string) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	domain, err := valid.Domain(rawDomain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	zm, prov, err := a.zoneManagerFor(cmd, domain, provider)
	if err != nil {
		return err
	}
	info, err := zm.EnsureZone(ctx(cmd), domain)
	if err != nil {
		return fmt.Errorf("dns zone create %s: %w", domain, err)
	}
	if info.Created {
		r.Message("created zone %s at %s", domain, prov)
	} else {
		r.Message("zone %s already exists at %s", domain, prov)
	}
	return r.Value(zoneInfoView(domain, info))
}

// zoneInfoView shapes ZoneInfo for rendering (delegation the operator must set).
func zoneInfoView(domain string, info dnsprovider.ZoneInfo) map[string]any {
	return map[string]any{
		"domain":               domain,
		"set_nameservers_to":   strings.Join(info.Nameservers, ", "),
		"publish_ds_at_parent": strings.Join(info.DS, " | "),
	}
}

// dnsMigrate copies a whole zone into an automated provider (njalla/desec) from
// one of three sources (AXFR / zonefile / provider API), to support moving a
// domain's DNS. It never deletes at the target and skips records already there.
func (a *App) dnsMigrate(cmd *cobra.Command, rawDomain, to, from, axfr, zonefile string, create, probe bool) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	cfg, secrets, err := a.Config()
	if err != nil {
		return err
	}
	domain, err := valid.Domain(rawDomain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	sources := 0
	for _, s := range []string{axfr, zonefile, from} {
		if s != "" {
			sources++
		}
	}
	if probe {
		sources++
	}
	if sources != 1 {
		return fmt.Errorf("%w: choose exactly one source (--axfr, --zonefile, --from or --probe)", ErrUsage)
	}

	// Pull the source records first — a dry-run then needs no target credentials.
	var records []dnsprovider.Record
	switch {
	case axfr != "":
		records, err = dnsprovider.PullAXFR(ctx(cmd), domain, axfr)
	case zonefile != "":
		records, err = readZonefile(domain, zonefile)
	case from != "":
		src, serr := newProvider(from, secrets)
		if serr != nil {
			return serr
		}
		records, err = src.ListRecords(ctx(cmd), domain)
	case probe:
		var selectors []string
		if database, derr := a.openDB(cmd, cfg); derr == nil {
			if dom, gerr := getDomain(ctx(cmd), database, domain); gerr == nil && dom.DKIMSelector != "" {
				selectors = append(selectors, dom.DKIMSelector)
			}
		}
		r.Message("probing public DNS for %s (best-effort; custom subdomains may be missed) ...", domain)
		records = dnsprovider.Discover(ctx(cmd), cfg.DNS.Resolver, domain, selectors)
	}
	if err != nil {
		return fmt.Errorf("dns migrate %s: %w", domain, err)
	}
	if len(records) == 0 {
		return fmt.Errorf("dns migrate %s: source returned no records", domain)
	}

	if a.flags.dryRun {
		r.Message("dry-run: %d record(s) found; would be copied to the target", len(records))
		return r.TypeTable(recordsTable(records), 0)
	}

	// Target provider: explicit --to, else the domain's dns_provider.
	if to == "" {
		database, derr := a.openDB(cmd, cfg)
		if derr != nil {
			return derr
		}
		dom, derr := getDomain(ctx(cmd), database, domain)
		if derr != nil {
			return derr
		}
		to = dom.DNSProvider
	}
	target, err := newProvider(to, secrets)
	if err != nil {
		return err
	}

	// Optionally create the zone at the target first (deSEC) and show delegation.
	if create {
		zm, ok := target.(dnsprovider.ZoneManager)
		if !ok {
			return fmt.Errorf("%w: provider %q cannot create zones (add the domain in its account first)", ErrUsage, to)
		}
		info, cerr := zm.EnsureZone(ctx(cmd), domain)
		if cerr != nil {
			return fmt.Errorf("dns migrate %s: create zone: %w", domain, cerr)
		}
		if info.Created {
			r.Message("created zone %s at %s", domain, to)
		}
		r.Message("delegation — set nameservers to: %s", strings.Join(info.Nameservers, ", "))
		if len(info.DS) > 0 {
			r.Message("DNSSEC — publish DS at parent: %s", strings.Join(info.DS, " | "))
		}
	}

	if err := a.confirm(fmt.Sprintf("Copy %d record(s) into %s at %s?", len(records), domain, to)); err != nil {
		return err
	}
	res, err := dnsprovider.Migrate(ctx(cmd), target, domain, records)
	if err != nil {
		return fmt.Errorf("dns migrate %s: %w", domain, err)
	}
	if rec, aerr := a.auditor(ctx(cmd)); aerr == nil {
		_ = rec.Record(ctx(cmd), "dns.migrate", domain, nil, map[string]any{
			"target": to, "created": len(res.Created), "skipped": len(res.Skipped), "failed": len(res.Failed),
		})
	}
	r.Message("migrated to %s: %d created, %d already present, %d failed",
		to, len(res.Created), len(res.Skipped), len(res.Failed))
	return r.StatusTable(migrateTable(res), 0)
}

// readZonefile opens and parses an operator-supplied BIND zone file.
func readZonefile(domain, path string) ([]dnsprovider.Record, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied path on a root CLI
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return dnsprovider.ParseZonefile(f, domain)
}

// migrateTable renders the per-record migration outcome.
func migrateTable(res dnsprovider.MigrateResult) output.Table {
	rows := make([][]string, 0, len(res.Created)+len(res.Skipped)+len(res.Failed))
	add := func(status string, recs []dnsprovider.Record) {
		for _, rec := range recs {
			rows = append(rows, []string{status, rec.Type, rec.Name, recordContent(rec)})
		}
	}
	add("created", res.Created)
	add("present", res.Skipped)
	add("failed", res.Failed)
	return output.Table{Columns: []string{"STATUS", "TYPE", "NAME", "CONTENT"}, Rows: rows}
}

// dnsBackends bundles everything the dns handlers need, opened once per command.
type dnsBackends struct {
	cfg      *config.Config
	db       *db.DB
	provider dnsprovider.Provider // nil when the domain is not on an automated provider
	mgr      *mail.Manager
	rec      *audit.Recorder
}

// dnsShow prints the desired mail record-set for a domain. It needs no registrar
// or DB write — only the DKIM key on disk and the domain's selector.
func (a *App) dnsShow(cmd *cobra.Command, rawDomain string, withMTASTS bool) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	cfg, _, err := a.Config()
	if err != nil {
		return err
	}
	domain, err := valid.Domain(rawDomain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	database, err := a.openDB(cmd, cfg)
	if err != nil {
		return err
	}
	defer database.Close()

	dom, err := getDomain(ctx(cmd), database, domain)
	if err != nil {
		return err
	}
	mgr := mail.New(a.sysRunner(), cfg.Mail.DKIMDir, cfg.Mail.Hostname, cfg.Server.IPv4, cfg.Server.IPv6)

	key, err := mgr.ReadDKIM(domain, dom.DKIMSelector)
	if err != nil {
		return fmt.Errorf("dns show %s: %w", domain, err)
	}
	recs := mgr.DesiredRecords(domain, dom.DKIMSelector, key.PublicKey, withMTASTS)
	return r.TypeTable(recordsTable(recs), 0)
}

// dnsCheck verifies live public DNS against the full desired record-set (the
// same set `dns show` prints), reporting per record whether it matches, drifts
// (old→new), or is missing — coloured, and covering MX/SPF/DMARC/DKIM/TLS-RPT/
// SRV/CNAME, not just the policy records.
func (a *App) dnsCheck(cmd *cobra.Command, rawDomain string) error {
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	cfg, _, err := a.Config()
	if err != nil {
		return err
	}
	domain, err := valid.Domain(rawDomain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	database, err := a.openDB(cmd, cfg)
	if err != nil {
		return err
	}
	dom, err := getDomain(ctx(cmd), database, domain)
	if err != nil {
		return err
	}

	mgr := mail.New(a.sysRunner(), cfg.Mail.DKIMDir, cfg.Mail.Hostname, cfg.Server.IPv4, cfg.Server.IPv6)
	key, err := mgr.ReadDKIM(domain, dom.DKIMSelector)
	if err != nil {
		return fmt.Errorf("dns check %s: %w", domain, err)
	}
	// withMTASTS=false: verify everything incl. the mta-sts host records, but do
	// not demand the _mta-sts policy TXT (only relevant once MTA-STS is activated
	// via `dns publish --with-mta-sts`).
	desired := mgr.DesiredRecords(domain, dom.DKIMSelector, key.PublicKey, false)

	live, err := dnscheck.New(cfg.DNS.Resolver, cfg.Mail.Hostname, cfg.Mail.DefaultSelector).
		ResolveLive(ctx(cmd), domain, desired)
	if err != nil {
		return fmt.Errorf("dns check %s: %w", domain, err)
	}
	plan := dnsprovider.Plan(live, desired)
	match := len(plan) - countMutating(plan)
	r.Message("%s — public DNS: %d of %d records correct", domain, match, len(plan))
	return r.StatusTable(njallaCheckTable(plan), 0)
}

// dnsCheckNjalla compares the desired mail record-set against the records that
// are actually live at the Njalla registrar (via the API, not public DNS) and
// reports, per record, whether it matches, drifts (old→new), or is missing. It
// also lists stale records (present at the zone but not part of the mail set)
// and, on an interactive terminal, offers to delete a selection of them.
func (a *App) dnsCheckNjalla(cmd *cobra.Command, rawDomain string, withMTASTS bool) error {
	be, domain, err := a.dnsMutableBackends(cmd, rawDomain, true)
	if err != nil {
		return err
	}
	defer be.db.Close()
	r, err := a.Renderer()
	if err != nil {
		return err
	}

	desired, err := a.desiredRecords(cmd, be, domain, withMTASTS)
	if err != nil {
		return err
	}
	live, err := be.provider.ListRecords(ctx(cmd), domain)
	if err != nil {
		return fmt.Errorf("dns check %s: list at %s: %w", domain, be.provider.Name(), err)
	}

	plan := dnsprovider.Plan(live, desired)
	match := len(plan) - countMutating(plan)
	r.Message("%s @ %s — mail records: %d match, %d to change",
		domain, be.provider.Name(), match, countMutating(plan))
	if err := r.StatusTable(njallaCheckTable(plan), 0); err != nil {
		return err
	}

	stale := dnsprovider.Stale(live, desired, false)
	if len(stale) == 0 {
		return nil
	}
	r.Message("\n%d other record(s) at the zone are not part of the mail set:", len(stale))
	if err := r.StatusTable(staleTable(stale), 0); err != nil {
		return err
	}
	return a.offerStaleDelete(cmd, be, domain, stale, r)
}

// offerStaleDelete lets the operator interactively pick stale records to remove.
// It only prompts on a real terminal with table output and no --dry-run; every
// deletion is confirmed by the selection itself and written to the audit log.
func (a *App) offerStaleDelete(cmd *cobra.Command, be *dnsBackends, domain string, stale []dnsprovider.Record, r *output.Renderer) error {
	if a.flags.dryRun || !a.interactive() || r.Format() != output.FormatTable {
		r.Message("(run `mailadmin dns takeover %s` to back up and replace the whole zone)", domain)
		return nil
	}
	labels := make([]string, len(stale))
	for i, rec := range stale {
		labels[i] = fmt.Sprintf("%-5s %-22s %s", rec.Type, rec.Name, rec.Content)
	}
	sel, err := a.selectIndices("Delete which stale records?", labels)
	if err != nil {
		return err
	}
	if len(sel) == 0 {
		return nil
	}
	if err := a.confirm(fmt.Sprintf("Delete %d record(s) from %s at %s?", len(sel), domain, be.provider.Name())); err != nil {
		return err
	}
	deleted := make([]dnsprovider.Record, 0, len(sel))
	for _, i := range sel {
		rec := stale[i]
		if rec.ID == "" {
			continue
		}
		if err := be.provider.RemoveRecord(ctx(cmd), domain, rec.ID); err != nil {
			return fmt.Errorf("delete %s %s: %w", rec.Type, rec.Name, err)
		}
		deleted = append(deleted, rec)
	}
	if err := be.rec.Record(ctx(cmd), "dns.prune", domain, deleted, nil); err != nil {
		return err
	}
	r.Message("deleted %d stale record(s) from %s", len(deleted), domain)
	return nil
}

// dnsPublish reconciles the desired mail record-set at the registrar. It only
// works for domains whose dns_provider is an automated backend; it confirms
// before mutating, honours --dry-run, guards MTA-STS behind readiness, and
// writes an audit record on success.
func (a *App) dnsPublish(cmd *cobra.Command, rawDomain string, withMTASTS bool) error {
	be, domain, err := a.dnsMutableBackends(cmd, rawDomain, true)
	if err != nil {
		return err
	}
	defer be.db.Close()
	r, err := a.Renderer()
	if err != nil {
		return err
	}

	desired, err := a.desiredRecords(cmd, be, domain, withMTASTS)
	if err != nil {
		return err
	}

	if a.flags.dryRun {
		live, err := be.provider.ListRecords(ctx(cmd), domain)
		if err != nil {
			return fmt.Errorf("dns publish %s: list: %w", domain, err)
		}
		plan := dnsprovider.Plan(live, desired)
		r.Message("dry-run: %d record(s) planned for %s", countMutating(plan), domain)
		return r.Table(changesTable(plan))
	}

	if err := a.confirm(fmt.Sprintf("Publish mail DNS for %s at %s?", domain, be.provider.Name())); err != nil {
		return err
	}

	applied, err := dnsprovider.Reconcile(ctx(cmd), be.provider, domain, desired)
	if err != nil {
		return fmt.Errorf("dns publish %s: %w", domain, err)
	}
	if err := be.rec.Record(ctx(cmd), "dns.publish", domain, nil, changeSummary(applied)); err != nil {
		return err
	}
	r.Message("published %d change(s) for %s", len(applied), domain)
	return r.Table(changesTable(applied))
}

// dnsTakeover snapshots the whole zone then replaces every record with the mail
// record-set. Destructive: it confirms, honours --dry-run, and backs up first
// (ReplaceAll writes the snapshot before removing anything).
func (a *App) dnsTakeover(cmd *cobra.Command, rawDomain string, keepWeb, withMTASTS bool) error {
	be, domain, err := a.dnsMutableBackends(cmd, rawDomain, true)
	if err != nil {
		return err
	}
	defer be.db.Close()
	r, err := a.Renderer()
	if err != nil {
		return err
	}

	desired, err := a.desiredRecords(cmd, be, domain, withMTASTS)
	if err != nil {
		return err
	}

	if a.flags.dryRun {
		live, err := be.provider.ListRecords(ctx(cmd), domain)
		if err != nil {
			return fmt.Errorf("dns takeover %s: list: %w", domain, err)
		}
		removed := plannedRemovals(live, keepWeb)
		r.Message("dry-run: takeover of %s would remove %d and add %d record(s) (backup taken first)",
			domain, len(removed), len(desired))
		return r.Table(recordsTable(desired))
	}

	warn := fmt.Sprintf("TAKEOVER replaces the ENTIRE %s zone at %s (a backup is saved first)", domain, be.provider.Name())
	if keepWeb {
		warn += "; apex/www web records are preserved"
	}
	if err := a.confirm(warn + ". Continue?"); err != nil {
		return err
	}

	res, err := dnsprovider.ReplaceAll(ctx(cmd), be.provider, domain, be.cfg.Backup.DNSBackupDir, desired, keepWeb)
	if err != nil {
		return fmt.Errorf("dns takeover %s: %w", domain, err)
	}
	if err := be.rec.Record(ctx(cmd), "dns.takeover", domain, nil, res); err != nil {
		return err
	}
	r.Message("takeover of %s complete: removed %d, added %d, backup %s",
		domain, len(res.Removed), len(res.Added), res.BackupPath)
	return r.Table(recordsTable(res.Added))
}

// dnsRestore wipes the current zone and re-adds every record from a snapshot.
func (a *App) dnsRestore(cmd *cobra.Command, rawDomain, backupPath string) error {
	be, domain, err := a.dnsMutableBackends(cmd, rawDomain, true)
	if err != nil {
		return err
	}
	defer be.db.Close()
	r, err := a.Renderer()
	if err != nil {
		return err
	}

	snap, err := dnsprovider.LoadSnapshot(backupPath)
	if err != nil {
		return fmt.Errorf("dns restore: load snapshot: %w", err)
	}
	if snapDomain, derr := valid.Domain(snap.Domain); derr != nil || snapDomain != domain {
		return fmt.Errorf("%w: snapshot is for %q, not %q", ErrUsage, snap.Domain, domain)
	}

	if a.flags.dryRun {
		r.Message("dry-run: restore would replace the %s zone with %d record(s) from %s",
			domain, len(snap.Records), backupPath)
		return r.Table(recordsTable(snap.Records))
	}

	if err := a.confirm(fmt.Sprintf("Restore %s zone from %s, discarding current records. Continue?", domain, backupPath)); err != nil {
		return err
	}

	if err := dnsprovider.Restore(ctx(cmd), be.provider, domain, snap); err != nil {
		return fmt.Errorf("dns restore %s: %w", domain, err)
	}
	if err := be.rec.Record(ctx(cmd), "dns.restore", domain, nil, map[string]any{
		"backup":  backupPath,
		"records": len(snap.Records),
	}); err != nil {
		return err
	}
	r.Message("restored %d record(s) for %s from %s", len(snap.Records), domain, backupPath)
	return r.Table(recordsTable(snap.Records))
}

// dnsMutableBackends validates the domain, opens the DB, verifies the domain is
// on an automated provider, and builds the registrar client + audit recorder.
// requireProvider must be true for mutating commands.
func (a *App) dnsMutableBackends(cmd *cobra.Command, rawDomain string, requireProvider bool) (*dnsBackends, string, error) {
	cfg, secrets, err := a.Config()
	if err != nil {
		return nil, "", err
	}
	domain, err := valid.Domain(rawDomain)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrUsage, err)
	}
	database, err := a.openDB(cmd, cfg)
	if err != nil {
		return nil, "", err
	}
	dom, err := getDomain(ctx(cmd), database, domain)
	if err != nil {
		database.Close()
		return nil, "", err
	}

	provider, err := newProvider(dom.DNSProvider, secrets)
	if err != nil {
		database.Close()
		if requireProvider {
			return nil, "", err
		}
	}

	be := &dnsBackends{
		cfg:      cfg,
		db:       database,
		provider: provider,
		mgr:      mail.New(a.sysRunner(), cfg.Mail.DKIMDir, cfg.Mail.Hostname, cfg.Server.IPv4, cfg.Server.IPv6),
		rec:      audit.New(database, audit.CurrentActor()),
	}
	return be, domain, nil
}

// desiredRecords reads the domain's DKIM key and builds the desired record-set,
// applying the MTA-STS readiness guard when requested.
func (a *App) desiredRecords(cmd *cobra.Command, be *dnsBackends, domain string, withMTASTS bool) ([]dnsprovider.Record, error) {
	dom, err := getDomain(ctx(cmd), be.db, domain)
	if err != nil {
		return nil, err
	}
	key, err := be.mgr.ReadDKIM(domain, dom.DKIMSelector)
	if err != nil {
		return nil, fmt.Errorf("dns: %w", err)
	}
	if withMTASTS {
		if err := mtaStsReady(ctx(cmd), domain); err != nil {
			return nil, fmt.Errorf("%w: refusing to publish MTA-STS: %v", ErrUsage, err)
		}
	}
	return be.mgr.DesiredRecords(domain, dom.DKIMSelector, key.PublicKey, withMTASTS), nil
}

// newProvider builds the registrar client for a domain's dns_provider value.
// Only "njalla" is automated today; anything else is a manual zone.
func newProvider(dnsProvider string, secrets *config.Secrets) (dnsprovider.Provider, error) {
	switch strings.ToLower(strings.TrimSpace(dnsProvider)) {
	case dnsProviderNjalla:
		if !secrets.HasNjalla() {
			return nil, fmt.Errorf("%w: NJALLA_TOKEN is not configured in secrets.env", ErrUsage)
		}
		return dnsprovider.NewNjalla(secrets.NjallaToken()), nil
	case dnsProviderDeSEC:
		if !secrets.HasDeSEC() {
			return nil, fmt.Errorf("%w: DESEC_TOKEN is not configured in secrets.env", ErrUsage)
		}
		return dnsprovider.NewDeSEC(secrets.DeSECToken()), nil
	default:
		return nil, fmt.Errorf("%w (dns_provider=%q); manage its zone manually or set it to %q or %q",
			errManualDNS, dnsProvider, dnsProviderNjalla, dnsProviderDeSEC)
	}
}

// automatedDNS reports whether a dns_provider value has registrar automation.
func automatedDNS(p string) bool {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case dnsProviderNjalla, dnsProviderDeSEC:
		return true
	}
	return false
}

// getDomain loads a domain row, mapping the not-found case to ErrNotFound.
func getDomain(c context.Context, database *db.DB, domain string) (db.Domain, error) {
	dom, err := database.GetDomain(c, domain)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.Domain{}, fmt.Errorf("%w: domain %q", ErrNotFound, domain)
		}
		return db.Domain{}, fmt.Errorf("lookup domain %q: %w", domain, err)
	}
	return dom, nil
}

// openDB returns the shared pool. It delegates to App.db so PGSERVICEFILE is set
// from config and the connection is reused (and closed once at exit).
func (a *App) openDB(cmd *cobra.Command, _ *config.Config) (*db.DB, error) {
	database, err := a.db(ctx(cmd))
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}
	return database, nil
}

// sysRunner builds a privileged-exec runner (the mail.Manager uses it for the
// DKIM helper). Every invocation still goes through internal/sys — no shell.
func (a *App) sysRunner() *sys.Runner {
	return sys.New(sys.DefaultTimeout, nil)
}

// mtaStsReady probes the domain's MTA-STS policy endpoint over verified HTTPS and
// requires an enforce-mode policy before MTA-STS records may be advertised. This
// is the "enforce guard" from REQUIREMENTS: never publish a policy that is not
// actually live, or receivers will start bouncing mail. The URL host is derived
// solely from the validated domain, so it is not user-controlled (no SSRF).
func mtaStsReady(c context.Context, domain string) error {
	url := "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	req, err := http.NewRequestWithContext(c, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("policy endpoint %s not reachable: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("policy endpoint %s returned HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	if !policyEnforces(string(body)) {
		return fmt.Errorf("policy at %s is not mode: enforce", url)
	}
	return nil
}

// policyEnforces reports whether an MTA-STS policy body declares enforce mode.
func policyEnforces(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), "mode") &&
			strings.EqualFold(strings.TrimSpace(v), "enforce") {
			return true
		}
	}
	return false
}

// countMutating counts non-"unchanged" changes in a plan.
func countMutating(changes []dnsprovider.Change) int {
	n := 0
	for _, c := range changes {
		if c.Op != dnsprovider.OpUnchanged {
			n++
		}
	}
	return n
}

// plannedRemovals returns the live records a takeover would delete, honouring
// keepWeb (mirrors dnsprovider's apex/www protection) for the dry-run preview.
func plannedRemovals(live []dnsprovider.Record, keepWeb bool) []dnsprovider.Record {
	out := make([]dnsprovider.Record, 0, len(live))
	for _, r := range live {
		if r.ID == "" {
			continue
		}
		if keepWeb && isApexWebRecord(r) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// isApexWebRecord mirrors dnsprovider's apex/www web-record test for previews.
func isApexWebRecord(r dnsprovider.Record) bool {
	name := strings.ToLower(strings.TrimSpace(r.Name))
	if name == "" {
		name = "@"
	}
	if name != "@" && name != "www" {
		return false
	}
	switch strings.ToUpper(r.Type) {
	case "A", "AAAA", "CNAME":
		return true
	}
	return false
}

// changeSummary reduces applied changes to an audit-friendly, secret-free shape.
func changeSummary(changes []dnsprovider.Change) []map[string]string {
	out := make([]map[string]string, 0, len(changes))
	for _, c := range changes {
		out = append(out, map[string]string{
			"op":      c.Op,
			"type":    c.Record.Type,
			"name":    c.Record.Name,
			"content": c.Record.Content,
		})
	}
	return out
}

// recordsTable renders a desired/live record-set.
func recordsTable(recs []dnsprovider.Record) output.Table {
	sorted := append([]dnsprovider.Record(nil), recs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		oi, oj := recordTypeOrder(sorted[i].Type), recordTypeOrder(sorted[j].Type)
		if oi != oj {
			return oi < oj
		}
		if !strings.EqualFold(sorted[i].Name, sorted[j].Name) {
			return strings.ToLower(sorted[i].Name) < strings.ToLower(sorted[j].Name)
		}
		return recordContent(sorted[i]) < recordContent(sorted[j])
	})
	rows := make([][]string, 0, len(sorted))
	for _, r := range sorted {
		rows = append(rows, []string{r.Type, r.Name, strconv.Itoa(r.Prio), recordContent(r)})
	}
	return output.Table{Columns: []string{"TYPE", "NAME", "PRIO", "CONTENT"}, Rows: rows}
}

// recordTypeOrder groups DNS record types into a stable, sensible display order
// (host records, aliases, mail, policy TXT, services, then the rest).
func recordTypeOrder(rtype string) int {
	switch strings.ToUpper(rtype) {
	case "A":
		return 0
	case "AAAA":
		return 1
	case "CNAME":
		return 2
	case "MX":
		return 3
	case "TXT":
		return 4
	case "SRV":
		return 5
	case "CAA":
		return 6
	case "NS":
		return 7
	default:
		return 8
	}
}

// recordContent renders a record's value for display. SRV records expand to
// "weight port target" (priority is shown in its own column) so the endpoint is
// legible instead of just the bare target host.
func recordContent(r dnsprovider.Record) string {
	if strings.EqualFold(r.Type, "SRV") {
		// prio weight port target — prio included so a priority-only drift is visible.
		return fmt.Sprintf("%d %d %d %s", r.Prio, r.Weight, r.Port, r.Content)
	}
	return r.Content
}

// staleStatus labels a stale record. Old DKIM keys (any selector, delegated as a
// CNAME or published as TXT under *._domainkey) are called out as "dkim-old" so
// the operator recognises a foreign provider's signing records among the stale.
func staleStatus(r dnsprovider.Record) string {
	if strings.HasSuffix(strings.ToLower(r.Name), "._domainkey") {
		return "dkim-old"
	}
	return "stale"
}

// changesTable renders a reconcile plan / applied change-set.
func changesTable(changes []dnsprovider.Change) output.Table {
	rows := make([][]string, 0, len(changes))
	for _, c := range changes {
		rows = append(rows, []string{c.Op, c.Record.Type, c.Record.Name, c.Record.Content})
	}
	return output.Table{Columns: []string{"OP", "TYPE", "NAME", "CONTENT"}, Rows: rows}
}

// njallaCheckTable renders a Plan as a read-only status view showing, per
// desired record, whether it is a match, a drift (with the current value), or
// missing at the registrar.
func njallaCheckTable(changes []dnsprovider.Change) output.Table {
	status := map[string]string{
		dnsprovider.OpUnchanged: "match",
		dnsprovider.OpEdit:      "drift",
		dnsprovider.OpAdd:       "missing",
		dnsprovider.OpDelete:    "remove",
	}
	rows := make([][]string, 0, len(changes))
	for _, c := range changes {
		st := status[c.Op]
		if st == "" {
			st = c.Op
		}
		typ, name := c.Record.Type, c.Record.Name
		current, desired := "—", recordContent(c.Record)
		if c.Current != nil {
			current = recordContent(*c.Current)
			typ, name = c.Current.Type, c.Current.Name
		}
		if c.Op == dnsprovider.OpDelete { // superfluous live record; nothing desired
			desired = "(remove — duplicate in slot)"
		}
		rows = append(rows, []string{st, typ, name, current, desired})
	}
	return output.Table{Columns: []string{"STATUS", "TYPE", "NAME", "CURRENT", "DESIRED"}, Rows: rows}
}

// staleTable lists records live at the zone that are not part of the mail set.
func staleTable(stale []dnsprovider.Record) output.Table {
	rows := make([][]string, 0, len(stale))
	for _, rec := range stale {
		rows = append(rows, []string{staleStatus(rec), rec.Type, rec.Name, recordContent(rec)})
	}
	return output.Table{Columns: []string{"STATUS", "TYPE", "NAME", "CONTENT"}, Rows: rows}
}

// resultsTable renders live DNS verification results.
