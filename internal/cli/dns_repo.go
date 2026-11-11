package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"mailadmin/internal/dnsrepo"
	"mailadmin/internal/valid"
)

// dnsStateDir holds the pending repository changes, one file per domain.
const dnsStateDir = "/var/lib/mailadmin"

func dnsStatePath(domain string) string {
	return filepath.Join(dnsStateDir, ".dns-repo-tlsa-"+domain+".json")
}

func newDNSTLSAPRCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "tlsa-pr <domain>",
		Short: "Propose the mail host's TLSA record as a pull request in dns.config_repo",
		Long: "Writes the TLSA record of the mail host (from its certificate) into the\n" +
			"mailadmin block of dnsconfig.js on a new branch, commits, pushes and opens a\n" +
			"pull request. The change is not merged here. `dns tlsa-status` reports when\n" +
			"the merged record is live.",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error { return app.dnsTLSAPR(c, args[0]) },
	}
}

func newDNSTLSAStatusCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "tlsa-status <domain>",
		Short: "Check a proposed TLSA change: exit 0 when merged and live, 5 while pending",
		Long: "Exit codes: 0 the record is merged and live (the pending state is cleared),\n" +
			"5 still pending (open, or merged but not yet visible at the provider),\n" +
			"3 no pending change, 1 the pull request was closed unmerged (state cleared).",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error { return app.dnsTLSAStatus(c, args[0]) },
	}
}

// dnsTLSAPR proposes the TLSA change for domain as a pull request.
func (a *App) dnsTLSAPR(cmd *cobra.Command, rawDomain string) error {
	cfg, _, err := a.Config()
	if err != nil {
		return err
	}
	if cfg.DNS.ConfigRepo == "" {
		return fmt.Errorf("%w: dns.config_repo is not set", ErrUsage)
	}
	domain, err := valid.Domain(rawDomain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	if pending, ok, err := dnsrepo.LoadState(dnsStatePath(domain)); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("a TLSA change for %s is already pending (PR %s): merge it or close it first", domain, pending.PR)
	}

	rec, res, err := a.daneRecord(ctx(cmd), cfg, domain)
	if err != nil {
		return fmt.Errorf("tlsa-pr %s: %w", domain, err)
	}
	usage, selector, matching, digest, err := parseTLSA(res.Value)
	if err != nil {
		return fmt.Errorf("tlsa-pr %s: %w", domain, err)
	}
	if a.flags.dryRun {
		r.Message("dry-run: would propose TLSA %s %s in %s", rec.Name, res.Value, cfg.DNS.ConfigRepo)
		return nil
	}
	if err := a.confirm(fmt.Sprintf("Propose TLSA %s (%s) for %s as a pull request?", rec.Name, res.Value, domain)); err != nil {
		return err
	}
	title := "dns: TLSA for " + domain + " mail host"
	body := "Certificate of " + cfg.Mail.Hostname + " (" + res.Source + "). Proposed by mailadmin; merge after review, the certificate is installed once the record is live."
	prop, err := dnsrepo.Repo{Dir: cfg.DNS.ConfigRepo}.Propose(ctx(cmd), domain, rec.Name, usage, selector, matching, digest, title, body)
	if errors.Is(err, dnsrepo.ErrUnchanged) {
		r.Message("TLSA for %s is already current in %s", domain, cfg.DNS.ConfigRepo)
		return nil
	}
	if err != nil {
		return fmt.Errorf("tlsa-pr %s: %w", domain, err)
	}
	pr := prop.URL[strings.LastIndex(prop.URL, "/")+1:]
	if err := dnsrepo.SaveState(dnsStatePath(domain), dnsrepo.State{Domain: domain, PR: pr, Branch: prop.Branch, TLSA: res.Value}); err != nil {
		return fmt.Errorf("tlsa-pr %s: pull request %s is open but its state was not saved: %w", domain, prop.URL, err)
	}
	r.Message("pull request for TLSA %s: %s", domain, prop.URL)
	return nil
}

// dnsTLSAStatus reports whether a proposed TLSA change is merged and live.
func (a *App) dnsTLSAStatus(cmd *cobra.Command, rawDomain string) error {
	cfg, _, err := a.Config()
	if err != nil {
		return err
	}
	if cfg.DNS.ConfigRepo == "" {
		return fmt.Errorf("%w: dns.config_repo is not set", ErrUsage)
	}
	domain, err := valid.Domain(rawDomain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	r, err := a.Renderer()
	if err != nil {
		return err
	}
	path := dnsStatePath(domain)
	pending, ok, err := dnsrepo.LoadState(path)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: no pending TLSA change for %s", ErrNotFound, domain)
	}
	repo := dnsrepo.Repo{Dir: cfg.DNS.ConfigRepo}
	prState, err := repo.PRState(ctx(cmd), pending.PR)
	if err != nil {
		return fmt.Errorf("tlsa-status %s: %w", domain, err)
	}
	switch prState {
	case "CLOSED":
		if err := dnsrepo.ClearState(path); err != nil {
			return err
		}
		return fmt.Errorf("pull request %s was closed without merging, pending change for %s dropped", pending.PR, domain)
	case "MERGED":
	default:
		return fmt.Errorf("%w: pull request %s is %s", ErrPending, pending.PR, strings.ToLower(prState))
	}

	be, _, err := a.dnsMutableBackends(cmd, domain, true)
	if err != nil {
		return err
	}
	sub, err := daneSubname(cfg.Mail.Hostname, domain)
	if err != nil {
		return err
	}
	live, err := be.provider.ListRecords(ctx(cmd), domain)
	if err != nil {
		return fmt.Errorf("tlsa-status %s: list records: %w", domain, err)
	}
	for _, rec := range live {
		if rec.Type == "TLSA" && rec.Name == sub && sameTLSA(rec.Content, pending.TLSA) {
			if err := dnsrepo.ClearState(path); err != nil {
				return err
			}
			r.Message("TLSA for %s is merged and live", domain)
			return nil
		}
	}
	return fmt.Errorf("%w: pull request %s is merged, TLSA not live at %s yet", ErrPending, pending.PR, be.provider.Name())
}

// parseTLSA splits "usage selector matching hex" into its parts.
func parseTLSA(value string) (usage, selector, matching int, digest string, err error) {
	f := strings.Fields(value)
	if len(f) != 4 {
		return 0, 0, 0, "", fmt.Errorf("TLSA value %q is not usage selector matching digest", value)
	}
	if usage, err = strconv.Atoi(f[0]); err != nil {
		return 0, 0, 0, "", err
	}
	if selector, err = strconv.Atoi(f[1]); err != nil {
		return 0, 0, 0, "", err
	}
	if matching, err = strconv.Atoi(f[2]); err != nil {
		return 0, 0, 0, "", err
	}
	return usage, selector, matching, strings.ToLower(f[3]), nil
}

// sameTLSA compares two TLSA values, ignoring spacing and hex case.
func sameTLSA(a, b string) bool {
	return strings.EqualFold(strings.Join(strings.Fields(a), " "), strings.Join(strings.Fields(b), " "))
}
