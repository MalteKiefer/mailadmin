package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"mailadmin/internal/config"
	"mailadmin/internal/db"
	"mailadmin/internal/install"
	"mailadmin/internal/sys"
	"mailadmin/internal/webserver"
)

// installTimeout bounds one external command during install. apt and the
// PostgreSQL package build are slow, so this is far above the default.
const installTimeout = 15 * time.Minute

// installBinaryPath is where the mailadmin binary is installed.
const installBinaryPath = "/usr/local/sbin/mailadmin"

// installConfigDir holds config.toml and secrets.env.
const installConfigDir = "/etc/mailadmin"

type installInputs struct {
	hostname, domain, ipv4, ipv6, selector string
	adopt                                  bool
	pgdgFingerprint, caddyFingerprint      string
	tls                                    string
}

func newInstallCmd(app *App) *cobra.Command {
	var in installInputs
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install and configure the whole mail stack on this Ubuntu or Debian host",
		Long: `Installs PostgreSQL and Caddy from their upstream apt repositories, Postfix,
Dovecot, rspamd and nftables from the distribution, creates the mailadmin
database and service accounts, and writes /etc/mailadmin/config.toml with a
generated secrets.env. It refuses to run on a host that already has mail-stack
state unless --adopt is given. --dry-run prints the plan and changes nothing.

Repository keys are checked against the fingerprint you confirm. Find the
published fingerprint on the vendor's page (PostgreSQL: postgresql.org/download
for Debian and Ubuntu, Caddy: caddyserver.com/docs/install) and type it when
asked, or pass it with --pgdg-fingerprint / --caddy-fingerprint.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runInstall(app, c, &in)
		},
	}
	f := cmd.Flags()
	f.StringVar(&in.hostname, "hostname", "", "mail host FQDN, e.g. mx.example.com (asked if omitted)")
	f.StringVar(&in.domain, "domain", "", "primary mail domain (asked if omitted)")
	f.StringVar(&in.ipv4, "ipv4", "", "public IPv4 of this host (asked if omitted)")
	f.StringVar(&in.ipv6, "ipv6", "", "public IPv6 of this host (optional)")
	f.StringVar(&in.selector, "selector", "", "default DKIM selector (default mail<year>)")
	f.BoolVar(&in.adopt, "adopt", false, "install on a host that already has mail-stack state; keep existing files")
	f.StringVar(&in.pgdgFingerprint, "pgdg-fingerprint", "", "expected fingerprint of the PostgreSQL repository key")
	f.StringVar(&in.caddyFingerprint, "caddy-fingerprint", "", "expected fingerprint of the Caddy repository key")
	f.StringVar(&in.tls, "tls", "acme", "certificate for the mail host: acme (public, needs DNS and ports 80/443) or internal (Caddy local CA, testing only)")
	return cmd
}

func runInstall(app *App, c *cobra.Command, in *installInputs) error {
	out := c.OutOrStdout()
	if runtime.GOOS != "linux" {
		return fmt.Errorf("%w: install runs on linux only", install.ErrUnsupported)
	}
	if err := install.CheckArch(runtime.GOARCH); err != nil {
		return err
	}
	osr, err := os.Open("/etc/os-release") // #nosec G304 -- fixed system path
	if err != nil {
		return fmt.Errorf("read os-release: %w", err)
	}
	distro, err := install.ParseOSRelease(osr)
	_ = osr.Close()
	if err != nil {
		return err
	}
	if !app.flags.dryRun && os.Geteuid() != 0 {
		return errors.New("install must run as root (try: sudo mailadmin install)")
	}

	if in.tls != "acme" && in.tls != "internal" {
		return fmt.Errorf("%w: --tls must be acme or internal", ErrUsage)
	}
	sr := sys.New(installTimeout, nil)
	x := install.Resolve(sr)
	conflicts := install.Conflicts(ctx(c), x, "/")
	if len(conflicts) > 0 && !in.adopt {
		return fmt.Errorf("host already has mail-stack state (%s): rerun with --adopt to keep it, or install on a fresh host",
			strings.Join(conflicts, ", "))
	}

	ans, err := collectAnswers(app, in)
	if err != nil {
		return err
	}
	if err := ans.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrUsage, err)
	}

	printInstallPlan(out, distro, ans, conflicts)
	if app.flags.dryRun {
		_, err := fmt.Fprintln(out, "dry-run: no changes made")
		return err
	}
	if err := app.confirm("install and configure the mail stack on " + ans.Hostname + "?"); err != nil {
		return err
	}

	pctx := ctx(c)
	if err := install.AptUpdate(pctx, x); err != nil {
		return err
	}
	if err := install.AptInstall(pctx, x, []string{"ca-certificates", "curl", "gnupg", "debconf-utils"}, ans.Hostname); err != nil {
		return err
	}

	repos := []struct {
		repo     install.Repo
		expected string
	}{
		{install.PostgresRepo(distro.Codename), in.pgdgFingerprint},
		{install.CaddyRepo(), in.caddyFingerprint},
	}
	for _, r := range repos {
		if err := addRepo(app, c, x, r.repo, r.expected); err != nil {
			return err
		}
	}

	if err := install.AptUpdate(pctx, x); err != nil {
		return err
	}
	pkgs := append(install.DistroPackages(), install.VendorPackages()...)
	if err := install.CheckDovecotVersion(pctx, x); err != nil {
		return err
	}
	if err := install.AptInstall(pctx, x, pkgs, ans.Hostname); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(out, "packages installed")

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate running binary: %w", err)
	}
	if err := install.InstallBinary(exe, installBinaryPath); err != nil {
		return err
	}

	if err := install.EnsureUser(pctx, x, "mailadmin", "/var/lib/mailadmin", 0); err != nil {
		return err
	}
	if err := install.EnsureUser(pctx, x, "vmail", "/var/vmail", 5000); err != nil {
		return err
	}
	if err := install.EnsureHostDirs(pctx, x); err != nil {
		return err
	}

	if err := install.EnableService(pctx, x, "postgresql"); err != nil {
		return err
	}
	for _, role := range install.PgRoles {
		if err := install.EnsureRole(pctx, x, role); err != nil {
			return err
		}
	}
	if err := install.EnsureDatabase(pctx, x, install.PgDatabase, "mailadmin"); err != nil {
		return err
	}
	if err := install.ApplyMigrations(pctx, x, in.adopt); err != nil {
		return err
	}
	if err := install.EnablePeerMap(pctx, x); err != nil {
		return err
	}
	if err := install.WritePgServiceFile(install.PgServiceFile); err != nil {
		return err
	}

	if err := install.WriteConfig(installConfigDir, ans); err != nil {
		if !in.adopt || !errors.Is(err, install.ErrExists) {
			return err
		}
		_, _ = fmt.Fprintln(out, "kept existing config (--adopt)")
	}

	if err := installMailStack(app, c, in, ans, x, sr, out); err != nil {
		return err
	}
	return nil
}

// installMailStack configures Postfix, Dovecot, rspamd, Caddy and the firewall,
// creates the domain with its DKIM key, and starts the daemons. Every step is
// idempotent, so rerunning with --adopt converges the host to the same state.
func installMailStack(app *App, c *cobra.Command, in *installInputs, ans install.Answers, x install.Exec, sr *sys.Runner, out io.Writer) error {
	pctx := ctx(c)
	secrets, err := config.LoadSecrets(filepath.Join(installConfigDir, config.SecretsFile))
	if err != nil {
		return err
	}
	if err := install.ApplyPostfix(pctx, x, ans.Hostname); err != nil {
		return err
	}
	if err := install.ApplyDovecot(pctx, x); err != nil {
		return err
	}
	if err := install.InstallHelpers(pctx, x, ans.Hostname, ans.Domain); err != nil {
		return err
	}

	database, err := app.db(pctx)
	if err != nil {
		return err
	}
	if err := database.CreateDomain(pctx, ans.Domain, ans.Selector); err != nil {
		if !errors.Is(err, db.ErrExists) {
			return err
		}
		// The row existed before install (created by hand or by an earlier partial
		// run). Fill in a missing selector, never replace one that is set.
		existing, gerr := database.GetDomain(pctx, ans.Domain)
		if gerr != nil {
			return gerr
		}
		if existing.DKIMSelector == "" {
			if err := database.SetDKIMSelector(pctx, ans.Domain, ans.Selector); err != nil {
				return err
			}
		} else {
			// rspamd signs with the stored selector, so the key and DNS output must use it too.
			ans.Selector = existing.DKIMSelector
		}
	}
	if _, err := x.Run(pctx, nil, install.DKIMGenHelperPath, ans.Domain, ans.Selector); err != nil {
		return fmt.Errorf("generate DKIM key for %s: %w", ans.Domain, err)
	}
	domains, err := database.ListDomains(pctx)
	if err != nil {
		return err
	}
	var pairs [][2]string
	var names, active []string
	for _, d := range domains {
		names = append(names, d.Name)
		if !d.Active {
			continue
		}
		pairs = append(pairs, [2]string{d.Name, d.DKIMSelector})
		active = append(active, d.Name)
	}
	if err := install.ApplyRspamd(pctx, x, secrets.RspamdControllerPW(), pairs); err != nil {
		return err
	}
	if err := install.ApplyCaddy(pctx, x, ans.Hostname, in.tls == "internal"); err != nil {
		return err
	}
	if err := install.ApplyFirewall(pctx, x); err != nil {
		return err
	}
	if err := install.EnableUnit(pctx, x, "caddy"); err != nil {
		return err
	}
	if err := install.ApplyAutoconfig(ans.Hostname); err != nil {
		return err
	}
	wm := webserver.New(sr, "", "", "", "")
	if err := wm.Sync(pctx, names); err != nil {
		return fmt.Errorf("autodiscovery include: %w", err)
	}
	// Autodiscovery covers every domain. MTA-STS advertises an enforce policy, so only active domains get it.
	// The policy file must exist before the vhost serves it, or the endpoint answers 404.
	if len(active) > 0 {
		if err := wm.WriteMTASTSPolicy(ans.Hostname); err != nil {
			return fmt.Errorf("mta-sts policy: %w", err)
		}
	}
	if err := wm.SyncMTASTS(pctx, active); err != nil {
		return fmt.Errorf("mta-sts include: %w", err)
	}
	_, _ = fmt.Fprintf(out, "waiting for a certificate for %s\n", ans.Hostname)
	if err := install.WaitForCertificate(pctx, x, ans.Hostname, ans.Domain, 10*time.Minute, 15*time.Second); err != nil {
		return err
	}
	for _, unit := range []string{"postfix", "dovecot", "rspamd"} {
		if err := install.EnableUnit(pctx, x, unit); err != nil {
			return err
		}
	}

	_, _ = fmt.Fprintf(out, `
install: mail stack configured and running.
  binary:    %s
  config:    %s/config.toml (secrets in %s/secrets.env, mode 0600)
  database:  %s (roles %s)
  firewall:  inbound limited to 22 plus %v (edit with mailadmin-fw-port)

Add this DNS record for %s (selector %s):
`, installBinaryPath, installConfigDir, installConfigDir, install.PgDatabase,
		strings.Join(install.PgRoles, ", "), install.DefaultTCPPorts, ans.Domain, ans.Selector)
	pub, err := os.ReadFile(filepath.Join(install.DKIMDirPath, ans.Domain+"."+ans.Selector+".key.pub")) // #nosec G304 -- fixed dkim dir
	if err == nil {
		_, _ = fmt.Fprintln(out, strings.TrimSpace(string(pub)))
	}
	_, _ = fmt.Fprintln(out, "Check with: mailadmin doctor")
	return nil
}

// collectAnswers takes flags first and asks for whatever is missing. Without a
// terminal, a missing required value is a usage error, never a silent default.
func collectAnswers(app *App, in *installInputs) (install.Answers, error) {
	a := install.Answers{
		Hostname: in.hostname,
		Domain:   in.domain,
		IPv4:     in.ipv4,
		IPv6:     in.ipv6,
		Selector: in.selector,
	}
	if a.Selector == "" {
		a.Selector = fmt.Sprintf("mail%d", time.Now().Year())
	}
	ask := func(dst *string, label string, optional bool) error {
		if *dst != "" {
			return nil
		}
		if !app.interactive() {
			if optional {
				return nil
			}
			return fmt.Errorf("%w: --%s is required when there is no terminal to ask", ErrUsage, label)
		}
		v, err := app.readLine(label + ": ")
		if err != nil {
			return err
		}
		*dst = v
		return nil
	}
	if err := ask(&a.Hostname, "hostname", false); err != nil {
		return a, err
	}
	if err := ask(&a.Domain, "domain", false); err != nil {
		return a, err
	}
	if err := ask(&a.IPv4, "ipv4", false); err != nil {
		return a, err
	}
	if err := ask(&a.IPv6, "ipv6 (empty for none)", true); err != nil {
		return a, err
	}
	return a, nil
}

// addRepo fetches a vendor key and installs it only after its fingerprint is
// confirmed. With a flag, the fingerprint must match it; otherwise the operator types it.
func addRepo(app *App, c *cobra.Command, x install.Exec, r install.Repo, expected string) error {
	out := c.OutOrStdout()
	pctx := ctx(c)
	key, err := install.FetchKey(pctx, r.KeyURL)
	if err != nil {
		return err
	}
	got, err := install.KeyFingerprint(pctx, x, key)
	if err != nil {
		return err
	}
	if expected == "" {
		if !app.interactive() {
			return fmt.Errorf("%w: --%s-fingerprint is required when there is no terminal", ErrUsage, r.Name)
		}
		_, _ = fmt.Fprintf(out, "%s repository key fingerprint: %s\n", r.Name, got)
		typed, err := app.readLine("type the fingerprint published by the vendor to confirm: ")
		if err != nil {
			return err
		}
		expected = typed
	}
	if err := install.InstallRepo(pctx, x, r, key, expected); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "added %s repository\n", r.Name)
	return nil
}

func printInstallPlan(out io.Writer, d install.Distro, a install.Answers, conflicts []string) {
	_, _ = fmt.Fprintf(out, "install plan for %s\n", d.Pretty)
	_, _ = fmt.Fprintf(out, "  host:      %s (domain %s, ipv4 %s, ipv6 %s, selector %s)\n",
		a.Hostname, a.Domain, a.IPv4, orDash(a.IPv6), a.Selector)
	_, _ = fmt.Fprintf(out, "  repos:     postgresql.org (PGDG), caddy stable (Cloudsmith)\n")
	_, _ = fmt.Fprintf(out, "  packages:  %s\n", strings.Join(append(install.DistroPackages(), install.VendorPackages()...), " "))
	_, _ = fmt.Fprintf(out, "  accounts:  mailadmin, vmail (uid 5000)\n")
	_, _ = fmt.Fprintf(out, "  database:  %s owned by mailadmin, roles %s\n", install.PgDatabase, strings.Join(install.PgRoles, ", "))
	_, _ = fmt.Fprintf(out, "  mail:      postfix, dovecot, rspamd, caddy configured for %s\n", a.Domain)
	_, _ = fmt.Fprintf(out, "  firewall:  nftables, inbound limited to 22 and mail/web ports\n")
	_, _ = fmt.Fprintf(out, "  writes:    %s/config.toml, %s/secrets.env, %s\n", installConfigDir, installConfigDir, installBinaryPath)
	if len(conflicts) > 0 {
		_, _ = fmt.Fprintf(out, "  adopting existing state: %s\n", strings.Join(conflicts, ", "))
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
