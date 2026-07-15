// Package cli wires the whole mailadmin command tree with cobra. Command
// definitions live one file per resource group; every RunE calls into a backend
// package and renders through internal/output — no per-command formatting.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"mailadmin/internal/audit"
	"mailadmin/internal/config"
	"mailadmin/internal/db"
	"mailadmin/internal/output"
	"mailadmin/internal/sys"
	"mailadmin/internal/webserver"
)

// Exit codes (locked by ARCHITECTURE).
const (
	ExitOK       = 0
	ExitRuntime  = 1
	ExitUsage    = 2
	ExitNotFound = 3
	ExitDeclined = 4
)

// Sentinel errors mapped to exit codes by main.
var (
	// ErrNotFound maps to ExitNotFound.
	ErrNotFound = errors.New("not found")
	// ErrDeclined maps to ExitDeclined (confirmation refused).
	ErrDeclined = errors.New("confirmation declined")
	// ErrUsage maps to ExitUsage (bad flags/arguments).
	ErrUsage = errors.New("usage error")
	// ErrNotImplemented is returned by skeleton handlers.
	ErrNotImplemented = errors.New("not implemented")
)

// globalFlags holds values bound to the persistent flags.
type globalFlags struct {
	output     string
	configPath string
	color      string // auto|always|never
	yes        bool
	dryRun     bool
	quiet      bool
}

// App carries shared state across command handlers. Config and backends are
// loaded lazily so `version`/`completion`/`config init` work without a config.
type App struct {
	flags    globalFlags
	cfg      *config.Config
	secrets  *config.Secrets
	renderer *output.Renderer

	// Lazily-initialised backends shared across handlers.
	database *db.DB
	run      *sys.Runner

	// out/in/err are indirections for testability; nil means the process
	// standard streams.
	out io.Writer
	in  io.Reader
	err io.Writer
}

func (a *App) stdout() io.Writer {
	if a.out != nil {
		return a.out
	}
	return os.Stdout
}

func (a *App) stdin() io.Reader {
	if a.in != nil {
		return a.in
	}
	return os.Stdin
}

func (a *App) stderr() io.Writer {
	if a.err != nil {
		return a.err
	}
	return os.Stderr
}

// Renderer returns the output renderer configured from -o/-q. The chosen format
// is validated here so a bad -o value is a usage error (exit 2).
func (a *App) Renderer() (*output.Renderer, error) {
	if a.renderer != nil {
		return a.renderer, nil
	}
	format, err := output.ParseFormat(a.flags.output)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUsage, err)
	}
	a.renderer = output.New(format, a.stdout(), a.flags.quiet)
	switch a.flags.color {
	case "always":
		a.renderer.SetColor(true)
	case "never":
		a.renderer.SetColor(false)
	}
	return a.renderer, nil
}

// Config lazily loads and returns the validated config + secrets from the
// --config path. It caches the result so repeated calls are cheap.
func (a *App) Config() (*config.Config, *config.Secrets, error) {
	if a.cfg != nil && a.secrets != nil {
		return a.cfg, a.secrets, nil
	}
	cfg, secrets, err := config.Load(a.flags.configPath)
	if err != nil {
		return nil, nil, err
	}
	a.cfg, a.secrets = cfg, secrets
	return cfg, secrets, nil
}

// DefaultCommandTimeout bounds every privileged external command (doveadm, nft,
// systemctl, …) run via internal/sys.
const DefaultCommandTimeout = 30 * time.Second

// runner returns the privileged-exec chokepoint. It is created once per App and
// records nothing to the audit log itself (per-mutation audit rows are written
// explicitly by handlers); passing nil keeps sys quiet.
func (a *App) runner() *sys.Runner {
	if a.run == nil {
		a.run = sys.New(DefaultCommandTimeout, nil)
	}
	return a.run
}

// db opens (once) and returns the Postgres pool, using the configured libpq
// service DSN. The caller must not close it; closeBackends does that at exit.
func (a *App) db(c context.Context) (*db.DB, error) {
	if a.database != nil {
		return a.database, nil
	}
	cfg, _, err := a.Config()
	if err != nil {
		return nil, err
	}
	if sf := cfg.Postgres.ServiceFile; sf != "" {
		// libpq resolves the service name from PGSERVICEFILE.
		if os.Getenv("PGSERVICEFILE") == "" {
			_ = os.Setenv("PGSERVICEFILE", sf)
		}
	}
	d, err := db.Open(c, cfg.DSN())
	if err != nil {
		return nil, err
	}
	a.database = d
	return d, nil
}

// auditor returns the audit recorder bound to the DB and the invoking unix user.
func (a *App) auditor(c context.Context) (*audit.Recorder, error) {
	d, err := a.db(c)
	if err != nil {
		return nil, err
	}
	return audit.New(d, audit.CurrentActor()), nil
}

// webserver returns the Caddy autodiscovery manager (default paths).
func (a *App) webserver() *webserver.Manager {
	return webserver.New(a.runner(), "", "", "", "")
}

// syncAutodiscovery regenerates the managed Caddy autodiscovery include from the
// current domain list and reloads Caddy.
func (a *App) syncAutodiscovery(c context.Context) error {
	d, err := a.db(c)
	if err != nil {
		return err
	}
	domains, err := d.ListDomains(c)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(domains))
	for _, dom := range domains {
		names = append(names, dom.Name)
	}
	return a.webserver().Sync(c, names)
}

// closeBackends releases pooled resources. Safe to call when nothing was opened.
func (a *App) closeBackends() {
	if a.database != nil {
		a.database.Close()
		a.database = nil
	}
}

// confirm prompts for a destructive action unless --yes. It returns ErrDeclined
// if the operator does not answer affirmatively, and treats EOF/quiet as a
// decline (fail closed).
func (a *App) confirm(prompt string) error {
	if a.flags.yes {
		return nil
	}
	line, err := a.readLine(fmt.Sprintf("%s [y/N]: ", prompt))
	if err != nil {
		return err
	}
	switch strings.ToLower(line) {
	case "y", "yes":
		return nil
	default:
		return ErrDeclined
	}
}

// NewRootCmd builds the root cobra command and the entire subcommand tree.
func NewRootCmd() *cobra.Command {
	app := &App{}
	// Release the DB pool when the process finishes, on success or error.
	cobra.OnFinalize(app.closeBackends)

	root := &cobra.Command{
		Use:           "mailadmin",
		Short:         "Multi-domain mail server administration CLI",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	// Flag parse errors are usage errors (exit 2).
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	})

	pf := root.PersistentFlags()
	pf.StringVarP(&app.flags.output, "output", "o", string(output.FormatTable), "output format: table|json|plain")
	pf.StringVar(&app.flags.configPath, "config", config.DefaultPath, "config file path")
	pf.BoolVar(&app.flags.yes, "yes", false, "skip confirmation prompts")
	pf.BoolVar(&app.flags.dryRun, "dry-run", false, "print plan without mutating external state")
	pf.BoolVarP(&app.flags.quiet, "quiet", "q", false, "suppress status messages")
	pf.StringVar(&app.flags.color, "color", "auto", "colourise output: auto|always|never")

	root.AddCommand(
		newDomainCmd(app),
		newMailboxCmd(app),
		newAliasCmd(app),
		newDNSCmd(app),
		newSecurityCmd(app),
		newQueueCmd(app),
		newServiceCmd(app),
		newLogCmd(app),
		newStatsCmd(app),
		newSieveCmd(app),
		newAuditCmd(app),
		newDoctorCmd(app),
		newConfigCmd(app),
		newVersionCmd(app),
		newUpdateCmd(app),
		newCompletionCmd(root),
	)
	return root
}

// ExitCode maps an error returned by a command to a process exit code.
func ExitCode(err error) int {
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, ErrNotFound):
		return ExitNotFound
	case errors.Is(err, ErrDeclined):
		return ExitDeclined
	case errors.Is(err, ErrUsage):
		return ExitUsage
	default:
		return ExitRuntime
	}
}

// ctx is a helper returning the command's context (or Background).
func ctx(cmd *cobra.Command) context.Context {
	if c := cmd.Context(); c != nil {
		return c
	}
	return context.Background()
}
