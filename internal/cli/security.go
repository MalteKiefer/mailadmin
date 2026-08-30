package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"mailadmin/internal/output"
	"mailadmin/internal/rspamd"
	"mailadmin/internal/rspamdconf"
	"mailadmin/internal/security"
	"mailadmin/internal/stats"
	"mailadmin/internal/sys"
	"mailadmin/internal/valid"
)

// security() builds the CrowdSec/nft/fail2ban backend on the shared privileged
// runner. It is cheap (no I/O) so each command constructs one on demand.
func (a *App) security() *security.Service {
	return security.New(a.runner())
}

// rspamdLearn() builds the rspamc Bayes-feedback backend on the shared
// privileged runner, confined to the default vmail root.
func (a *App) rspamdLearn() *rspamd.Service {
	return rspamd.New(a.runner(), "")
}

func newSecurityCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "security", Short: "Bans, allowlist, firewall and overview"}
	cmd.AddCommand(
		newBanCmd(app),
		newAllowlistCmd(app),
		newFirewallCmd(app),
		newOverviewCmd(app),
		newLearnSpamCmd(app),
		newLearnHamCmd(app),
		newQuarantineCmd(app),
		newRatelimitCmd(app),
		newGreylistCmd(app),
	)
	return cmd
}

func newBanCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "ban", Short: "Manage CrowdSec bans"}

	list := &cobra.Command{
		Use:   "list",
		Short: "List active bans",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, _ []string) error { return runBanList(app, c) },
	}

	var addDur string
	add := &cobra.Command{
		Use:   "add <ip>",
		Short: "Ban an ip/cidr",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return runBanAdd(app, c, args[0], addDur) },
	}
	add.Flags().StringVar(&addDur, "dur", "", "ban duration (e.g. 4h)")

	remove := &cobra.Command{
		Use:   "remove <ip>",
		Short: "Remove a ban",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return runBanRemove(app, c, args[0]) },
	}

	cmd.AddCommand(list, add, remove)
	return cmd
}

func newAllowlistCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "allowlist", Short: "Manage the firewall allowlist"}

	list := &cobra.Command{
		Use:   "list",
		Short: "List allowlist entries",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, _ []string) error { return runAllowList(app, c) },
	}

	add := &cobra.Command{
		Use:   "add <ip>",
		Short: "Allowlist an ip/cidr",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return runAllowAdd(app, c, args[0]) },
	}

	remove := &cobra.Command{
		Use:   "remove <ip>",
		Short: "Remove an allowlist entry",
		Args:  cobra.ExactArgs(1),
		RunE:  func(c *cobra.Command, args []string) error { return runAllowRemove(app, c, args[0]) },
	}

	cmd.AddCommand(list, add, remove)
	return cmd
}

func newFirewallCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "firewall", Short: "Inspect and adjust open ports"}

	show := &cobra.Command{
		Use:   "show",
		Short: "Show managed open ports",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, _ []string) error { return runFirewallShow(app, c) },
	}

	open := &cobra.Command{
		Use:   "open <proto> <port>",
		Short: "Open a port (tcp|udp)",
		Args:  cobra.ExactArgs(2),
		RunE:  func(c *cobra.Command, args []string) error { return runFirewallPort(app, c, "open", args[0], args[1]) },
	}

	closeCmd := &cobra.Command{
		Use:   "close <proto> <port>",
		Short: "Close a port (tcp|udp)",
		Args:  cobra.ExactArgs(2),
		RunE:  func(c *cobra.Command, args []string) error { return runFirewallPort(app, c, "close", args[0], args[1]) },
	}

	cmd.AddCommand(show, open, closeCmd)
	return cmd
}

func newOverviewCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "overview",
		Short: "Show the aggregated security posture",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, _ []string) error { return runOverview(app, c) },
	}
}

// ---- row shapes (flatten backend types for stable table/plain/json output) --

type banRow struct {
	IP       string `json:"ip"`
	Scenario string `json:"scenario"`
	Type     string `json:"type"`
	Duration string `json:"duration"`
	Until    string `json:"until"`
	Origin   string `json:"origin"`
}

var banColumns = []string{"IP", "SCENARIO", "TYPE", "DURATION", "UNTIL", "ORIGIN"}

func banRowOf(d security.Decision) []string {
	until := ""
	if !d.Until.IsZero() {
		until = d.Until.UTC().Format("2006-01-02T15:04:05Z")
	}
	return []string{d.IP, d.Scenario, d.Type, d.Duration, until, d.Origin}
}

type allowRow struct {
	IP      string `json:"ip"`
	Comment string `json:"comment,omitempty"`
}

var allowColumns = []string{"IP", "COMMENT"}

func allowRowOf(e security.AllowEntry) []string { return []string{e.IP, e.Comment} }

type portRow struct {
	Proto string `json:"proto"`
	Port  int    `json:"port"`
}

var portColumns = []string{"PROTO", "PORT"}

func portRowOf(p security.FirewallPort) []string {
	return []string{p.Proto, strconv.Itoa(p.Port)}
}

// ---- bans -----------------------------------------------------------------

func runBanList(app *App, cmd *cobra.Command) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	decisions, err := app.security().ListBans(ctx(cmd))
	if err != nil {
		return err
	}
	rows := make([][]string, 0, len(decisions))
	for _, d := range decisions {
		rows = append(rows, banRowOf(d))
	}
	return r.Table(output.Table{Columns: banColumns, Rows: rows})
}

func runBanAdd(app *App, cmd *cobra.Command, ip, dur string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	// Validate before prompting/executing so bad input fails fast and never
	// reaches an argv.
	value, err := valid.CIDR(ip)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if dur != "" {
		if _, derr := valid.Duration(dur); derr != nil {
			return fmt.Errorf("%w: %v", ErrUsage, derr)
		}
	}

	if app.flags.dryRun {
		if dur != "" {
			r.Message("dry-run: would ban %s for %s", value, dur)
		} else {
			r.Message("dry-run: would ban %s", value)
		}
		return nil
	}

	prompt := fmt.Sprintf("ban %s", value)
	if dur != "" {
		prompt = fmt.Sprintf("ban %s for %s", value, dur)
	}
	if err := app.confirm(prompt); err != nil {
		return err
	}

	if err := app.security().AddBan(ctx(cmd), value, dur); err != nil {
		return err
	}

	after := map[string]string{"ip": value}
	if dur != "" {
		after["duration"] = dur
	}
	app.recordSecurity(cmd, "security.ban.add", value, nil, after)

	r.Message("banned %s", value)
	return nil
}

func runBanRemove(app *App, cmd *cobra.Command, ip string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	value, err := valid.CIDR(ip)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if app.flags.dryRun {
		r.Message("dry-run: would remove ban %s", value)
		return nil
	}
	if err := app.confirm(fmt.Sprintf("remove ban %s", value)); err != nil {
		return err
	}
	if err := app.security().RemoveBan(ctx(cmd), value); err != nil {
		return err
	}
	app.recordSecurity(cmd, "security.ban.remove", value, map[string]string{"ip": value}, nil)
	r.Message("removed ban %s", value)
	return nil
}

// ---- allowlist ------------------------------------------------------------

func runAllowList(app *App, cmd *cobra.Command) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	entries, err := app.security().ListAllow(ctx(cmd))
	if err != nil {
		return err
	}
	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, allowRowOf(e))
	}
	return r.Table(output.Table{Columns: allowColumns, Rows: rows})
}

func runAllowAdd(app *App, cmd *cobra.Command, ip string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	value, err := valid.CIDR(ip)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if app.flags.dryRun {
		r.Message("dry-run: would allowlist %s", value)
		return nil
	}
	if err := app.confirm(fmt.Sprintf("allowlist %s", value)); err != nil {
		return err
	}
	if err := app.security().AddAllow(ctx(cmd), value); err != nil {
		return err
	}
	app.recordSecurity(cmd, "security.allowlist.add", value, nil, map[string]string{"ip": value})
	r.Message("allowlisted %s", value)
	return nil
}

func runAllowRemove(app *App, cmd *cobra.Command, ip string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	value, err := valid.CIDR(ip)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if app.flags.dryRun {
		r.Message("dry-run: would remove allowlist entry %s", value)
		return nil
	}
	if err := app.confirm(fmt.Sprintf("remove allowlist entry %s", value)); err != nil {
		return err
	}
	if err := app.security().RemoveAllow(ctx(cmd), value); err != nil {
		return err
	}
	app.recordSecurity(cmd, "security.allowlist.remove", value, map[string]string{"ip": value}, nil)
	r.Message("removed allowlist entry %s", value)
	return nil
}

// ---- firewall -------------------------------------------------------------

func runFirewallShow(app *App, cmd *cobra.Command) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	ports, err := app.security().ShowFirewall(ctx(cmd))
	if err != nil {
		return err
	}
	rows := make([][]string, 0, len(ports))
	for _, p := range ports {
		rows = append(rows, portRowOf(p))
	}
	return r.Table(output.Table{Columns: portColumns, Rows: rows})
}

// runFirewallPort opens or closes a managed port. action is a compile-time
// constant ("open"|"close") from the command wiring, never user input.
func runFirewallPort(app *App, cmd *cobra.Command, action, protoArg, portArg string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	proto, err := valid.Proto(protoArg)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	portNum, err := strconv.Atoi(portArg)
	if err != nil {
		return fmt.Errorf("%w: port %q is not numeric", ErrUsage, portArg)
	}
	port, err := valid.Port(portNum)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}

	if app.flags.dryRun {
		r.Message("dry-run: would %s %s port %d", action, proto, port)
		return nil
	}

	if err := app.confirm(fmt.Sprintf("%s %s port %d", action, proto, port)); err != nil {
		return err
	}

	svc := app.security()
	if action == "open" {
		err = svc.OpenPort(ctx(cmd), proto, port)
	} else {
		err = svc.ClosePort(ctx(cmd), proto, port)
	}
	if err != nil {
		return err
	}

	target := fmt.Sprintf("%s/%d", proto, port)
	app.recordSecurity(cmd, "security.firewall."+action, target,
		nil, portRow{Proto: proto, Port: port})
	r.Message("%sed %s port %d", action, proto, port)
	return nil
}

// ---- overview -------------------------------------------------------------

func runOverview(app *App, cmd *cobra.Command) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	ov, err := app.security().Overview(ctx(cmd))
	if err != nil {
		return err
	}

	// JSON consumers get the structured aggregate verbatim; the human formats
	// get labelled sections so the three sources stay distinguishable.
	if r.Format() == output.FormatJSON {
		return r.JSON(overviewJSONFrom(ov))
	}

	r.Message("bans: %d  allowlist: %d  open ports: %d  fail2ban: %s",
		len(ov.Decisions), len(ov.Allowlist), len(ov.OpenPorts), yesNo(ov.Fail2ban))

	banRows := make([][]string, 0, len(ov.Decisions))
	for _, d := range ov.Decisions {
		banRows = append(banRows, banRowOf(d))
	}
	r.Message("Bans")
	if err := r.Table(output.Table{Columns: banColumns, Rows: banRows}); err != nil {
		return err
	}

	allowRows := make([][]string, 0, len(ov.Allowlist))
	for _, e := range ov.Allowlist {
		allowRows = append(allowRows, allowRowOf(e))
	}
	r.Message("Allowlist")
	if err := r.Table(output.Table{Columns: allowColumns, Rows: allowRows}); err != nil {
		return err
	}

	portRows := make([][]string, 0, len(ov.OpenPorts))
	for _, p := range ov.OpenPorts {
		portRows = append(portRows, portRowOf(p))
	}
	r.Message("Open ports")
	return r.Table(output.Table{Columns: portColumns, Rows: portRows})
}

// overviewJSON is the machine-readable shape of an overview: pre-flattened rows
// so the JSON matches the columns shown in table/plain mode.
type overviewJSON struct {
	Bans      []banRow   `json:"bans"`
	Allowlist []allowRow `json:"allowlist"`
	OpenPorts []portRow  `json:"open_ports"`
	Fail2ban  bool       `json:"fail2ban_running"`
}

func overviewJSONFrom(ov security.Overview) overviewJSON {
	out := overviewJSON{Fail2ban: ov.Fail2ban}
	for _, d := range ov.Decisions {
		until := ""
		if !d.Until.IsZero() {
			until = d.Until.UTC().Format("2006-01-02T15:04:05Z")
		}
		out.Bans = append(out.Bans, banRow{
			IP: d.IP, Scenario: d.Scenario, Type: d.Type,
			Duration: d.Duration, Until: until, Origin: d.Origin,
		})
	}
	for _, e := range ov.Allowlist {
		out.Allowlist = append(out.Allowlist, allowRow{IP: e.IP, Comment: e.Comment})
	}
	for _, p := range ov.OpenPorts {
		out.OpenPorts = append(out.OpenPorts, portRow{Proto: p.Proto, Port: p.Port})
	}
	return out
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// recordSecurity writes a best-effort audit entry for a successful mutation.
// A missing/broken audit path must not mask the completed action (the change is
// already applied), so recorder errors are swallowed after the side effect. The
// backing DB pool is owned by the App and released via closeBackends.
func (a *App) recordSecurity(cmd *cobra.Command, action, target string, before, after any) {
	rec, err := a.auditor(ctx(cmd))
	if err != nil {
		return
	}
	_ = rec.Record(ctx(cmd), action, target, before, after)
}

// ---- rspamd Bayes feedback (learn-spam / learn-ham) ------------------------
//
// This replaces the deleted mailadmin-rspamd-learn shell helper (see
// docs/SECURITY-AUDIT.md L-3): a message source is either a Postfix queue id
// (fetched via postcat) or a file path, which internal/rspamd confines —
// after symlink resolution — to the vmail root before it ever reaches rspamc.

func newLearnSpamCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "learn-spam <queue-id|path>",
		Short: "Train rspamd's Bayes classifier that a message is spam",
		Long: "Feeds a message to `rspamc learn_spam`. The message source is either a\n" +
			"Postfix queue id (fetched via postcat) or a file path under the vmail\n" +
			"spool (e.g. a message file from a mailbox's Maildir); the path is\n" +
			"confined to the vmail root, rejecting traversal and symlink escapes.",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error { return runLearn(app, c, "spam", args[0]) },
	}
}

func newLearnHamCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "learn-ham <queue-id|path>",
		Short: "Train rspamd's Bayes classifier that a message is ham (not spam)",
		Long: "Feeds a message to `rspamc learn_ham`. The message source is either a\n" +
			"Postfix queue id (fetched via postcat) or a file path under the vmail\n" +
			"spool (e.g. a message file from a mailbox's Maildir); the path is\n" +
			"confined to the vmail root, rejecting traversal and symlink escapes.",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error { return runLearn(app, c, "ham", args[0]) },
	}
}

// runLearn validates source (no side effects), honours --dry-run, then trains
// rspamd and records an audit entry. verdict is a compile-time constant
// ("spam"|"ham") from the command wiring, never user input.
func runLearn(app *App, cmd *cobra.Command, verdict, source string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}

	svc := app.rspamdLearn()
	kind, identifier, err := svc.Resolve(source)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}

	if app.flags.dryRun {
		r.Message("dry-run: would train rspamd (learn-%s) on %s %s", verdict, kind, identifier)
		return nil
	}

	c := ctx(cmd)
	var trainErr error
	switch verdict {
	case "spam":
		_, trainErr = svc.LearnSpam(c, source)
	default:
		_, trainErr = svc.LearnHam(c, source)
	}
	if trainErr != nil {
		return trainErr
	}

	app.recordSecurity(cmd, "security.learn-"+verdict, identifier, nil, map[string]string{"kind": kind})
	r.Message("trained rspamd (learn-%s) on %s %s", verdict, kind, identifier)
	return nil
}

// ---- quarantine (log-derived, read-only) -----------------------------------

func newQuarantineCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "quarantine",
		Short: "Inspect reject/greylist activity derived from the rspamd log",
	}

	var since string
	list := &cobra.Command{
		Use:   "list",
		Short: "List reject/soft-reject/greylist verdicts parsed from the rspamd log (not a message store)",
		Long: "rspamd is not configured with a quarantine message store here: a rejected\n" +
			"message was never accepted onto disk, so there is nothing to release. This\n" +
			"command is a read-only diagnostic view, parsed from the rspamd log, of\n" +
			"reject/soft-reject/greylist verdicts in the given window. From/To/Subject\n" +
			"are shown only when rspamd's configured log_format happens to include them.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error { return runQuarantineList(app, c, since) },
	}
	list.Flags().StringVar(&since, "since", "", "how far back to look, e.g. 2h, 3d (default 7 days)")

	cmd.AddCommand(list)
	return cmd
}

// runQuarantineList validates --since, parses the rspamd log over that
// window, and renders the resulting verdicts. Read-only: no confirm, no audit.
func runQuarantineList(app *App, cmd *cobra.Command, since string) error {
	if since != "" {
		if _, err := valid.Duration(since); err != nil {
			return fmt.Errorf("%w: --since: %v", ErrUsage, err)
		}
	}

	r, err := app.Renderer()
	if err != nil {
		return err
	}
	cfg, err := app.statsConfig()
	if err != nil {
		return err
	}

	col := stats.New(sys.New(sys.DefaultTimeout, nil), cfg.Logs.Units)
	entries, err := col.Quarantine(ctx(cmd), since)
	if err != nil {
		return err
	}

	if app.flags.output == string(output.FormatJSON) {
		return r.JSON(entries)
	}
	t := output.Table{Columns: []string{"TIMESTAMP", "ACTION", "SCORE", "FROM", "TO", "SUBJECT", "QUEUE ID"}}
	for _, e := range entries {
		t.Rows = append(t.Rows, []string{e.Timestamp, e.Action, e.Score, e.From, e.To, e.Subject, e.QueueID})
	}
	return r.Table(t)
}

// ---- rspamd ratelimit / greylist tuning ------------------------------------
//
// These commands read and surgically edit /etc/rspamd/local.d/ratelimit.conf
// and greylist.conf (see internal/rspamdconf for the parser/writer and why it
// is a narrow line-oriented grammar rather than a full UCL editor). Every
// mutating write is followed by the same `rspamadm configtest` check `doctor`
// runs (rspamdCheck, doctor.go) before being reported as a success; a failed
// check rolls the file back to its pre-write content so rspamd is never left
// with a config that fails to load. A successful, validated write is followed
// by a reload of the rspamd unit through internal/services (the same
// allowlist-gated path `mailadmin service reload rspamd` uses) so the change
// actually takes effect.
//
// rspamdConfDir is the local.d directory. It is not currently exposed as a
// mailadmin config setting (internal/config/config.go is out of scope for
// this change), so it is pinned to rspamdconf.DefaultConfDir, the well-known
// Debian/rspamd default.
const rspamdConfDir = rspamdconf.DefaultConfDir

// validateAndReload runs the doctor rspamd-config check against the
// just-written file; on failure it restores oldContent to path and returns an
// error, so a bad rspamd config is never left on disk. On success it reloads
// the rspamd unit via the allowlist-gated services backend.
func (a *App) validateAndReload(cmd *cobra.Command, path string, oldContent []byte) error {
	c := ctx(cmd)
	res := rspamdCheck(c, a.runner())
	if res.Status != statusOK {
		if rbErr := rspamdconf.RestoreFile(path, oldContent); rbErr != nil {
			return fmt.Errorf("rspamd config validation failed (%s) AND rollback failed: %v", res.Detail, rbErr)
		}
		return fmt.Errorf("rspamd config validation failed, rolled back: %s", res.Detail)
	}

	svc, err := a.services()
	if err != nil {
		return fmt.Errorf("config written and validated, but reload could not be attempted: %w", err)
	}
	if err := svc.Reload(c, "rspamd"); err != nil {
		return fmt.Errorf("config written and validated, but reload failed: %w", err)
	}
	return nil
}

// ---- ratelimit --------------------------------------------------------

func newRatelimitCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ratelimit",
		Short: "Show or tune rspamd rate-limit buckets (local.d/ratelimit.conf)",
	}

	show := &cobra.Command{
		Use:   "show",
		Short: "Show the configured rate for every ratelimit bucket",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, _ []string) error { return runRatelimitShow(app, c) },
	}

	set := &cobra.Command{
		Use:   "set <bucket> <rate>",
		Short: "Set a ratelimit bucket's rate (e.g. \"20 / 1m\")",
		Long: "Sets one bucket in the rspamd ratelimit module's `rates { }` block. Buckets:\n" +
			strings.Join(rspamdconf.RatelimitBuckets, ", ") + ".\n" +
			"rate must be \"<count> / <n><unit>\", unit one of s,m,h,d,w (e.g. \"20 / 1m\").",
		Args: cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error { return runRatelimitSet(app, c, args[0], args[1]) },
	}

	cmd.AddCommand(show, set)
	return cmd
}

var ratelimitColumns = []string{"BUCKET", "RATE", "SOURCE"}

func runRatelimitShow(app *App, cmd *cobra.Command) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	values, err := rspamdconf.ReadRatelimit(rspamdConfDir)
	if err != nil {
		return err
	}
	rows := make([][]string, 0, len(rspamdconf.RatelimitBuckets))
	for _, b := range rspamdconf.RatelimitBuckets {
		if v, ok := values[b]; ok {
			rows = append(rows, []string{b, v, "file"})
		} else {
			rows = append(rows, []string{b, "", "rspamd default"})
		}
	}
	return r.Table(output.Table{Columns: ratelimitColumns, Rows: rows})
}

func runRatelimitSet(app *App, cmd *cobra.Command, bucketArg, rateArg string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	if !rspamdconf.IsBucket(bucketArg) {
		return fmt.Errorf("%w: unknown ratelimit bucket %q (valid: %s)",
			ErrUsage, bucketArg, strings.Join(rspamdconf.RatelimitBuckets, ", "))
	}
	normalized, err := rspamdconf.ValidateRate(rateArg)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}

	values, err := rspamdconf.ReadRatelimit(rspamdConfDir)
	if err != nil {
		return err
	}
	oldDisplay, hadOld := values[bucketArg]
	if !hadOld {
		oldDisplay = "(rspamd default)"
	}

	if app.flags.dryRun {
		r.Message("dry-run: would set ratelimit %s: %s -> %s", bucketArg, oldDisplay, normalized)
		return nil
	}

	if err := app.confirm(fmt.Sprintf("set ratelimit %s to %s (was %s)", bucketArg, normalized, oldDisplay)); err != nil {
		return err
	}

	oldContent, oldValue, err := rspamdconf.SetRatelimit(rspamdConfDir, bucketArg, rateArg)
	if err != nil {
		return err
	}

	if err := app.validateAndReload(cmd, rspamdconf.RatelimitPath(rspamdConfDir), oldContent); err != nil {
		return err
	}

	before := map[string]string{"rate": oldValue}
	after := map[string]string{"rate": normalized}
	app.recordSecurity(cmd, "security.ratelimit.set", bucketArg, before, after)

	r.Message("set ratelimit %s to %s", bucketArg, normalized)
	return nil
}

// ---- greylist -----------------------------------------------------------

func newGreylistCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "greylist",
		Short: "Show or tune rspamd greylisting (local.d/greylist.conf)",
	}

	show := &cobra.Command{
		Use:   "show",
		Short: "Show the configured greylist timeout/expire",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, _ []string) error { return runGreylistShow(app, c) },
	}

	var timeout, expire string
	set := &cobra.Command{
		Use:   "set",
		Short: "Set greylist timeout and/or expire",
		Long: "Sets the rspamd greylist module's timeout (how long a first-seen\n" +
			"triplet is soft-rejected) and/or expire (how long a passed triplet stays\n" +
			"valid), e.g. --timeout 5m --expire 1d. Durations use a single unit\n" +
			"(s|m|h|d), matching the rest of mailadmin's duration flags.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error { return runGreylistSet(app, c, timeout, expire) },
	}
	set.Flags().StringVar(&timeout, "timeout", "", "greylist timeout, e.g. 5m")
	set.Flags().StringVar(&expire, "expire", "", "greylist expire, e.g. 1d")

	cmd.AddCommand(show, set)
	return cmd
}

var greylistColumns = []string{"SETTING", "VALUE", "SOURCE"}

func runGreylistShow(app *App, cmd *cobra.Command) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	values, err := rspamdconf.ReadGreylist(rspamdConfDir)
	if err != nil {
		return err
	}
	rows := make([][]string, 0, len(rspamdconf.GreylistSettings))
	for _, s := range rspamdconf.GreylistSettings {
		if v, ok := values[s]; ok {
			rows = append(rows, []string{s, v, "file"})
		} else {
			rows = append(rows, []string{s, "", "rspamd default"})
		}
	}
	return r.Table(output.Table{Columns: greylistColumns, Rows: rows})
}

// greylistChange is one --timeout/--expire value to apply, in flag order.
type greylistChange struct {
	setting, value string
}

func runGreylistSet(app *App, cmd *cobra.Command, timeout, expire string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	if timeout == "" && expire == "" {
		return fmt.Errorf("%w: at least one of --timeout/--expire is required", ErrUsage)
	}

	var changes []greylistChange
	if timeout != "" {
		v, verr := valid.Duration(timeout)
		if verr != nil {
			return fmt.Errorf("%w: --timeout: %v", ErrUsage, verr)
		}
		changes = append(changes, greylistChange{"timeout", v})
	}
	if expire != "" {
		v, verr := valid.Duration(expire)
		if verr != nil {
			return fmt.Errorf("%w: --expire: %v", ErrUsage, verr)
		}
		changes = append(changes, greylistChange{"expire", v})
	}

	current, err := rspamdconf.ReadGreylist(rspamdConfDir)
	if err != nil {
		return err
	}

	if app.flags.dryRun {
		for _, chg := range changes {
			old, ok := current[chg.setting]
			if !ok {
				old = "(rspamd default)"
			}
			r.Message("dry-run: would set greylist %s: %s -> %s", chg.setting, old, chg.value)
		}
		return nil
	}

	descr := make([]string, 0, len(changes))
	for _, chg := range changes {
		descr = append(descr, fmt.Sprintf("%s=%s", chg.setting, chg.value))
	}
	if err := app.confirm("set greylist " + strings.Join(descr, ", ")); err != nil {
		return err
	}

	var originalContent []byte
	haveOriginal := false
	before := map[string]string{}
	after := map[string]string{}
	targets := make([]string, 0, len(changes))

	for _, chg := range changes {
		oldContent, oldValue, serr := rspamdconf.SetGreylist(rspamdConfDir, chg.setting, chg.value)
		if serr != nil {
			if haveOriginal {
				_ = rspamdconf.RestoreFile(rspamdconf.GreylistPath(rspamdConfDir), originalContent)
			}
			return serr
		}
		if !haveOriginal {
			originalContent = oldContent
			haveOriginal = true
		}
		before[chg.setting] = oldValue
		after[chg.setting] = chg.value
		targets = append(targets, chg.setting)
	}

	if err := app.validateAndReload(cmd, rspamdconf.GreylistPath(rspamdConfDir), originalContent); err != nil {
		return err
	}

	app.recordSecurity(cmd, "security.greylist.set", strings.Join(targets, ","), before, after)

	for _, chg := range changes {
		r.Message("set greylist %s to %s", chg.setting, chg.value)
	}
	return nil
}
