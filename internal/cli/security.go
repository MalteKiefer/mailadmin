package cli

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"mailadmin/internal/output"
	"mailadmin/internal/security"
	"mailadmin/internal/valid"
)

// security() builds the CrowdSec/nft/fail2ban backend on the shared privileged
// runner. It is cheap (no I/O) so each command constructs one on demand.
func (a *App) security() *security.Service {
	return security.New(a.runner())
}

func newSecurityCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "security", Short: "Bans, allowlist, firewall and overview"}
	cmd.AddCommand(newBanCmd(app), newAllowlistCmd(app), newFirewallCmd(app), newOverviewCmd(app))
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
