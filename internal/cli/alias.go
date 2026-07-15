package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/spf13/cobra"

	"mailadmin/internal/db"
	"mailadmin/internal/output"
	"mailadmin/internal/valid"
)

func newAliasCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{Use: "alias", Short: "Manage aliases and catch-alls"}

	var listDomain string
	list := &cobra.Command{
		Use:   "list",
		Short: "List aliases",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return runAliasList(app, c, listDomain)
		},
	}
	list.Flags().StringVar(&listDomain, "domain", "", "filter by domain")

	show := &cobra.Command{
		Use:   "show <source>",
		Short: "Show alias destinations for a source",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runAliasShow(app, c, args[0])
		},
	}

	var addCatchAll bool
	add := &cobra.Command{
		Use:   "add <source> <destination>",
		Short: "Add an alias (source may be @domain for catch-all)",
		Args:  cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			return runAliasAdd(app, c, args[0], args[1], addCatchAll)
		},
	}
	add.Flags().BoolVar(&addCatchAll, "catch-all", false, "treat source as a @domain catch-all")

	remove := &cobra.Command{
		Use:   "remove <source> [destination]",
		Short: "Remove an alias (all destinations if none given)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(c *cobra.Command, args []string) error {
			dst := ""
			if len(args) == 2 {
				dst = args[1]
			}
			return runAliasRemove(app, c, args[0], dst)
		},
	}

	cmd.AddCommand(list, show, add, remove)
	return cmd
}

// aliasTable builds the shared table view for a set of aliases.
func aliasTable(aliases []db.Alias) output.Table {
	t := output.Table{Columns: []string{"SOURCE", "DESTINATION", "ACTIVE"}}
	for _, a := range aliases {
		t.Rows = append(t.Rows, []string{a.Source, a.Destination, boolYesNo(a.Active)})
	}
	return t
}

// runAliasList lists all aliases, optionally filtered to a single domain.
func runAliasList(app *App, c *cobra.Command, domainFilter string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	if domainFilter != "" {
		domainFilter, err = valid.Domain(domainFilter)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrUsage, err)
		}
	}
	database, err := app.db(ctx(c))
	if err != nil {
		return err
	}
	aliases, err := database.ListAliases(ctx(c), domainFilter)
	if err != nil {
		return err
	}
	if app.flags.output == string(output.FormatJSON) {
		return r.JSON(aliases)
	}
	return r.StatusTable(aliasTable(aliases), 2)
}

// runAliasShow lists every destination configured for one alias source, mapping
// an unknown source to exit 3.
func runAliasShow(app *App, c *cobra.Command, rawSource string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	source, err := valid.AliasSource(rawSource)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	database, err := app.db(ctx(c))
	if err != nil {
		return err
	}
	all, err := database.ListAliases(ctx(c), aliasSourceDomain(source))
	if err != nil {
		return err
	}
	matches := make([]db.Alias, 0, len(all))
	for _, a := range all {
		if a.Source == source {
			matches = append(matches, a)
		}
	}
	if len(matches) == 0 {
		return fmt.Errorf("alias %s: %w", source, ErrNotFound)
	}
	if app.flags.output == string(output.FormatJSON) {
		return r.JSON(matches)
	}
	return r.StatusTable(aliasTable(matches), 2)
}

// runAliasAdd creates (or reactivates) an alias. The source domain must be a
// configured mail domain, mirroring the legacy CLI. --catch-all requires the
// source to be a bare @domain.
func runAliasAdd(app *App, c *cobra.Command, rawSource, rawDest string, catchAll bool) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	source, err := valid.AliasSource(rawSource)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	isCatchAll := strings.HasPrefix(source, "@")
	if catchAll && !isCatchAll {
		return fmt.Errorf("%w: --catch-all requires an @domain source, got %q", ErrUsage, rawSource)
	}
	dest, err := aliasDestination(rawDest)
	if err != nil {
		return err
	}

	database, err := app.db(ctx(c))
	if err != nil {
		return err
	}
	srcDomain := aliasSourceDomain(source)
	if _, err := database.GetDomain(ctx(c), srcDomain); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("alias source domain %s not configured: %w", srcDomain, ErrNotFound)
		}
		return err
	}

	if err := database.CreateAlias(ctx(c), source, dest); err != nil {
		return err
	}
	rec, err := app.auditor(ctx(c))
	if err != nil {
		return err
	}
	after := db.Alias{Source: source, Destination: dest, Active: true}
	if err := rec.Record(ctx(c), "alias.add", source, nil, after); err != nil {
		return err
	}
	r.Message("alias %s -> %s added", source, dest)
	return nil
}

// runAliasRemove deletes one destination for a source, or every destination when
// dst is empty. It is destructive, so it confirms unless --yes and audits.
func runAliasRemove(app *App, c *cobra.Command, rawSource, rawDest string) error {
	r, err := app.Renderer()
	if err != nil {
		return err
	}
	source, err := valid.AliasSource(rawSource)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	var dest string
	if rawDest != "" {
		if dest, err = aliasDestination(rawDest); err != nil {
			return err
		}
	}

	database, err := app.db(ctx(c))
	if err != nil {
		return err
	}

	// Fail closed on a missing target so removal reports exit 3 rather than a
	// silent no-op.
	existing, err := aliasesForSource(ctx(c), database, source, dest)
	if err != nil {
		return err
	}
	if len(existing) == 0 {
		if dest != "" {
			return fmt.Errorf("alias %s -> %s: %w", source, dest, ErrNotFound)
		}
		return fmt.Errorf("alias %s: %w", source, ErrNotFound)
	}

	prompt := fmt.Sprintf("Remove alias %s -> %s?", source, dest)
	if dest == "" {
		prompt = fmt.Sprintf("Remove all %d destination(s) for alias %s?", len(existing), source)
	}
	if err := app.confirm(prompt); err != nil {
		return err
	}

	if dest != "" {
		err = database.DeleteAlias(ctx(c), source, dest)
	} else {
		err = database.DeleteAliasesBySource(ctx(c), source)
	}
	if err != nil {
		return err
	}

	rec, err := app.auditor(ctx(c))
	if err != nil {
		return err
	}
	if err := rec.Record(ctx(c), "alias.remove", source, existing, nil); err != nil {
		return err
	}
	r.Message("alias(es) removed for %s", source)
	return nil
}

// aliasesForSource returns the aliases matching source (and dest when non-empty)
// that currently exist, used to fail closed on removal.
func aliasesForSource(c context.Context, database *db.DB, source, dest string) ([]db.Alias, error) {
	if dest != "" {
		a, err := database.GetAlias(c, source, dest)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, nil
			}
			return nil, err
		}
		return []db.Alias{a}, nil
	}
	all, err := database.ListAliases(c, aliasSourceDomain(source))
	if err != nil {
		return nil, err
	}
	out := make([]db.Alias, 0, len(all))
	for _, a := range all {
		if a.Source == source {
			out = append(out, a)
		}
	}
	return out, nil
}

// aliasDestination validates an alias destination (a full mail address) and
// returns its normalised local@domain form. A bad destination is a usage error.
func aliasDestination(raw string) (string, error) {
	local, domain, err := valid.Address(raw)
	if err != nil {
		return "", fmt.Errorf("%w: destination %v", ErrUsage, err)
	}
	return local + "@" + domain, nil
}

// aliasSourceDomain extracts the domain part of a validated alias source, for
// both "user@domain" and "@domain" catch-all forms.
func aliasSourceDomain(source string) string {
	if i := strings.LastIndexByte(source, '@'); i >= 0 {
		return source[i+1:]
	}
	return source
}
