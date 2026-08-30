// Package backup builds and restores self-contained mailadmin disaster-
// recovery bundles: a Postgres dump, the DKIM key directory, per-mailbox
// active Sieve scripts, and the non-secret config.toml.
//
// A bundle is a plain timestamped directory (not an archive), named
// mailadmin-<UTC timestamp>, written under the operator's configured backup
// directory:
//
//	<dir>/mailadmin-20260830T120000Z/
//	  manifest.json   -- see Manifest
//	  db.dump         -- pg_dump --format=custom output
//	  dkim/           -- verbatim copy of cfg.Mail.DKIMDir
//	  sieve/*.sieve   -- one file per mailbox with an active script, named
//	                     <local>@<domain>.sieve
//	  config.toml     -- copy of mailadmin's own config.toml
//
// secrets.env is deliberately never included in a bundle — see SecretsWarning.
//
// This package holds the mechanical, unprivileged parts (manifest shape,
// path/argv construction, directory copying, bundle discovery) so they can be
// unit-tested without a real Postgres or dovecot. The orchestration that ties
// these to the database, DKIM manager, and ManageSieve service lives in
// internal/cli (mirroring how internal/dnsprovider vs internal/cli/dns.go
// split backup/restore of DNS zones).
package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Bundle layout: fixed names inside a bundle directory.
const (
	ManifestFile = "manifest.json"
	DKIMDir      = "dkim"
	SieveDir     = "sieve"
	ConfigFile   = "config.toml"
	DBDumpFile   = "db.dump"
)

// Component names accepted by `backup restore --component` and recorded in
// Manifest.Components.
const (
	ComponentDB     = "domain-db"
	ComponentDKIM   = "dkim"
	ComponentSieve  = "sieve"
	ComponentConfig = "config"
)

// AllComponents lists every component, in the fixed order a full backup/
// restore processes them: the database first (so a restore's DKIM/Sieve
// changes always land on top of a matching schema), then key material, then
// mail-routing scripts, then the non-secret config file last.
var AllComponents = []string{ComponentDB, ComponentDKIM, ComponentSieve, ComponentConfig}

// ErrUnknownComponent is returned for a --component value not in AllComponents.
var ErrUnknownComponent = errors.New("backup: unknown component")

// ValidComponent reports whether name is one of AllComponents.
func ValidComponent(name string) bool {
	for _, c := range AllComponents {
		if c == name {
			return true
		}
	}
	return false
}

// manifestSchemaVersion is bumped only if the Manifest shape changes
// incompatibly; ReadManifest does not currently reject other versions (older
// bundles should still be inspectable/listable), but callers may check it.
const manifestSchemaVersion = 1

// SecretsWarning is stamped into every manifest and echoed to the operator at
// backup time, so nobody assumes secrets.env travels with a bundle.
const SecretsWarning = "secrets.env is NOT included in this bundle (API tokens, rspamd controller password). " +
	"Back it up separately through a secrets-appropriate channel and restore it by hand."

// Manifest is the metadata written alongside every bundle.
type Manifest struct {
	Version          int       `json:"version"`
	MailadminVersion string    `json:"mailadmin_version"`
	CreatedAt        time.Time `json:"created_at"`
	Components       []string  `json:"components"`

	DBService string `json:"db_service,omitempty"`
	DBFormat  string `json:"db_format,omitempty"` // "custom" (pg_dump --format=custom)

	Domains      []string `json:"domains,omitempty"`
	Mailboxes    int      `json:"mailboxes,omitempty"`
	DKIMKeyFiles int      `json:"dkim_key_files,omitempty"`
	// SieveScripts lists the mailbox addresses whose active Sieve script was
	// backed up (one <address>.sieve file per entry under sieve/).
	SieveScripts []string `json:"sieve_scripts,omitempty"`

	Notes string `json:"notes"`
}

// NewManifest builds a manifest for a bundle taken now, stamping the fixed
// secrets warning.
func NewManifest(mailadminVersion string, components []string) Manifest {
	return Manifest{
		Version:          manifestSchemaVersion,
		MailadminVersion: mailadminVersion,
		CreatedAt:        time.Now().UTC(),
		Components:       components,
		Notes:            SecretsWarning,
	}
}

// HasComponent reports whether m declares component as included.
func (m Manifest) HasComponent(component string) bool {
	for _, c := range m.Components {
		if c == component {
			return true
		}
	}
	return false
}

// BundleName returns the directory name for a bundle taken at t:
// mailadmin-<UTC timestamp, filesystem-safe>.
func BundleName(t time.Time) string {
	return "mailadmin-" + t.UTC().Format("20060102T150405Z")
}

// WriteManifest marshals m as pretty JSON to <bundleDir>/manifest.json (0600).
func WriteManifest(bundleDir string, m Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("backup: marshal manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, ManifestFile), b, 0o600); err != nil {
		return fmt.Errorf("backup: write manifest: %w", err)
	}
	return nil
}

// ReadManifest loads and parses a bundle's manifest.json.
func ReadManifest(bundleDir string) (Manifest, error) {
	var m Manifest
	path := filepath.Join(bundleDir, ManifestFile)
	// path is built from an operator-supplied bundle directory (root CLI)
	// joined with the fixed ManifestFile basename; no attacker-controlled
	// path component reaches ReadFile.
	b, err := os.ReadFile(path) // #nosec G304 -- operator-supplied bundle path + fixed basename
	if err != nil {
		return m, fmt.Errorf("backup: read manifest: %w", err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("backup: parse manifest %s: %w", path, err)
	}
	return m, nil
}

// SieveFileName returns the on-disk filename for a mailbox's backed-up active
// Sieve script, given its already-validated "local@domain" address (see
// internal/valid.Address). Addresses only ever contain characters valid in a
// filename component, so this cannot escape the bundle's sieve directory.
func SieveFileName(address string) string {
	return address + ".sieve"
}
