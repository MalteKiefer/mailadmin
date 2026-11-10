package install

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Repo is a vendor apt repository that install adds next to the distribution
// archive. The key is fetched over https, its fingerprint must be confirmed by
// the operator against the vendor's published value, and apt is told to trust
// only that key for this repository (Signed-By).
type Repo struct {
	Name       string // file stem for the keyring and the sources entry
	KeyURL     string // vendor key, ASCII armored
	URI        string
	Suites     string
	Components string
}

// KeyringPath is where the dearmored key is stored.
func (r Repo) KeyringPath() string { return "/usr/share/keyrings/" + r.Name + ".gpg" }

// SourcesPath is the deb822 sources file for the repository.
func (r Repo) SourcesPath() string { return "/etc/apt/sources.list.d/" + r.Name + ".sources" }

// Sources renders the deb822 entry.
func (r Repo) Sources() string {
	return fmt.Sprintf("Types: deb\nURIs: %s\nSuites: %s\nComponents: %s\nSigned-By: %s\n",
		r.URI, r.Suites, r.Components, r.KeyringPath())
}

// PostgresRepo is the PostgreSQL Global Development Group repository, the
// upstream source the PostgreSQL project documents for Debian and Ubuntu.
func PostgresRepo(codename string) Repo {
	return Repo{
		Name:       "pgdg",
		KeyURL:     "https://www.postgresql.org/media/keys/ACCC4CF8.asc",
		URI:        "https://apt.postgresql.org/pub/repos/apt",
		Suites:     codename + "-pgdg",
		Components: "main",
	}
}

// CaddyRepo is the official Caddy stable repository, hosted by Cloudsmith.
func CaddyRepo() Repo {
	return Repo{
		Name:       "caddy-stable",
		KeyURL:     "https://dl.cloudsmith.io/public/caddy/stable/gpg.key",
		URI:        "https://dl.cloudsmith.io/public/caddy/stable/deb/debian",
		Suites:     "any-version",
		Components: "main",
	}
}

// VendorRepos are the third-party repositories install adds, in order. The
// install loop and the unattended-upgrades origins both come from this list.
func VendorRepos(codename string) []Repo {
	return []Repo{PostgresRepo(codename), CaddyRepo(), CrowdSecRepo()}
}

// CrowdSecRepo is the official CrowdSec repository, hosted by packagecloud. It
// carries the agent and the nftables bouncer.
func CrowdSecRepo() Repo {
	return Repo{
		Name:       "crowdsec",
		KeyURL:     "https://packagecloud.io/crowdsec/crowdsec/gpgkey",
		URI:        "https://packagecloud.io/crowdsec/crowdsec/any",
		Suites:     "any",
		Components: "main",
	}
}

// FetchKey downloads a vendor key over https with a timeout and a size cap.
func FetchKey(ctx context.Context, url string) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("key url must be https: %s", url)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch key: %w", err)
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch key %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch key %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", url, err)
	}
	return body, nil
}

// KeyFingerprint returns the primary fingerprint gpg computes for an armored
// key. It is derived locally, never taken from the download.
func KeyFingerprint(ctx context.Context, x Exec, armored []byte) (string, error) {
	res, err := x.Run(ctx, armored, "gpg", "--batch", "--with-colons",
		"--import-options", "show-only", "--import")
	if err != nil {
		return "", fmt.Errorf("read key: %w", err)
	}
	return parseFingerprint(res.Stdout)
}

// parseFingerprint returns the primary key fingerprint of gpg colon output (the
// fpr record that follows the pub record; later fpr records belong to subkeys).
// The download must hold exactly one primary key: gpg --dearmor puts every key
// into the keyring apt trusts for the repository, so a second key appended to
// the genuine one would be trusted without ever being checked.
func parseFingerprint(colons []byte) (string, error) {
	pubs := 0
	fpr := ""
	for _, line := range strings.Split(string(colons), "\n") {
		f := strings.Split(line, ":")
		switch {
		case f[0] == "pub":
			pubs++
		case pubs == 1 && fpr == "" && len(f) > 9 && f[0] == "fpr" && f[9] != "":
			fpr = normalizeFingerprint(f[9])
		}
	}
	if pubs > 1 {
		return "", fmt.Errorf("the key download holds %d primary keys, expected exactly one: refusing to trust it", pubs)
	}
	if fpr == "" {
		return "", errors.New("gpg reported no fingerprint for the key")
	}
	return fpr, nil
}

// normalizeFingerprint compares fingerprints without spaces and case.
func normalizeFingerprint(s string) string {
	return strings.ToUpper(strings.ReplaceAll(s, " ", ""))
}

// InstallRepo writes the dearmored keyring and the sources entry. The key's
// primary fingerprint must equal confirmed, the value the operator checked
// against the vendor's published fingerprint. A mismatch installs nothing.
func InstallRepo(ctx context.Context, x Exec, r Repo, armored []byte, confirmed string) error {
	got, err := KeyFingerprint(ctx, x, armored)
	if err != nil {
		return err
	}
	if got != normalizeFingerprint(confirmed) {
		return fmt.Errorf("%s key fingerprint is %s, expected %s: refusing to install",
			r.Name, got, normalizeFingerprint(confirmed))
	}
	// apt verifies as the _apt user, so the keyring must be world-readable. It is
	// renamed into place with an explicit mode, which also repairs a keyring an
	// earlier run left unreadable.
	res, err := x.Run(ctx, armored, "gpg", "--batch", "--dearmor")
	if err != nil {
		return fmt.Errorf("dearmor %s key: %w", r.Name, err)
	}
	if err := writeAtomic(r.KeyringPath(), res.Stdout, 0o644); err != nil {
		return fmt.Errorf("write %s keyring: %w", r.Name, err)
	}
	if err := writeAtomic(r.SourcesPath(), []byte(r.Sources()), 0o644); err != nil {
		return fmt.Errorf("write %s sources: %w", r.Name, err)
	}
	return nil
}
