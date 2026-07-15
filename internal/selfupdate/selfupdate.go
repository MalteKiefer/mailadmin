// Package selfupdate checks GitHub for a newer mailadmin release and, on
// request, replaces the running binary with it.
//
// Security properties:
//   - All network calls go to fixed api.github.com / release-asset URLs — no
//     user-controlled endpoint (no SSRF surface).
//   - TLS 1.2+ with certificate verification (no InsecureSkipVerify).
//   - The downloaded binary is verified against the SHA256SUMS file published
//     with the release before it is installed; a mismatch aborts.
//   - Installation is atomic: the new binary is written to a temp file in the
//     same directory and renamed over the target, preserving its mode.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	repoOwner = "MalteKiefer"
	repoName  = "mailadmin"

	// checksumsAsset is the release asset listing "<sha256>  <filename>" lines.
	checksumsAsset = "SHA256SUMS"

	httpTimeout    = 30 * time.Second
	maxJSONBytes   = 1 << 20  // 1 MiB: a release payload is far smaller
	maxSumsBytes   = 64 << 10 // 64 KiB
	maxBinaryBytes = 128 << 20
)

// ErrNoAsset is returned when the release has no binary for this OS/arch.
var ErrNoAsset = errors.New("selfupdate: no release asset for this platform")

// ErrChecksumMismatch is returned when the downloaded binary does not match the
// published SHA256SUMS entry.
var ErrChecksumMismatch = errors.New("selfupdate: checksum mismatch")

// Release is the subset of a GitHub release we consume.
type Release struct {
	Tag    string  `json:"tag_name"`
	Assets []Asset `json:"assets"`
}

// Asset is a single downloadable release artifact.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

// AssetName is the artifact name the release workflow publishes for the current
// platform, e.g. "mailadmin-linux-amd64".
func AssetName() string {
	return fmt.Sprintf("%s-%s-%s", repoName, runtime.GOOS, runtime.GOARCH)
}

func newClient() *http.Client {
	return &http.Client{
		Timeout: httpTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}

// Latest fetches the most recent published release.
func Latest(ctx context.Context) (Release, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", repoOwner, repoName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", repoName+"/"+"selfupdate")

	resp, err := newClient().Do(req)
	if err != nil {
		return Release{}, fmt.Errorf("selfupdate: query latest release: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("selfupdate: github returned %s", resp.Status)
	}
	var rel Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJSONBytes)).Decode(&rel); err != nil {
		return Release{}, fmt.Errorf("selfupdate: decode release: %w", err)
	}
	if rel.Tag == "" {
		return Release{}, errors.New("selfupdate: release has no tag")
	}
	return rel, nil
}

// IsNewer reports whether latest is a strictly higher semantic version than
// current. A non-numeric current (e.g. "dev") is treated as older so a real
// release is always offered; a non-numeric latest is never considered newer.
func IsNewer(current, latest string) bool {
	lv, ok := parseSemver(latest)
	if !ok {
		return false
	}
	cv, ok := parseSemver(current)
	if !ok {
		return true
	}
	for i := 0; i < 3; i++ {
		if lv[i] != cv[i] {
			return lv[i] > cv[i]
		}
	}
	return false
}

// parseSemver parses "vX.Y.Z" / "X.Y.Z" (ignoring any pre-release/build suffix)
// into a [3]int. ok is false if it is not of that shape.
func parseSemver(s string) ([3]int, bool) {
	var out [3]int
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// assetFor returns the download URL of the platform binary in rel.
func assetFor(rel Release) (string, error) {
	want := AssetName()
	for _, a := range rel.Assets {
		if a.Name == want {
			return a.URL, nil
		}
	}
	return "", fmt.Errorf("%w: %s", ErrNoAsset, want)
}

// checksumsURL returns the SHA256SUMS asset URL in rel.
func checksumsURL(rel Release) (string, error) {
	for _, a := range rel.Assets {
		if a.Name == checksumsAsset {
			return a.URL, nil
		}
	}
	return "", fmt.Errorf("selfupdate: release has no %s", checksumsAsset)
}

// Apply downloads the platform binary from rel, verifies it against the
// release's SHA256SUMS, and atomically replaces the currently running
// executable. It requires write permission on the executable and its directory
// (i.e. root for a system install).
func Apply(ctx context.Context, rel Release) error {
	binURL, err := assetFor(rel)
	if err != nil {
		return err
	}
	sumsURL, err := checksumsURL(rel)
	if err != nil {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("selfupdate: locate executable: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("selfupdate: resolve executable: %w", err)
	}

	wantSum, err := fetchChecksum(ctx, sumsURL, AssetName())
	if err != nil {
		return err
	}

	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".mailadmin-update-*")
	if err != nil {
		return fmt.Errorf("selfupdate: create temp: %w", err)
	}
	tmpName := tmp.Name()
	// Clean up the temp file on any failure path.
	success := false
	defer func() {
		_ = tmp.Close()
		if !success {
			_ = os.Remove(tmpName)
		}
	}()

	gotSum, err := download(ctx, binURL, tmp)
	if err != nil {
		return err
	}
	if gotSum != wantSum {
		return fmt.Errorf("%w: got %s want %s", ErrChecksumMismatch, gotSum, wantSum)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("selfupdate: close temp: %w", err)
	}

	// Preserve the current binary's mode; default to 0755 if it cannot be read.
	mode := os.FileMode(0o755)
	if fi, statErr := os.Stat(exe); statErr == nil {
		mode = fi.Mode().Perm()
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return fmt.Errorf("selfupdate: chmod: %w", err)
	}
	if err := os.Rename(tmpName, exe); err != nil {
		return fmt.Errorf("selfupdate: install (need write access to %s): %w", exe, err)
	}
	success = true
	return nil
}

// download streams url into w and returns the hex SHA-256 of the bytes written.
func download(ctx context.Context, url string, w io.Writer) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", repoName+"/"+"selfupdate")
	resp, err := newClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("selfupdate: download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("selfupdate: download %s: %s", url, resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, maxBinaryBytes)); err != nil {
		return "", fmt.Errorf("selfupdate: download body: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// fetchChecksum downloads the SHA256SUMS file and returns the hex digest listed
// for filename.
func fetchChecksum(ctx context.Context, url, filename string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", repoName+"/"+"selfupdate")
	resp, err := newClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("selfupdate: fetch checksums: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("selfupdate: fetch checksums: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSumsBytes))
	if err != nil {
		return "", fmt.Errorf("selfupdate: read checksums: %w", err)
	}
	sum := parseChecksums(string(body), filename)
	if sum == "" {
		return "", fmt.Errorf("selfupdate: no checksum for %s", filename)
	}
	return sum, nil
}

// parseChecksums returns the digest for filename from "<sha256>  <name>" lines
// (the format produced by sha256sum), tolerating a leading "*" binary marker.
func parseChecksums(body, filename string) string {
	for _, line := range strings.Split(body, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name == filename {
			return strings.ToLower(fields[0])
		}
	}
	return ""
}
