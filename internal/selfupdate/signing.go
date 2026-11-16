package selfupdate

import (
	"bytes"
	"context"
	_ "embed" // release-signing-key.asc
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// releaseSigningFingerprint is the only key that may sign a release. The key is
// embedded, so a replaced release asset cannot bring its own key.
const releaseSigningFingerprint = "AB222289126C59D40BDFC707C82C7B375578C141"

//go:embed release-signing-key.asc
var releaseSigningKey string

// ErrUnsigned is returned when a release has no SHA256SUMS.asc signature asset.
var ErrUnsigned = errors.New("selfupdate: release has no SHA256SUMS.asc signature")

// ErrSignature is returned when SHA256SUMS does not verify against the pinned key.
var ErrSignature = errors.New("selfupdate: SHA256SUMS signature invalid")

// maxSigBytes bounds the detached signature download.
const maxSigBytes = 16 << 10

// signatureURL returns the SHA256SUMS.asc asset URL in rel.
func signatureURL(assets []Asset) (string, error) {
	for _, a := range assets {
		if a.Name == checksumsAsset+".asc" {
			return a.URL, nil
		}
	}
	return "", ErrUnsigned
}

// verifySums checks the detached signature over the SHA256SUMS body against the
// pinned release key. Any other signer, or a changed body, fails.
func verifySums(sums, sig []byte) error {
	all, err := openpgp.ReadArmoredKeyRing(strings.NewReader(releaseSigningKey))
	if err != nil {
		return fmt.Errorf("selfupdate: read embedded release key: %w", err)
	}
	var pinned openpgp.EntityList
	for _, e := range all {
		if strings.EqualFold(fmt.Sprintf("%X", e.PrimaryKey.Fingerprint), releaseSigningFingerprint) {
			pinned = append(pinned, e)
		}
	}
	if len(pinned) != 1 {
		return fmt.Errorf("selfupdate: embedded key does not carry pinned fingerprint %s", releaseSigningFingerprint)
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(pinned, bytes.NewReader(sums), bytes.NewReader(sig), nil); err != nil {
		return fmt.Errorf("%w: %w", ErrSignature, err)
	}
	return nil
}

// fetchBody downloads url, bounded to limit bytes.
func fetchBody(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", repoName+"/"+"selfupdate")
	resp, err := newClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("selfupdate: fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("selfupdate: fetch %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}
