package dnsprovider

import (
	"crypto/tls"
	"net/http"
	"time"
)

// newHTTPClient returns the HTTP client used for all registrar API calls. TLS
// 1.2+ is pinned explicitly (rather than relying on the Go default) so the
// minimum stays fixed if a future Go release changes its default, and cert
// verification is always on (no InsecureSkipVerify).
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}
