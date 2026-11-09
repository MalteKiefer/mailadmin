package webserver

import (
	"fmt"
	"os"
	"path/filepath"
)

// MTASTSPolicy renders the policy served at /.well-known/mta-sts.txt. Every
// hosted domain delivers to the same mail host, so one policy covers them all.
// The mode is "testing": receivers report failures instead of refusing mail,
// so a broken TLS setup does not block delivery. Switch to "enforce" once the
// reports look clean.
func MTASTSPolicy(mxHost string) string {
	return fmt.Sprintf("version: STSv1\nmode: testing\nmx: %s\nmax_age: 604800\n", mxHost)
}

// WriteMTASTSPolicy writes the policy file under the MTA-STS web root that the
// mta-sts.<domain> Caddy site serves. Without it the endpoint answers 404.
func (m *Manager) WriteMTASTSPolicy(mxHost string) error {
	dir := filepath.Join(m.mtaStsRoot, ".well-known")
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- served by Caddy, world-readable
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return writeFileAtomic(filepath.Join(dir, "mta-sts.txt"), []byte(MTASTSPolicy(mxHost)), 0o644)
}
