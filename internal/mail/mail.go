// Package mail handles DKIM key material (read/generate), the desired DNS
// record-set for a domain, and MTA-STS policy synchronisation. It reads keys
// from the rspamd DKIM directory and shells out (via internal/sys) to the
// privileged key generator and the MTA-STS sync helper.
package mail

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mailadmin/internal/dnsprovider"
	"mailadmin/internal/sys"
	"mailadmin/internal/valid"
)

// Privileged helper binaries (absolute paths, matching the old system). They
// are invoked with a validated (domain, selector) argument vector — never a
// shell string.
const (
	dkimGenBin  = "/usr/local/libexec/mailadmin-dkim-gen"
	dkimTTL     = 3600
	maxKeyBytes = 64 << 10 // 64 KiB: a DKIM .pub file is well under this
)

// ErrNoDKIMKey is returned by ReadDKIM when the public key file is absent.
var ErrNoDKIMKey = errors.New("mail: dkim public key not found")

// errMissingDKIMPrefix guards against a malformed/empty key file so callers
// never publish a DKIM record that would not validate.
var errMissingDKIMPrefix = errors.New("mail: missing v=DKIM1 prefix")

// DKIMKey is a DKIM keypair reference on disk.
type DKIMKey struct {
	Domain    string
	Selector  string
	PublicKey string // "v=DKIM1; k=rsa; p=..." record value
	PrivPath  string
	PubPath   string
}

// Manager reads and generates DKIM material and builds desired record-sets.
type Manager struct {
	runner   *sys.Runner
	dkimDir  string
	mailHost string
	ipv4     string
	ipv6     string
}

// New builds a Manager. dkimDir is the rspamd DKIM directory.
func New(runner *sys.Runner, dkimDir, mailHost, ipv4, ipv6 string) *Manager {
	return &Manager{runner: runner, dkimDir: dkimDir, mailHost: mailHost, ipv4: ipv4, ipv6: ipv6}
}

// paths returns the private/public key paths for a validated domain+selector,
// matching the layout written by mailadmin-dkim-gen: <dir>/<domain>.<sel>.key
// and <dir>/<domain>.<sel>.key.pub.
func (m *Manager) paths(domain, selector string) (priv, pub string) {
	base := filepath.Join(m.dkimDir, domain+"."+selector+".key")
	return base, base + ".pub"
}

// ReadDKIM loads the public DKIM record for domain+selector from disk. The
// rspamadm-generated .pub file is a BIND-style TXT record whose value is split
// across quoted segments; ReadDKIM joins them into the single record value.
func (m *Manager) ReadDKIM(domain, selector string) (DKIMKey, error) {
	domain, err := valid.Domain(domain)
	if err != nil {
		return DKIMKey{}, fmt.Errorf("mail.ReadDKIM: %w", err)
	}
	selector, err = valid.Selector(selector)
	if err != nil {
		return DKIMKey{}, fmt.Errorf("mail.ReadDKIM: %w", err)
	}
	priv, pub := m.paths(domain, selector)

	// pub is derived from the configured dkim_dir plus a validated domain and
	// selector (valid.Domain/valid.Selector above), so it cannot escape the key
	// directory; no untrusted path component reaches os.ReadFile.
	raw, err := os.ReadFile(pub) // #nosec G304 -- path built from validated domain/selector under fixed dkim_dir
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DKIMKey{}, fmt.Errorf("mail.ReadDKIM %s.%s: %w", domain, selector, ErrNoDKIMKey)
		}
		return DKIMKey{}, fmt.Errorf("mail.ReadDKIM: read %s: %w", pub, err)
	}
	if len(raw) > maxKeyBytes {
		raw = raw[:maxKeyBytes]
	}

	value, err := parseDKIMPublic(string(raw))
	if err != nil {
		return DKIMKey{}, fmt.Errorf("mail.ReadDKIM %s.%s: %w", domain, selector, err)
	}
	return DKIMKey{
		Domain:    domain,
		Selector:  selector,
		PublicKey: value,
		PrivPath:  priv,
		PubPath:   pub,
	}, nil
}

// GenerateDKIM generates (or regenerates) a DKIM keypair for domain+selector by
// invoking the privileged mailadmin-dkim-gen helper, then reads back the
// resulting public record. The helper is idempotent: it only creates a key when
// one does not already exist.
func (m *Manager) GenerateDKIM(ctx context.Context, domain, selector string) (DKIMKey, error) {
	domain, err := valid.Domain(domain)
	if err != nil {
		return DKIMKey{}, fmt.Errorf("mail.GenerateDKIM: %w", err)
	}
	selector, err = valid.Selector(selector)
	if err != nil {
		return DKIMKey{}, fmt.Errorf("mail.GenerateDKIM: %w", err)
	}
	if _, err := m.runner.Output(ctx, dkimGenBin, domain, selector); err != nil {
		return DKIMKey{}, fmt.Errorf("mail.GenerateDKIM %s.%s: %w", domain, selector, err)
	}
	key, err := m.ReadDKIM(domain, selector)
	if err != nil {
		return DKIMKey{}, fmt.Errorf("mail.GenerateDKIM: %w", err)
	}
	return key, nil
}

// DesiredRecords builds the desired DNS record-set for a domain, mirroring
// `mailadmin dns <domain>`. withMTASTS gates the _mta-sts + host records.
func (m *Manager) DesiredRecords(domain, selector, dkimValue string, withMTASTS bool) []dnsprovider.Record {
	return dnsprovider.DesiredMailRecords(domain, dnsprovider.MailRecordOpts{
		MailHost:   m.mailHost,
		IPv4:       m.ipv4,
		IPv6:       m.ipv6,
		Selector:   selector,
		DKIMValue:  dkimValue,
		TTL:        dkimTTL,
		WithMTASTS: withMTASTS,
	})
}

// parseDKIMPublic extracts the DKIM record value from a rspamadm dkim_keygen
// public-key file. That file has the form:
//
//	<sel>._domainkey IN TXT ( "v=DKIM1; k=rsa; "
//	        "p=MIIB...==" ) ;
//
// The value is the concatenation of every double-quoted segment. A bare
// "v=DKIM1;..." line (no quoting) is also accepted. The result must begin with
// the v=DKIM1 tag, else the file is treated as malformed.
func parseDKIMPublic(s string) (string, error) {
	joined := joinQuoted(s)
	if joined == "" {
		// Fall back to a single unquoted line (be liberal in what we accept).
		joined = firstDKIMLine(s)
	}
	joined = strings.TrimSpace(joined)
	if joined == "" {
		return "", errMissingDKIMPrefix
	}
	if !strings.HasPrefix(strings.ToLower(joined), "v=dkim1") {
		return "", errMissingDKIMPrefix
	}
	return joined, nil
}

// joinQuoted concatenates the contents of every double-quoted segment in s, in
// order. Segments are what rspamadm splits the long p= value into.
func joinQuoted(s string) string {
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if inQuote {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// firstDKIMLine returns the first non-empty line that starts with the v=DKIM1
// tag, used when the file is a plain unquoted record value.
func firstDKIMLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "v=dkim1") {
			return line
		}
	}
	return ""
}
