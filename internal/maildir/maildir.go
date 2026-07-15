// Package maildir performs filesystem operations on a virtual mailbox's Maildir
// under a fixed root (/var/vmail/<domain>/<user>). Purge and dedupe touch only
// files inside that computed path; no external command is executed and no shell
// is involved. Addresses are validated by the caller (internal/valid) and the
// resulting path is confined to Root so a crafted local-part/domain cannot
// escape the mail spool.
package maildir

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultRoot is the virtual-mailbox storage root (dovecot mail_location).
const DefaultRoot = "/var/vmail"

// ErrOutsideRoot is returned when a computed mailbox path would escape Root.
var ErrOutsideRoot = errors.New("maildir: path escapes mail root")

// ErrNotFound is returned when a mailbox's Maildir does not exist on disk.
var ErrNotFound = errors.New("maildir: not found")

// Manager resolves and operates on Maildir paths under Root.
type Manager struct {
	root string
}

// New builds a Manager. An empty root uses DefaultRoot.
func New(root string) *Manager {
	if root == "" {
		root = DefaultRoot
	}
	return &Manager{root: filepath.Clean(root)}
}

// path returns the confined /var/vmail/<domain>/<user> directory for an address.
// It rejects any result that is not strictly inside Root (defence in depth on
// top of caller-side address validation).
func (m *Manager) path(local, domain string) (string, error) {
	if local == "" || domain == "" ||
		strings.ContainsAny(local, "/\x00") || strings.ContainsAny(domain, "/\x00") {
		return "", fmt.Errorf("%w: %s@%s", ErrOutsideRoot, local, domain)
	}
	p := filepath.Clean(filepath.Join(m.root, domain, local))
	rootPrefix := m.root + string(os.PathSeparator)
	if p != m.root && !strings.HasPrefix(p, rootPrefix) {
		return "", fmt.Errorf("%w: %s", ErrOutsideRoot, p)
	}
	return p, nil
}

// Exists reports whether the mailbox directory is present.
func (m *Manager) Exists(local, domain string) (bool, error) {
	p, err := m.path(local, domain)
	if err != nil {
		return false, err
	}
	fi, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return fi.IsDir(), nil
}

// Purge deletes the mailbox directory tree. A missing directory is reported via
// ErrNotFound so the caller can surface a clear message.
func (m *Manager) Purge(local, domain string) error {
	p, err := m.path(local, domain)
	if err != nil {
		return err
	}
	if fi, statErr := os.Stat(p); errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrNotFound, p)
	} else if statErr != nil {
		return statErr
	} else if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrOutsideRoot, p)
	}
	if err := os.RemoveAll(p); err != nil {
		return fmt.Errorf("maildir purge: %w", err)
	}
	return nil
}

// DedupeReport summarises a dedupe pass.
type DedupeReport struct {
	DryRun  bool  `json:"dry_run"`
	Kept    int   `json:"kept"`
	Deleted int   `json:"deleted"`
	Skipped int   `json:"skipped"` // messages without a usable Message-ID
	Bytes   int64 `json:"reclaimed_bytes"`
}

// folderOrder lists maildir subfolders in keep-priority order: the first copy of
// a Message-ID seen (highest-priority folder) is retained, later copies removed.
var folderOrder = []string{
	"cur", "new",
	".Sent/cur", ".Sent/new",
	".Archive/cur", ".Archive/new",
	".Drafts/cur", ".Drafts/new",
	".Junk/cur", ".Junk/new",
	".Trash/cur", ".Trash/new",
}

// Dedupe removes duplicate messages (same Message-ID) from the mailbox's
// Maildir, keeping the first occurrence in folder-priority order. With dryRun
// true it counts duplicates without deleting anything. The mailbox's message
// files are read locally; no external process runs.
func (m *Manager) Dedupe(local, domain string, dryRun bool) (DedupeReport, error) {
	p, err := m.path(local, domain)
	if err != nil {
		return DedupeReport{}, err
	}
	box := filepath.Join(p, "Maildir")
	if fi, statErr := os.Stat(box); errors.Is(statErr, os.ErrNotExist) || (statErr == nil && !fi.IsDir()) {
		return DedupeReport{}, fmt.Errorf("%w: %s", ErrNotFound, box)
	} else if statErr != nil {
		return DedupeReport{}, statErr
	}

	rep := DedupeReport{DryRun: dryRun}
	seen := make(map[string]struct{})

	for _, sub := range folderOrder {
		dir := filepath.Join(box, sub)
		entries, derr := os.ReadDir(dir)
		if errors.Is(derr, os.ErrNotExist) {
			continue
		}
		if derr != nil {
			return rep, fmt.Errorf("maildir dedupe: read %s: %w", sub, derr)
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.Type().IsRegular() && !strings.HasPrefix(e.Name(), ".") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			fp := filepath.Join(dir, name)
			mid, ok := messageID(fp)
			if !ok {
				rep.Skipped++
				continue
			}
			if _, dup := seen[mid]; dup {
				if fi, serr := os.Stat(fp); serr == nil {
					rep.Bytes += fi.Size()
				}
				if !dryRun {
					if rmErr := os.Remove(fp); rmErr != nil {
						continue
					}
				}
				rep.Deleted++
				continue
			}
			seen[mid] = struct{}{}
			rep.Kept++
		}
	}
	return rep, nil
}

// messageID extracts a lower-cased, angle-stripped Message-ID from a message
// file header block. It stops at the first blank line (end of headers) and
// never reads the body, bounding work on large messages.
func messageID(path string) (string, bool) {
	// path is a Maildir message file enumerated from the mailbox directory the
	// operator selected; not an untrusted external input.
	f, err := os.Open(path) // #nosec G304 -- local Maildir message path walked from the mailbox dir
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			return "", false
		}
		if len(line) >= 11 && strings.EqualFold(line[:11], "message-id:") {
			v := strings.TrimSpace(line[11:])
			v = strings.TrimPrefix(v, "<")
			v = strings.TrimSuffix(v, ">")
			v = strings.TrimSpace(v)
			if v == "" {
				return "", false
			}
			return strings.ToLower(v), true
		}
	}
	return "", false
}
