package dnsprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mailadmin/internal/valid"
)

// Snapshot is a full point-in-time copy of a zone's records, taken before any
// destructive change so it can be restored. It is what "back up all records"
// produces.
type Snapshot struct {
	Domain   string    `json:"domain"`
	Provider string    `json:"provider"`
	TakenAt  time.Time `json:"taken_at"`
	Records  []Record  `json:"records"`
}

// Backup fetches every record in the zone (unfiltered) so the operator can
// save it before a takeover.
func Backup(ctx context.Context, p Provider, domain string) (Snapshot, error) {
	recs, err := p.ListRecords(ctx, domain)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Domain: domain, Provider: p.Name(), TakenAt: time.Now().UTC(), Records: recs}, nil
}

// WriteSnapshot persists a snapshot as pretty JSON under dir, named
// <domain>-<timestamp>.json, and returns the full path. dir is created 0700.
func WriteSnapshot(dir string, s Snapshot) (string, error) {
	// Re-validate the domain at the sink: it is normally validated upstream, but
	// this guarantees the filename component can never contain a path separator
	// (or "..") regardless of caller, keeping the write confined to dir.
	if _, err := valid.Domain(s.Domain); err != nil {
		return "", fmt.Errorf("write snapshot: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s-%s.json", s.Domain, s.TakenAt.Format("20060102T150405Z"))
	path := filepath.Join(dir, name)
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// LoadSnapshot reads a snapshot JSON file (for restore/undo).
func LoadSnapshot(path string) (Snapshot, error) {
	var s Snapshot
	// path is a snapshot file named by the local root operator on the command
	// line; there is no untrusted (network/user-account) input here.
	b, err := os.ReadFile(path) // #nosec G304 -- operator-supplied local snapshot path (root CLI)
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

// TakeoverResult reports what a ReplaceAll did (for the audit log + UI).
type TakeoverResult struct {
	BackupPath string   `json:"backup_path,omitempty"`
	Removed    []Record `json:"removed"`
	Added      []Record `json:"added"`
}

// ReplaceAll performs the domain-onboarding takeover: it MUST be given a
// backupDir so the current zone is snapshotted first, then EVERY existing
// record is removed and the desired mail record-set is added. This is
// destructive — callers must confirm and be admin-gated.
//
// If protectApexWeb is true, existing apex/www A/AAAA/CNAME records are kept
// (so publishing mail DNS does not knock a website offline). Set false for a
// pure mail zone.
func ReplaceAll(ctx context.Context, p Provider, domain, backupDir string, desired []Record, protectApexWeb bool) (TakeoverResult, error) {
	var res TakeoverResult
	snap, err := Backup(ctx, p, domain)
	if err != nil {
		return res, fmt.Errorf("backup: %w", err)
	}
	path, err := WriteSnapshot(backupDir, snap)
	if err != nil {
		return res, fmt.Errorf("save backup: %w", err)
	}
	res.BackupPath = path

	for _, r := range snap.Records {
		if protectApexWeb && isApexWeb(r) {
			continue
		}
		if r.ID == "" {
			continue
		}
		if err := p.RemoveRecord(ctx, domain, r.ID); err != nil {
			return res, fmt.Errorf("remove %s %s (backup kept at %s): %w", r.Type, r.Name, path, err)
		}
		res.Removed = append(res.Removed, r)
	}
	for _, d := range desired {
		if err := p.AddRecord(ctx, domain, d); err != nil {
			return res, fmt.Errorf("add %s %s (backup at %s): %w", d.Type, d.Name, path, err)
		}
		res.Added = append(res.Added, d)
	}
	return res, nil
}

// Restore wipes the current zone and re-adds every record from a snapshot —
// the undo for ReplaceAll. Records keep their content; provider assigns new ids.
func Restore(ctx context.Context, p Provider, domain string, snap Snapshot) error {
	live, err := p.ListRecords(ctx, domain)
	if err != nil {
		return err
	}
	for _, r := range live {
		if r.ID == "" {
			continue
		}
		if err := p.RemoveRecord(ctx, domain, r.ID); err != nil {
			return fmt.Errorf("restore: remove %s: %w", r.Type, err)
		}
	}
	for _, r := range snap.Records {
		r.ID = ""
		if err := p.AddRecord(ctx, domain, r); err != nil {
			return fmt.Errorf("restore: add %s %s: %w", r.Type, r.Name, err)
		}
	}
	return nil
}

func isApexWeb(r Record) bool {
	n := strings.ToLower(normName(r.Name))
	if n != "@" && n != "www" {
		return false
	}
	switch strings.ToUpper(r.Type) {
	case "A", "AAAA", "CNAME":
		return true
	}
	return false
}
