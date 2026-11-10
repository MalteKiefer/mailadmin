package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
)

// StateDir is mailadmin's state directory. The journal and the copies of the
// files install changed live here. It is a variable so tests can use a temp dir.
var StateDir = "/var/lib/mailadmin"

// ErrNoManifest is returned by LoadManifest when install has not run here.
var ErrNoManifest = errors.New("no install record found: nothing to uninstall")

// ManagedFile is one file install created or changed. Existed false means install
// created it, and uninstall removes it. Otherwise Backup names the saved original,
// which uninstall writes back with its mode and owner.
type ManagedFile struct {
	Path    string `json:"path"`
	Existed bool   `json:"existed"`
	Mode    uint32 `json:"mode,omitempty"`
	UID     int    `json:"uid,omitempty"`
	GID     int    `json:"gid,omitempty"`
	Backup  string `json:"backup,omitempty"`
}

// Manifest is the install record: what install changed on this host.
type Manifest struct {
	Version string        `json:"version"`
	Files   []ManagedFile `json:"files"`
	// Packages are the packages install installed (not those already present).
	Packages []string `json:"packages"`
	// PackagesAssumed is set when the host was installed before the journal
	// existed; the packages then come from install's package list, intersected
	// with what is installed now.
	PackagesAssumed bool     `json:"packages_assumed,omitempty"`
	Users           []string `json:"users"`
	Database        string   `json:"database,omitempty"`
	Roles           []string `json:"roles,omitempty"`
	NftTable        bool     `json:"nft_table,omitempty"`
}

func manifestPath() string { return filepath.Join(StateDir, "install.json") }
func originalsDir() string { return filepath.Join(StateDir, "originals") }

// journal is the active recorder. It is nil when nothing is being recorded, for
// example during uninstall, so restoring files does not record them again.
type journal struct {
	mu   sync.Mutex
	m    Manifest
	seen map[string]bool
}

var active *journal

// LoadManifest reads the install record of this host.
func LoadManifest() (*Manifest, error) {
	data, err := os.ReadFile(manifestPath()) // #nosec G304 -- fixed state path
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoManifest
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", manifestPath(), err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", manifestPath(), err)
	}
	return &m, nil
}

// BeginJournal starts recording the changes of an install run. An existing record
// is loaded and extended, so reruns never replace a saved original with a file
// install wrote earlier.
func BeginJournal(version string) error {
	j := &journal{seen: map[string]bool{}}
	m, err := LoadManifest()
	switch {
	case errors.Is(err, ErrNoManifest):
		j.m = Manifest{}
	case err != nil:
		return err
	default:
		j.m = *m
	}
	j.m.Version = version
	for _, f := range j.m.Files {
		j.seen[f.Path] = true
	}
	if err := os.MkdirAll(originalsDir(), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", originalsDir(), err)
	}
	if err := j.save(); err != nil {
		return err
	}
	active = j
	return nil
}

// EndJournal stops recording.
func EndJournal() { active = nil }

// recordFile saves the state of path before install changes it for the first time.
func recordFile(path string) error {
	if active == nil {
		return nil
	}
	return active.recordFile(path)
}

func (j *journal) recordFile(path string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.seen[path] {
		return nil
	}
	f := ManagedFile{Path: path}
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// install creates it; uninstall removes it.
	case err != nil:
		return fmt.Errorf("record %s: %w", path, err)
	case !fi.Mode().IsRegular():
		return fmt.Errorf("refusing to change %s: not a regular file", path)
	default:
		data, rerr := os.ReadFile(path) // #nosec G304 -- path install is about to change
		if rerr != nil {
			return fmt.Errorf("save original of %s: %w", path, rerr)
		}
		name := backupName(path)
		if werr := os.WriteFile(filepath.Join(originalsDir(), name), data, 0o600); werr != nil { // #nosec G306 -- state dir copy
			return fmt.Errorf("save original of %s: %w", path, werr)
		}
		f.Existed = true
		f.Backup = name
		f.Mode = uint32(fi.Mode().Perm())
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			f.UID, f.GID = int(st.Uid), int(st.Gid)
		}
	}
	j.seen[path] = true
	j.m.Files = append(j.m.Files, f)
	return j.save()
}

// RecordPackages notes packages install installed.
func RecordPackages(names []string) error {
	if active == nil {
		return nil
	}
	return active.update(func(m *Manifest) { m.Packages = unionSorted(m.Packages, names) })
}

// RecordUsers notes system users install created.
func RecordUsers(names ...string) error {
	if active == nil {
		return nil
	}
	return active.update(func(m *Manifest) { m.Users = unionSorted(m.Users, names) })
}

// RecordDatabase notes the database and roles install created.
func RecordDatabase(db string, roles []string) error {
	if active == nil {
		return nil
	}
	return active.update(func(m *Manifest) { m.Database, m.Roles = db, unionSorted(m.Roles, roles) })
}

// RecordNftTable notes that install created the mailadmin nftables table.
func RecordNftTable() error {
	if active == nil {
		return nil
	}
	return active.update(func(m *Manifest) { m.NftTable = true })
}

func (j *journal) update(fn func(*Manifest)) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	fn(&j.m)
	return j.save()
}

// save writes the record atomically and does not go through the journal itself.
func (j *journal) save() error {
	data, err := json.MarshalIndent(j.m, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(StateDir, ".install.json.*")
	if err != nil {
		return fmt.Errorf("write %s: %w", manifestPath(), err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, manifestPath())
}

func backupName(path string) string {
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:16])
}

func unionSorted(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// AssumePackages covers a host installed before the journal existed: its
// packages are taken from install's package list, minus the base system packages
// that install only depends on. The record marks them as assumed.
func AssumePackages(installed []string) error {
	if active == nil {
		return nil
	}
	have := map[string]bool{}
	for _, p := range installed {
		have[p] = true
	}
	var add []string
	for _, p := range AllPackages() {
		if have[p] && !basePackages[p] {
			add = append(add, p)
		}
	}
	return active.update(func(m *Manifest) {
		m.Packages = unionSorted(m.Packages, add)
		m.PackagesAssumed = true
	})
}

// basePackages are part of a usable base system; uninstall never purges them.
var basePackages = map[string]bool{
	"ca-certificates": true, "curl": true, "gnupg": true, "nftables": true,
	"iproute2": true, "openssl": true, "debconf-utils": true,
}
