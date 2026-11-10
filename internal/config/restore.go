package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// MergeRestored returns the config a restore writes to livePath. The bundle copy
// is the base. Its [secrets] table is kept when it has one (bundles from before
// v1.29.2 carry the secrets); otherwise the table of the live config is kept, so a
// restore never drops API tokens or the rspamd controller password. Restore writes
// TOML only: a live config in YAML or JSON is refused rather than overwritten with
// TOML under a .yaml or .json name.
func MergeRestored(bundle []byte, livePath string) ([]byte, error) {
	if ext := strings.ToLower(filepath.Ext(livePath)); ext != ".toml" {
		return nil, fmt.Errorf("live config %s is %s: restore writes config.toml only, convert the file to TOML first", livePath, ext)
	}
	var bm map[string]any
	if _, err := toml.Decode(string(bundle), &bm); err != nil {
		return nil, fmt.Errorf("%w: bundle config: %w", ErrInvalidConfig, err)
	}
	if !hasTable(bm["secrets"]) {
		live, err := liveSecrets(livePath)
		if err != nil {
			return nil, err
		}
		if live != nil {
			bm["secrets"] = live
		} else {
			delete(bm, "secrets")
		}
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(bm); err != nil {
		return nil, fmt.Errorf("encode restored config: %w", err)
	}
	return buf.Bytes(), nil
}

// hasTable reports whether v is a non-empty table.
func hasTable(v any) bool {
	m, ok := v.(map[string]any)
	return ok && len(m) > 0
}

// liveSecrets returns the [secrets] table of the live config at path, or nil when
// there is no live config or it holds no secrets.
func liveSecrets(path string) (map[string]any, error) {
	text, err := os.ReadFile(path) // #nosec G304 -- operator config path
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read live config %s: %w", path, err)
	}
	var m map[string]any
	if _, err := toml.Decode(string(text), &m); err != nil {
		return nil, fmt.Errorf("%w: live config %s: %w", ErrInvalidConfig, path, err)
	}
	if !hasTable(m["secrets"]) {
		return nil, nil
	}
	return m["secrets"].(map[string]any), nil
}

// WriteSecretFile replaces path with data at mode 0600. The data goes to a temp
// file next to the target and is renamed into place, so a crash leaves either the
// old or the new file. A symlink at path is followed, so an operator-managed link
// keeps pointing at its target.
func WriteSecretFile(path string, data []byte) error {
	target, err := filepath.EvalSymlinks(path)
	if errors.Is(err, fs.ErrNotExist) {
		target = danglingTarget(path)
	} else if err != nil {
		return fmt.Errorf("resolve %s: %w", path, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".*")
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", target, err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", target, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod %s: %w", target, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync %s: %w", target, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", target, err)
	}
	if err := os.Rename(name, target); err != nil {
		return fmt.Errorf("install %s: %w", target, err)
	}
	return nil
}

// danglingTarget returns the file a dangling symlink at path names, following a
// chain of links up to a fixed depth. Writing there creates that file, as writing through the link did before,
// instead of replacing the link. Any other path is returned unchanged.
func danglingTarget(path string) string {
	const maxLinks = 16
	for i := 0; i < maxLinks; i++ {
		fi, err := os.Lstat(path)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			return path
		}
		link, err := os.Readlink(path)
		if err != nil {
			return path
		}
		if !filepath.IsAbs(link) {
			link = filepath.Join(filepath.Dir(path), link)
		}
		path = link
	}
	return path
}
