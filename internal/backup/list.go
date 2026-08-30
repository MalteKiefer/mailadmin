package backup

import (
	"os"
	"path/filepath"
	"sort"
)

// BundleInfo summarises one discovered bundle for `backup list`.
type BundleInfo struct {
	Path  string
	Name  string
	Bytes int64

	Manifest Manifest
	// ManifestErr is set when manifest.json is missing or unreadable; the
	// bundle is still listed (so a broken/partial bundle stays visible)
	// with a zero Manifest.
	ManifestErr error
}

// ListBundles scans dir for immediate subdirectories containing a
// manifest.json and returns them newest-first (bundle names sort
// lexicographically by their UTC timestamp, so string order is chronological
// order). A missing dir is not an error: it just means no backups exist yet.
func ListBundles(dir string) ([]BundleInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []BundleInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if _, err := os.Stat(filepath.Join(path, ManifestFile)); err != nil {
			continue // not a bundle directory
		}
		bi := BundleInfo{Path: path, Name: e.Name()}
		bi.Manifest, bi.ManifestErr = ReadManifest(path)
		bi.Bytes, _ = DirSize(path)
		out = append(out, bi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}
