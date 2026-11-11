package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// reBundle matches the directory names BundleName produces, and nothing else.
var reBundle = regexp.MustCompile(`^mailadmin-[0-9]{8}T[0-9]{6}Z$`)

// ErrLocalKeep is returned for a keep count below 1. Pruning never removes every bundle.
var ErrLocalKeep = errors.New("backup: local bundle retention must keep at least one bundle")

// PruneLocalBundles removes the bundle directories in dir except the newest keep. Only
// directories named like a bundle are touched. The caller must call it only after the
// bundles were archived. It returns the removed names.
func PruneLocalBundles(dir string, keep int) ([]string, error) {
	if keep < 1 {
		return nil, ErrLocalKeep
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() && reBundle.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	// Names carry a UTC timestamp, so lexical order is time order.
	sort.Strings(names)
	if len(names) <= keep {
		return nil, nil
	}
	var removed []string
	for _, name := range names[:len(names)-keep] {
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			return removed, fmt.Errorf("remove local bundle %s: %w", name, err)
		}
		removed = append(removed, name)
	}
	return removed, nil
}
