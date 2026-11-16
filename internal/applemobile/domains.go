package applemobile

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ReadDomainList loads the allow-list written by WriteDomainList: one active domain
// per line. A missing file is an empty list.
func ReadDomainList(path string) (map[string]bool, error) {
	f, err := os.Open(path) // #nosec G304 -- fixed path from config
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]bool{}, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if d := strings.TrimSpace(sc.Text()); d != "" && !strings.HasPrefix(d, "#") {
			out[strings.ToLower(d)] = true
		}
	}
	return out, sc.Err()
}

// WriteDomainList atomically replaces the allow-list at path. The file holds domain
// names only and is world-readable, so the unprivileged web service can read it.
func WriteDomainList(path string, domains []string) error {
	names := append([]string(nil), domains...)
	sort.Strings(names)
	var b bytes.Buffer
	b.WriteString("# Managed by mailadmin. Active mail domains allowed in the Apple profile form.\n")
	for _, d := range names {
		if strings.ContainsAny(d, "\n\r \t") || d == "" {
			return fmt.Errorf("applemobile: invalid domain %q in allow-list", d)
		}
		b.WriteString(d + "\n")
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".apple-domains-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b.Bytes()); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}
