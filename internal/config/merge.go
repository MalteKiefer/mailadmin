package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// MergeNewKeys adds every key of defaultText that the TOML config at hostPath
// lacks. Values and comments the operator wrote stay as they are. The [secrets]
// table is never touched. It returns the added key paths, sorted, and writes the
// file only when something was added. YAML and JSON configs are not merged.
func MergeNewKeys(hostPath string, defaultText []byte) ([]string, error) {
	if strings.ToLower(filepath.Ext(hostPath)) != ".toml" {
		return nil, fmt.Errorf("%w: %s: automatic merge needs a TOML config", ErrInvalidConfig, hostPath)
	}
	host, err := os.ReadFile(hostPath) // #nosec G304 -- operator config path
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", hostPath, err)
	}
	var hm, dm map[string]any
	if _, err := toml.Decode(string(host), &hm); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidConfig, hostPath, err)
	}
	if _, err := toml.Decode(string(defaultText), &dm); err != nil {
		return nil, fmt.Errorf("%w: default config: %w", ErrInvalidConfig, err)
	}

	m := &merger{inserts: map[string][]string{}}
	m.walk(nil, dm, hm)
	if len(m.added) == 0 {
		return nil, nil
	}
	out, err := m.apply(string(host))
	if err != nil {
		return nil, err
	}
	if _, err := toml.Decode(out, &map[string]any{}); err != nil {
		return nil, fmt.Errorf("merged config does not parse, nothing written: %w", err)
	}
	if err := WriteSecretFile(hostPath, []byte(out)); err != nil {
		return nil, err
	}
	sort.Strings(m.added)
	return m.added, nil
}

type merger struct {
	added   []string
	inserts map[string][]string // table path -> "key = value" lines
	blocks  []string            // whole tables missing from the host
}

func (m *merger) walk(prefix []string, dv, hv map[string]any) {
	keys := make([]string, 0, len(dv))
	for k := range dv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if len(prefix) == 0 && k == "secrets" {
			continue
		}
		path := append(append([]string{}, prefix...), k)
		dsub, dIsMap := dv[k].(map[string]any)
		if _, ok := hv[k]; !ok {
			if dIsMap {
				m.blocks = append(m.blocks, encodeTable(path, dsub))
				m.collect(path, dsub)
				continue
			}
			line := encodeKV(k, dv[k])
			m.inserts[strings.Join(prefix, ".")] = append(m.inserts[strings.Join(prefix, ".")], line)
			m.added = append(m.added, strings.Join(path, "."))
			continue
		}
		if hsub, ok := hv[k].(map[string]any); ok && dIsMap {
			m.walk(path, dsub, hsub)
		}
	}
}

// collect records the leaf paths of a whole missing table.
func (m *merger) collect(prefix []string, dv map[string]any) {
	for k, v := range dv {
		path := append(append([]string{}, prefix...), k)
		if sub, ok := v.(map[string]any); ok {
			m.collect(path, sub)
			continue
		}
		m.added = append(m.added, strings.Join(path, "."))
	}
}

// apply inserts the scalar keys below their table headers and appends the missing tables.
func (m *merger) apply(text string) (string, error) {
	lines := strings.Split(text, "\n")
	var b strings.Builder
	seen := map[string]bool{}
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
		t := strings.TrimSpace(l)
		if !strings.HasPrefix(t, "[") || strings.HasPrefix(t, "[[") {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(t, "["), "]")
		if ins, ok := m.inserts[name]; ok && !seen[name] {
			seen[name] = true
			for _, line := range ins {
				b.WriteString(line + "\n")
			}
		}
	}
	for name := range m.inserts {
		if !seen[name] {
			return "", fmt.Errorf("cannot place keys under [%s]: table header not found, add them by hand", name)
		}
	}
	for _, blk := range m.blocks {
		b.WriteString("\n" + blk)
	}
	return strings.TrimRight(b.String(), "\n") + "\n", nil
}

func encodeKV(k string, v any) string {
	var buf bytes.Buffer
	_ = toml.NewEncoder(&buf).Encode(map[string]any{k: v})
	return strings.TrimRight(buf.String(), "\n")
}

// encodeTable renders the table at path with its subtables. The header is written
// with its full path, so a table under an existing parent gets no second parent header.
func encodeTable(path []string, v map[string]any) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s]\n", strings.Join(path, "."))
	var subs []string
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, ok := v[k].(map[string]any); ok {
			subs = append(subs, k)
			continue
		}
		b.WriteString(encodeKV(k, v[k]) + "\n")
	}
	for _, k := range subs {
		b.WriteString("\n")
		b.WriteString(encodeTable(append(append([]string{}, path...), k), v[k].(map[string]any)))
	}
	return b.String()
}
