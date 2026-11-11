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

// MergeResult lists what a merge changed in the host config.
type MergeResult struct {
	Added    []string // key paths the host lacked, now present with the release default
	Obsolete []string // key paths the release no longer has, kept and marked
}

// MergeNewKeys brings the TOML config at hostPath in line with the release
// defaults in defaultText, for a release tagged tag. Every key the host lacks is
// added. Every key the host has but the defaults do not is kept, and a comment
// marks it as obsolete. Values, other comments and [secrets] stay as they are.
// The file is written only when something changed. YAML and JSON are not merged.
func MergeNewKeys(hostPath string, defaultText []byte, tag string) (MergeResult, error) {
	var res MergeResult
	if strings.ToLower(filepath.Ext(hostPath)) != ".toml" {
		return res, fmt.Errorf("%w: %s: automatic merge needs a TOML config", ErrInvalidConfig, hostPath)
	}
	host, err := os.ReadFile(hostPath) // #nosec G304 -- operator config path
	if err != nil {
		return res, fmt.Errorf("config: read %s: %w", hostPath, err)
	}
	var hm, dm map[string]any
	if _, err := toml.Decode(string(host), &hm); err != nil {
		return res, fmt.Errorf("%w: %s: %w", ErrInvalidConfig, hostPath, err)
	}
	if _, err := toml.Decode(string(defaultText), &dm); err != nil {
		return res, fmt.Errorf("%w: default config: %w", ErrInvalidConfig, err)
	}

	m := &merger{inserts: map[string][]string{}, marks: map[string][]string{}, tag: tag}
	m.walk(nil, dm, hm)
	m.findObsolete(nil, dm, hm)
	out, err := m.apply(string(host))
	if err != nil {
		return res, err
	}
	if len(m.added) == 0 && len(m.marked) == 0 {
		return res, nil
	}
	if _, err := toml.Decode(out, &map[string]any{}); err != nil {
		return res, fmt.Errorf("merged config does not parse, nothing written: %w", err)
	}
	if err := WriteSecretFile(hostPath, []byte(out)); err != nil {
		return res, err
	}
	sort.Strings(m.added)
	sort.Strings(m.marked)
	res.Added = m.added
	res.Obsolete = m.marked
	return res, nil
}

type merger struct {
	tag      string
	added    []string
	obsolete []string            // every obsolete key found
	marked   []string            // obsolete keys that got a new marker in this run
	inserts  map[string][]string // table path -> "key = value" lines to add
	marks    map[string][]string // table path -> obsolete keys to mark
	blocks   []string            // whole tables the host lacks
}

func (m *merger) walk(prefix []string, dv, hv map[string]any) {
	for _, k := range sortedKeys(dv) {
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
			name := strings.Join(prefix, ".")
			m.inserts[name] = append(m.inserts[name], encodeKV(k, dv[k]))
			m.added = append(m.added, strings.Join(path, "."))
			continue
		}
		if hsub, ok := hv[k].(map[string]any); ok && dIsMap {
			m.walk(path, dsub, hsub)
		}
	}
}

// findObsolete records host keys and tables the release defaults no longer have.
func (m *merger) findObsolete(prefix []string, dv, hv map[string]any) {
	for _, k := range sortedKeys(hv) {
		if len(prefix) == 0 && k == "secrets" {
			continue
		}
		path := append(append([]string{}, prefix...), k)
		dv1, ok := dv[k]
		if !ok {
			m.collectObsolete(path, hv[k])
			continue
		}
		hsub, hIsMap := hv[k].(map[string]any)
		dsub, dIsMap := dv1.(map[string]any)
		if hIsMap && dIsMap {
			m.findObsolete(path, dsub, hsub)
		}
	}
}

// collectObsolete marks every leaf of a host table or key the release dropped.
func (m *merger) collectObsolete(path []string, v any) {
	if sub, ok := v.(map[string]any); ok {
		for _, k := range sortedKeys(sub) {
			m.collectObsolete(append(append([]string{}, path...), k), sub[k])
		}
		return
	}
	name := strings.Join(path[:len(path)-1], ".")
	m.marks[name] = append(m.marks[name], path[len(path)-1])
	m.obsolete = append(m.obsolete, strings.Join(path, "."))
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

// apply inserts the missing scalar keys below their table headers, marks the
// obsolete keys and appends the missing tables.
func (m *merger) apply(text string) (string, error) {
	lines := strings.Split(text, "\n")
	var b strings.Builder
	cur, prev := "", ""
	seen := map[string]bool{}
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && !strings.HasPrefix(t, "[[") {
			cur = strings.TrimSuffix(strings.TrimPrefix(t, "["), "]")
		}
		if keys := m.marks[cur]; len(keys) > 0 && isKeyLine(t, keys) && !strings.HasPrefix(prev, markerPrefix) {
			fmt.Fprintf(&b, "%s%s: no longer read, safe to remove\n", markerPrefix, m.tag)
			m.marked = append(m.marked, cur+"."+strings.TrimSpace(strings.SplitN(t, "=", 2)[0]))
		}
		prev = strings.TrimSpace(l)
		b.WriteString(l)
		b.WriteString("\n")
		if !strings.HasPrefix(t, "[") {
			continue
		}
		if ins, ok := m.inserts[cur]; ok && !seen["ins/"+cur] {
			seen["ins/"+cur] = true
			for _, line := range ins {
				b.WriteString(line + "\n")
			}
		}
	}
	for name := range m.inserts {
		if !seen["ins/"+name] {
			return "", fmt.Errorf("cannot place keys under [%s]: table header not found, add them by hand", name)
		}
	}
	for _, blk := range m.blocks {
		b.WriteString("\n" + blk)
	}
	return strings.TrimRight(b.String(), "\n") + "\n", nil
}

const markerPrefix = "# obsolete since "

// isKeyLine reports whether the trimmed line assigns one of keys.
func isKeyLine(t string, keys []string) bool {
	for _, k := range keys {
		if strings.HasPrefix(t, k+" ") || strings.HasPrefix(t, k+"=") {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func encodeKV(k string, v any) string {
	var buf bytes.Buffer
	_ = toml.NewEncoder(&buf).Encode(map[string]any{k: v})
	return strings.TrimRight(buf.String(), "\n")
}

// encodeTable renders the table at path with its subtables. The header carries
// the full path, so a table under an existing parent gets no second parent header.
func encodeTable(path []string, v map[string]any) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s]\n", strings.Join(path, "."))
	var subs []string
	for _, k := range sortedKeys(v) {
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
