package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"go.yaml.in/yaml/v3"
)

// ErrNoConfig is returned by Discover when the config directory holds no config file.
var ErrNoConfig = errors.New("no config file")

// configExts are the accepted extensions of the single config file config.<ext>.
var configExts = []string{"toml", "yaml", "yml", "json"}

// Discover returns the one config file dir/config.<ext>. Several config files
// are an error, not a silent choice.
func Discover(dir string) (string, error) {
	var found []string
	for _, ext := range configExts {
		p := filepath.Join(dir, "config."+ext)
		fi, err := os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("config: stat %s: %w", p, err)
		}
		if !fi.Mode().IsRegular() {
			return "", fmt.Errorf("%w: %s is not a regular file", ErrInvalidConfig, p)
		}
		found = append(found, p)
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("%w in %s (expected config.toml, config.yaml, config.yml or config.json)", ErrNoConfig, dir)
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("%w: several config files in %s (%s): keep exactly one", ErrInvalidConfig, dir, strings.Join(found, ", "))
	}
}

// readTOML returns the config file as TOML text. YAML and JSON are converted to
// TOML, so there is a single decoder and one set of validation rules.
func readTOML(path string) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator config path
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".toml":
		return data, nil
	case ".yaml", ".yml":
		var v any
		if err := yaml.Unmarshal(data, &v); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrInvalidConfig, path, err)
		}
		return encodeTOML(path, v)
	case ".json":
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrInvalidConfig, path, err)
		}
		return encodeTOML(path, v)
	default:
		return nil, fmt.Errorf("%w: unsupported config format %s", ErrInvalidConfig, path)
	}
}

// encodeTOML converts a decoded YAML or JSON document to TOML text.
func encodeTOML(path string, v any) ([]byte, error) {
	m, ok := normalize(v).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: %s: top level must be a mapping", ErrInvalidConfig, path)
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(m); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidConfig, path, err)
	}
	return buf.Bytes(), nil
}

// normalize turns YAML and JSON values into the types TOML can hold: string
// keyed maps, integers as int64, floats as float64.
func normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = normalize(x)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[fmt.Sprint(k)] = normalize(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = normalize(x)
		}
		return out
	case json.Number:
		if n, err := strconv.ParseInt(t.String(), 10, 64); err == nil {
			return n
		}
		f, _ := t.Float64()
		return f
	default:
		return v
	}
}

// ReadSecretsEnv returns the KEY=VALUE pairs of a legacy secrets.env. It applies
// the same permission rules as Load.
func ReadSecretsEnv(path string) (map[string]string, error) { return readSecretsFile(path) }

// HasSecretsTable reports whether the TOML config text already holds a
// [secrets] table. Migration only appends a new table, so it never duplicates one.
func HasSecretsTable(text []byte) bool {
	return regexp.MustCompile(`(?m)^\s*\[secrets\]\s*(#.*)?$`).Match(text)
}

// SecretsTOML renders m as a [secrets] table, keys sorted, values quoted.
func SecretsTOML(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if m[k] != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("\n[secrets]\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s = %s\n", k, strconv.Quote(m[k]))
	}
	return b.String()
}

// WithoutSecrets returns the config at path as TOML with the [secrets] table
// removed. A backup bundle stores this copy, so it never holds API tokens or
// the rspamd controller password. YAML and JSON are converted first.
func WithoutSecrets(path string) ([]byte, error) {
	text, err := readTOML(path)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if _, err := toml.Decode(string(text), &m); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidConfig, path, err)
	}
	delete(m, "secrets")
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(m); err != nil {
		return nil, fmt.Errorf("encode %s: %w", path, err)
	}
	return buf.Bytes(), nil
}
