package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// NewDefaultKeys lists the keys (dotted paths) that the default config of a newer
// release has and the host config lacks. The [secrets] table is left out: its
// keys are filled in by the operator. The host file may be TOML, YAML or JSON.
func NewDefaultKeys(hostPath string, defaultText []byte) ([]string, error) {
	hostText, err := readTOML(hostPath)
	if err != nil {
		return nil, err
	}
	var host, def map[string]any
	if _, err := toml.Decode(string(hostText), &host); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidConfig, hostPath, err)
	}
	if _, err := toml.Decode(string(defaultText), &def); err != nil {
		return nil, fmt.Errorf("%w: default config: %w", ErrInvalidConfig, err)
	}
	var missing []string
	walkMissing("", def, host, &missing)
	sort.Strings(missing)
	return missing, nil
}

func walkMissing(prefix string, def, host map[string]any, out *[]string) {
	for k, dv := range def {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		if path == "secrets" {
			continue
		}
		hv, ok := host[k]
		if !ok {
			*out = append(*out, path)
			continue
		}
		dm, dIsMap := dv.(map[string]any)
		hm, hIsMap := hv.(map[string]any)
		if dIsMap && hIsMap {
			walkMissing(path, dm, hm, out)
		}
	}
}

// FormatKeys renders the missing keys for the operator.
func FormatKeys(keys []string) string { return strings.Join(keys, ", ") }
