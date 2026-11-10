package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The backup bundle copy must not carry the [secrets] table, in any input format.
func TestWithoutSecretsDropsSecretsTable(t *testing.T) {
	cases := map[string]string{
		"config.toml": "[mail]\nhostname = \"mx.example.com\"\n\n[secrets]\nDESEC_TOKEN = \"tok\"\n",
		"config.yaml": "mail:\n  hostname: mx.example.com\nsecrets:\n  DESEC_TOKEN: tok\n",
		"config.json": `{"mail":{"hostname":"mx.example.com"},"secrets":{"DESEC_TOKEN":"tok"}}`,
	}
	for name, body := range cases {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := WithoutSecrets(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(string(out), "tok") || strings.Contains(string(out), "secrets") {
			t.Fatalf("%s: secrets left in bundle copy:\n%s", name, out)
		}
		if !strings.Contains(string(out), "mx.example.com") {
			t.Fatalf("%s: non-secret values lost:\n%s", name, out)
		}
	}
}
