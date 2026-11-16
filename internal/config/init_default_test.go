package config

import "testing"

// A newer release may ship keys an older binary does not know. Upgrades must
// still merge that default, so only its syntax is checked.
func TestCheckDefaultSyntaxAcceptsUnknownKeys(t *testing.T) {
	newer := []byte("[future]\nkey = true\n")
	if err := checkDefaultSyntax(newer); err != nil {
		t.Fatalf("newer default refused: %v", err)
	}
	if err := checkDefault(newer); err == nil {
		t.Fatal("config init must still refuse unknown keys")
	}
	if err := checkDefaultSyntax([]byte("[broken")); err == nil {
		t.Fatal("broken TOML accepted")
	}
}
