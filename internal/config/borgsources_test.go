package config

import (
	"testing"

	"github.com/BurntSushi/toml"
)

func TestBorgSourcesDecodesStringAndList(t *testing.T) {
	var a struct {
		Source BorgSources `toml:"source"`
	}
	if _, err := toml.Decode(`source = ""`, &a); err != nil || len(a.Source) != 0 {
		t.Fatalf("empty string: %v %v", a.Source, err)
	}
	if _, err := toml.Decode(`source = "/var/vmail"`, &a); err != nil || len(a.Source) != 1 || a.Source[0] != "/var/vmail" {
		t.Fatalf("single string: %v %v", a.Source, err)
	}
	if _, err := toml.Decode(`source = ["/var/lib/mailadmin/backups", "/var/vmail"]`, &a); err != nil || len(a.Source) != 2 {
		t.Fatalf("list: %v %v", a.Source, err)
	}
	if _, err := toml.Decode(`source = [1]`, &a); err == nil {
		t.Fatal("non-string entries must be refused")
	}
}
