package cli

import (
	"errors"
	"path/filepath"
	"testing"

	"mailadmin/internal/config"
)

func TestBackupDirResolution(t *testing.T) {
	// abs builds a path filepath.IsAbs recognises on whatever OS the test
	// runs on (backupDir's absoluteness check is OS-native, even though the
	// deployed binary only ever runs on Linux).
	abs := func(elem ...string) string {
		p, err := filepath.Abs(filepath.Join(elem...))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	explicit := abs("tmp", "explicit")
	configured := abs("var", "lib", "mailadmin", "backups")

	tests := []struct {
		name    string
		flag    string
		cfgDir  string
		want    string
		wantErr bool
	}{
		{"flag wins", explicit, configured, explicit, false},
		{"falls back to config", "", configured, configured, false},
		{"neither set is a usage error", "", "", "", true},
		{"relative flag is a usage error", "relative/dir", configured, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{Backup: config.Backup{Dir: tt.cfgDir}}
			got, err := backupDir(cfg, tt.flag)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("backupDir(%q, %q) = %q, nil; want error", tt.cfgDir, tt.flag, got)
				}
				if !errors.Is(err, ErrUsage) {
					t.Fatalf("err = %v, want Is ErrUsage", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("backupDir(%q, %q): unexpected error: %v", tt.cfgDir, tt.flag, err)
			}
			if got != tt.want {
				t.Fatalf("backupDir(%q, %q) = %q, want %q", tt.cfgDir, tt.flag, got, tt.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	s := []string{"domain-db", "dkim"}
	if !contains(s, "dkim") {
		t.Error("expected contains to find dkim")
	}
	if contains(s, "config") {
		t.Error("did not expect contains to find config")
	}
	if contains(nil, "x") {
		t.Error("contains on nil slice must be false")
	}
}
