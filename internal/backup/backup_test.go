package backup

import (
	"path/filepath"
	"testing"
	"time"
)

func TestBundleName(t *testing.T) {
	tm := time.Date(2026, 8, 30, 12, 34, 56, 0, time.FixedZone("CEST", 2*3600))
	got := BundleName(tm)
	want := "mailadmin-20260830T103456Z" // normalized to UTC
	if got != want {
		t.Fatalf("BundleName = %q, want %q", got, want)
	}
}

func TestValidComponent(t *testing.T) {
	for _, c := range AllComponents {
		if !ValidComponent(c) {
			t.Errorf("ValidComponent(%q) = false, want true", c)
		}
	}
	for _, bad := range []string{"", "domaindb", "DKIM", "everything"} {
		if ValidComponent(bad) {
			t.Errorf("ValidComponent(%q) = true, want false", bad)
		}
	}
}

func TestManifestHasComponent(t *testing.T) {
	m := NewManifest("1.2.3", []string{ComponentDB, ComponentDKIM})
	if !m.HasComponent(ComponentDB) || !m.HasComponent(ComponentDKIM) {
		t.Fatal("expected both components present")
	}
	if m.HasComponent(ComponentSieve) {
		t.Fatal("did not expect sieve component present")
	}
	if m.Notes != SecretsWarning {
		t.Fatalf("Notes = %q, want the fixed secrets warning", m.Notes)
	}
	if m.Version != manifestSchemaVersion {
		t.Fatalf("Version = %d, want %d", m.Version, manifestSchemaVersion)
	}
}

func TestWriteReadManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	m := NewManifest("2026.08.30", AllComponents)
	m.Domains = []string{"example.com", "example.org"}
	m.Mailboxes = 7
	m.DKIMKeyFiles = 4
	m.SieveScripts = []string{"alice@example.com", "bob@example.org"}
	m.DBService = "mail-admin"
	m.DBFormat = "custom"

	if err := WriteManifest(dir, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	got, err := ReadManifest(dir)
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if got.Version != m.Version || got.DBService != m.DBService || got.Mailboxes != m.Mailboxes {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, m)
	}
	if len(got.Domains) != 2 || got.Domains[0] != "example.com" {
		t.Fatalf("Domains round-trip mismatch: %v", got.Domains)
	}
	if len(got.SieveScripts) != 2 {
		t.Fatalf("SieveScripts round-trip mismatch: %v", got.SieveScripts)
	}
	if !got.CreatedAt.Equal(m.CreatedAt) {
		t.Fatalf("CreatedAt round-trip mismatch: got %v, want %v", got.CreatedAt, m.CreatedAt)
	}
}

func TestReadManifestMissing(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadManifest(filepath.Join(dir, "nope")); err == nil {
		t.Fatal("expected error reading manifest from a bundle that does not exist")
	}
}

func TestSieveFileName(t *testing.T) {
	got := SieveFileName("alice@example.com")
	want := "alice@example.com.sieve"
	if got != want {
		t.Fatalf("SieveFileName = %q, want %q", got, want)
	}
}
