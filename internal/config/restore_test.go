package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const bundleNoSecrets = "[mail]\nhostname = \"mx.example.com\"\n"

func writeTestFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

// A restore from a v1.29.2 bundle (no secrets in it) must keep the live secrets.
func TestMergeRestoredKeepsLiveSecrets(t *testing.T) {
	live := filepath.Join(t.TempDir(), "config.toml")
	writeTestFile(t, live, "[mail]\nhostname = \"old.example.com\"\n\n[secrets]\nDESEC_TOKEN = \"live-tok\"\n", 0o600)
	out, err := MergeRestored([]byte(bundleNoSecrets), live)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "live-tok") {
		t.Fatalf("live secret lost:\n%s", out)
	}
	if !strings.Contains(string(out), "mx.example.com") {
		t.Fatalf("bundle values lost:\n%s", out)
	}
}

// A bundle from before v1.29.2 carries its own secrets; they win over the live ones.
func TestMergeRestoredPrefersBundleSecrets(t *testing.T) {
	live := filepath.Join(t.TempDir(), "config.toml")
	writeTestFile(t, live, "[secrets]\nDESEC_TOKEN = \"live-tok\"\n", 0o600)
	bundle := bundleNoSecrets + "\n[secrets]\nDESEC_TOKEN = \"bundle-tok\"\n"
	out, err := MergeRestored([]byte(bundle), live)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "bundle-tok") || strings.Contains(string(out), "live-tok") {
		t.Fatalf("bundle secrets must win:\n%s", out)
	}
}

// Without a live config there is nothing to keep: the bundle copy is written as is.
func TestMergeRestoredWithoutLiveConfig(t *testing.T) {
	out, err := MergeRestored([]byte(bundleNoSecrets), filepath.Join(t.TempDir(), "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "secrets") {
		t.Fatalf("no secrets expected:\n%s", out)
	}
}

// A YAML or JSON live config must not be overwritten with TOML text.
func TestMergeRestoredRefusesNonTOMLLive(t *testing.T) {
	for _, name := range []string{"config.yaml", "config.json"} {
		_, err := MergeRestored([]byte(bundleNoSecrets), filepath.Join(t.TempDir(), name))
		if err == nil || !strings.Contains(err.Error(), "restore writes config.toml only") {
			t.Fatalf("%s: want refusal, got %v", name, err)
		}
	}
}

func TestWriteSecretFileKeepsSymlinkAndMode(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.toml")
	writeTestFile(t, target, "old\n", 0o600)
	link := filepath.Join(dir, "config.toml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteSecretFile(link, []byte("new\n")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink replaced by a regular file")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "new\n" {
		t.Fatalf("target content %q", data)
	}
	info, _ := os.Stat(target)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 600", info.Mode().Perm())
	}
}

// Load enforces 0600 only for a config that holds secrets, and the check must agree.
func TestSecretsStateModeRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	writeTestFile(t, path, "[mail]\n", 0o644)
	c := validConfig()
	c.Path = path
	if ok, detail := secretsState(&c); !ok {
		t.Fatalf("0644 config without secrets must pass: %s", detail)
	}
	c.Secrets = map[string]string{"DESEC_TOKEN": "tok"}
	if ok, _ := secretsState(&c); ok {
		t.Fatal("0644 config holding secrets must fail")
	}
}

// A dangling symlink must get the file it names, not be replaced by a regular file.
func TestWriteSecretFileCreatesDanglingLinkTarget(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "managed.toml")
	link := filepath.Join(dir, "config.toml")
	if err := os.Symlink(missing, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteSecretFile(link, []byte("new\n")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("dangling symlink replaced by a regular file")
	}
	data, err := os.ReadFile(missing)
	if err != nil || string(data) != "new\n" {
		t.Fatalf("named file = %q, %v", data, err)
	}
}

// A symlinked --config path must be judged by its target, as Load does.
func TestSecretsStateFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.toml")
	writeTestFile(t, real, "[mail]\n", 0o600)
	link := filepath.Join(dir, "config.toml")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	c := validConfig()
	c.Path = link
	c.Secrets = map[string]string{"DESEC_TOKEN": "tok"}
	if ok, detail := secretsState(&c); !ok {
		t.Fatalf("symlinked 0600 config with secrets must pass: %s", detail)
	}
}
