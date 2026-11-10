package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mailadmin/internal/config"
	"mailadmin/internal/sys"
)

// fakeExec records every command and answers from a fixed table keyed by a
// substring of the joined argv. Unmatched commands succeed with empty output.
type fakeExec struct {
	calls   [][]string
	answers map[string]string
	fail    map[string]bool
}

func (f *fakeExec) Run(_ context.Context, _ []byte, argv ...string) (sys.Result, error) {
	joined := strings.Join(argv, " ")
	f.calls = append(f.calls, argv)
	for key, fail := range f.fail {
		if fail && strings.Contains(joined, key) {
			return sys.Result{}, sys.ErrNonZeroExit
		}
	}
	for key, out := range f.answers {
		if strings.Contains(joined, key) {
			return sys.Result{Stdout: []byte(out)}, nil
		}
	}
	return sys.Result{}, nil
}

func TestParseOSRelease(t *testing.T) {
	cases := []struct {
		name, body, wantID, wantCodename string
		wantErr                          bool
	}{
		{"ubuntu", "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_CODENAME=noble\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n", "ubuntu", "noble", false},
		{"debian", "ID=debian\nVERSION_CODENAME=bookworm\n", "debian", "bookworm", false},
		{"fedora", "ID=fedora\nVERSION_CODENAME=x\n", "", "", true},
		{"no codename", "ID=debian\n", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := ParseOSRelease(strings.NewReader(c.body))
			if c.wantErr {
				if err == nil {
					t.Fatalf("want error, got %+v", d)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d.ID != c.wantID || d.Codename != c.wantCodename {
				t.Fatalf("got %+v", d)
			}
		})
	}
}

func TestRepoSourcesUseSignedBy(t *testing.T) {
	got := PostgresRepo("noble").Sources()
	for _, want := range []string{
		"Types: deb",
		"URIs: https://apt.postgresql.org/pub/repos/apt",
		"Suites: noble-pgdg",
		"Signed-By: /usr/share/keyrings/pgdg.gpg",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("sources missing %q:\n%s", want, got)
		}
	}
}

func TestParseFingerprintTakesPrimaryKey(t *testing.T) {
	colons := "tru:t:1:\npub:-:4096:1:ABCDEF0123456789:1700000000:::\n" +
		"fpr:::::::::b9 7b 0a fc aa 1a 47 f0 44 f2 44 a0 7f cc 7d 46 ac cc 4c f8:\n" +
		"fpr:::::::::1111111111111111111111111111111111111111:\n"
	got, err := parseFingerprint([]byte(colons))
	if err != nil {
		t.Fatal(err)
	}
	if got != "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8" {
		t.Fatalf("fingerprint = %q", got)
	}
}

func TestParseFingerprintRefusesExtraKeys(t *testing.T) {
	colons := "pub:-:4096:1:A:1:::\nfpr:::::::::AAAA000000000000000000000000000000000000:\n" +
		"pub:-:4096:1:B:1:::\nfpr:::::::::BBBB000000000000000000000000000000000000:\n"
	if _, err := parseFingerprint([]byte(colons)); err == nil || !strings.Contains(err.Error(), "2 primary keys") {
		t.Fatalf("a download with a second key must be refused, got %v", err)
	}
}

func TestInstallRepoRefusesUnconfirmedKey(t *testing.T) {
	x := &fakeExec{answers: map[string]string{
		"show-only": "pub:-:4096:1:X:1:::\nfpr:::::::::AAAA000000000000000000000000000000000000:\n",
	}}
	err := InstallRepo(context.Background(), x, PostgresRepo("noble"), []byte("key"),
		"BBBB000000000000000000000000000000000000")
	if err == nil || !strings.Contains(err.Error(), "refusing to install") {
		t.Fatalf("want fingerprint refusal, got %v", err)
	}
	for _, c := range x.calls {
		if strings.Contains(strings.Join(c, " "), "--dearmor") {
			t.Fatal("keyring written despite fingerprint mismatch")
		}
	}
}

func TestAnswersValidate(t *testing.T) {
	good := Answers{Hostname: "mx.example.com", Domain: "example.com", IPv4: "192.0.2.10", Selector: "mail2026"}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid answers rejected: %v", err)
	}
	bad := good
	bad.IPv4 = "::ffff:192.0.2.10"
	if err := bad.Validate(); err == nil {
		t.Fatal("IPv4-mapped IPv6 accepted as ipv4")
	}
	bad = good
	bad.Hostname = "not a host"
	if err := bad.Validate(); err == nil {
		t.Fatal("bad hostname accepted")
	}
	norm := Answers{Hostname: "MX.Example.com.", Domain: "Example.COM.", IPv4: "192.0.2.10",
		IPv6: "2001:DB8:0:0:0:0:0:1", Selector: "mail2026"}
	if err := norm.Validate(); err != nil {
		t.Fatal(err)
	}
	if norm.Hostname != "mx.example.com" || norm.Domain != "example.com" || norm.IPv6 != "2001:db8::1" {
		t.Fatalf("not normalized: %+v", norm)
	}
}

// The rendered config must load through the real config loader, so install
// can never write a config that mailadmin itself refuses.
func TestRenderedConfigLoads(t *testing.T) {
	dir := t.TempDir()
	a := Answers{Hostname: "mx.example.com", Domain: "example.com", IPv4: "192.0.2.10", IPv6: "2001:db8::10", Selector: "mail2026"}
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), RenderConfig(a), 0o644); err != nil {
		t.Fatal(err)
	}
	secrets, err := RenderSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secrets.env"), secrets, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, sec, err := config.Load(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.Mail.Hostname != "mx.example.com" || cfg.Postgres.Service != PgService {
		t.Fatalf("loaded config %+v", cfg)
	}
	if sec.RspamdControllerPW() == "" {
		t.Fatal("rspamd controller password not generated")
	}
}

func TestWriteConfigRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	a := Answers{Hostname: "mx.example.com", Domain: "example.com", IPv4: "192.0.2.10", Selector: "mail2026"}
	if err := WriteConfig(dir, a); err != nil {
		t.Fatal(err)
	}
	err := WriteConfig(dir, a)
	if !errors.Is(err, ErrExists) {
		t.Fatalf("second WriteConfig: want ErrExists, got %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "secrets.env"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("secrets.env mode %o, want 600", info.Mode().Perm())
	}
}

// With --adopt, an existing schema keeps its baseline (001 is recorded, not
// re-run) and the later migrations are still applied.
func TestApplyMigrationsAdoptSkipsBaseline(t *testing.T) {
	x := &fakeExec{answers: map[string]string{
		"to_regclass('domain')": "t",
	}}
	if err := ApplyMigrations(context.Background(), x, true); err != nil {
		t.Fatal(err)
	}
	var baselineRun, laterRun bool
	for _, c := range x.calls {
		j := strings.Join(c, " ")
		if strings.Contains(j, "INSERT INTO schema_migrations (version) VALUES ('001_baseline.sql') RETURNING") {
			baselineRun = true
		}
		if strings.Contains(j, "-f -") && strings.Contains(j, "psql") {
			laterRun = true
		}
	}
	if !baselineRun {
		t.Fatal("adopted baseline was not recorded")
	}
	if !laterRun {
		t.Fatal("later migrations were not applied")
	}
}

func TestConflictsReportsExistingMailState(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/postfix"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/postfix/main.cf"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	x := &fakeExec{fail: map[string]bool{"dpkg-query": true}}
	got := Conflicts(context.Background(), x, root)
	if len(got) != 1 || got[0] != "/etc/postfix/main.cf" {
		t.Fatalf("conflicts = %v", got)
	}
}

// Command names are resolved to absolute paths before they reach the runner.
func TestResolveMakesPathsAbsolute(t *testing.T) {
	x := &fakeExec{}
	if _, err := Resolve(x).Run(context.Background(), nil, "sh", "-c", "true"); err != nil {
		t.Fatal(err)
	}
	if got := x.calls[0][0]; !filepath.IsAbs(got) {
		t.Fatalf("argv[0] = %q, want absolute path", got)
	}
}

// A crash between the two writes leaves only secrets.env. A rerun must still
// create config.toml instead of stopping at the existing secrets file.
func TestWriteConfigCreatesMissingConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secrets.env"), []byte("RSPAMD_CONTROLLER_PW=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := Answers{Hostname: "mx.example.com", Domain: "example.com", IPv4: "192.0.2.10", Selector: "mail2026"}
	if err := WriteConfig(dir, a); err != nil {
		t.Fatalf("WriteConfig with only secrets.env: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.toml")); err != nil {
		t.Fatalf("config.toml not created: %v", err)
	}
}
