package config

import (
	"strings"
	"testing"
)

func goodWebmail() Webmail {
	return Webmail{Enabled: true, Domain: "webmail.kiefer-networks.de", Version: "v1",
		SHA256: strings.Repeat("a", 64), Listen: "127.0.0.1:8081"}
}

func goodBorg() BorgBackup {
	return BorgBackup{Enabled: true, Repo: "ssh://u1@u1.example.net:23/./mailadmin",
		SSHKey: "/root/.ssh/borg_ed25519", KnownHosts: "/root/.ssh/known_hosts_borg",
		Encryption: "repokey-blake2", Compression: "zstd,6", Schedule: "*-*-* 03:30:00",
		Prune: true, Compact: true, CheckEvery: "1w",
		Retention: BorgRetention{Daily: 7, Weekly: 4, Monthly: 6}}
}

func TestWebmailValidate(t *testing.T) {
	if err := (Webmail{}).validate(); err != nil {
		t.Fatalf("disabled webmail must not be checked: %v", err)
	}
	if err := goodWebmail().validate(); err != nil {
		t.Fatalf("valid webmail refused: %v", err)
	}
	for name, mut := range map[string]func(*Webmail){
		"bad domain": func(w *Webmail) { w.Domain = "not a host" },
		"no version": func(w *Webmail) { w.Version = "" },
		"short sum":  func(w *Webmail) { w.SHA256 = "abc" },
		"upper hex":  func(w *Webmail) { w.SHA256 = strings.Repeat("A", 64) },
		"bad listen": func(w *Webmail) { w.Listen = "nope" },
	} {
		w := goodWebmail()
		mut(&w)
		if err := w.validate(); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestBorgValidate(t *testing.T) {
	if err := (BorgBackup{}).validate("/var/lib/mailadmin/backups"); err != nil {
		t.Fatalf("disabled borg must not be checked: %v", err)
	}
	if err := goodBorg().validate("/var/lib/mailadmin/backups"); err != nil {
		t.Fatalf("valid borg refused: %v", err)
	}
	local := goodBorg()
	local.Repo = "/mnt/backup/borg"
	local.SSHKey, local.KnownHosts = "", ""
	if err := local.validate("/var/lib/mailadmin/backups"); err != nil {
		t.Fatalf("local repo refused: %v", err)
	}
	for name, mut := range map[string]func(*BorgBackup){
		"no repo":          func(b *BorgBackup) { b.Repo = "" },
		"relative repo":    func(b *BorgBackup) { b.Repo = "borg/repo" },
		"relative ssh key": func(b *BorgBackup) { b.SSHKey = "id" },
		"no known_hosts":   func(b *BorgBackup) { b.KnownHosts = "" },
		"bad encryption":   func(b *BorgBackup) { b.Encryption = "aes-something" },
		"no compression":   func(b *BorgBackup) { b.Compression = "" },
		"no schedule":      func(b *BorgBackup) { b.Schedule = "" },
		"bad check_every":  func(b *BorgBackup) { b.CheckEvery = "weekly" },
		"negative keep":    func(b *BorgBackup) { b.Retention.Daily = -1 },
		"keeps nothing":    func(b *BorgBackup) { b.Retention = BorgRetention{} },
	} {
		b := goodBorg()
		mut(&b)
		if err := b.validate("/var/lib/mailadmin/backups"); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	noSource := goodBorg()
	if err := noSource.validate(""); err == nil {
		t.Fatal("no source and no backup.dir must be refused")
	}
}
