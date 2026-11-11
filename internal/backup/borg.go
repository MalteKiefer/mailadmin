package backup

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"mailadmin/internal/config"
	"mailadmin/internal/sys"
)

// BorgBin is the absolute path of the borg client (internal/sys runs absolute paths only).
const BorgBin = "/usr/bin/borg"

// BorgArchivePrefix names every archive mailadmin writes. Prune and list touch only these.
const BorgArchivePrefix = "mailadmin-"

// ErrBorgRepo is returned for a repository value mailadmin cannot use.
var ErrBorgRepo = errors.New("backup: borg repo must be ssh://user@host[:port]/path or an absolute path")

var reEvery = regexp.MustCompile(`^([1-9][0-9]*)([dw])$`)

// Borg runs the borg client for the [backup.borg] settings.
type Borg struct {
	Cfg        config.BorgBackup
	Passphrase string
	Exec       *sys.Runner
}

// ParseRepo splits a borg repository into its ssh parts. ssh is false for a local path.
func ParseRepo(repo string) (ssh bool, host, port string, err error) {
	if !strings.HasPrefix(repo, "ssh://") {
		if !filepath.IsAbs(repo) {
			return false, "", "", ErrBorgRepo
		}
		return false, "", "", nil
	}
	u, perr := url.Parse(repo)
	if perr != nil || u.User == nil || u.Hostname() == "" {
		return false, "", "", ErrBorgRepo
	}
	port = u.Port()
	if port == "" {
		port = "22"
	}
	return true, u.Hostname(), port, nil
}

// runner returns the sys runner with borg's environment: the ssh command with the
// configured key and pinned host keys, and the passphrase. The passphrase is passed in
// the environment only, never in argv.
func (b Borg) runner() (*sys.Runner, error) {
	ssh, _, port, err := ParseRepo(b.Cfg.Repo)
	if err != nil {
		return nil, err
	}
	var env []string
	if ssh {
		env = append(env, fmt.Sprintf("BORG_RSH=ssh -i %s -p %s -o IdentitiesOnly=yes -o UserKnownHostsFile=%s -o StrictHostKeyChecking=yes",
			b.Cfg.SSHKey, port, b.Cfg.KnownHosts))
	}
	if b.Passphrase != "" {
		env = append(env, "BORG_PASSPHRASE="+b.Passphrase)
	}
	return b.Exec.WithEnv(env...), nil
}

// Init creates the repository with the configured encryption.
func (b Borg) Init(ctx context.Context) error {
	r, err := b.runner()
	if err != nil {
		return err
	}
	_, err = r.Run(ctx, nil, BorgBin, "init", "--encryption="+b.Cfg.Encryption, b.Cfg.Repo)
	return err
}

// ArchiveName returns the archive name for a run at t.
func ArchiveName(t time.Time) string {
	return BorgArchivePrefix + t.UTC().Format("20060102T150405Z")
}

// Create archives sources as one archive named for now and returns its name.
func (b Borg) Create(ctx context.Context, sources []string, now time.Time) (string, error) {
	if len(sources) == 0 {
		return "", errors.New("backup: no borg source paths")
	}
	r, err := b.runner()
	if err != nil {
		return "", err
	}
	name := ArchiveName(now)
	argv := []string{BorgBin, "create", "--stats", "--compression", b.Cfg.Compression, b.Cfg.Repo + "::" + name}
	argv = append(argv, sources...)
	if _, err := r.Run(ctx, nil, argv...); err != nil {
		return "", err
	}
	return name, nil
}

// Prune keeps the configured number of daily, weekly and monthly mailadmin archives.
func (b Borg) Prune(ctx context.Context) error {
	r, err := b.runner()
	if err != nil {
		return err
	}
	argv := []string{BorgBin, "prune", "--glob-archives", BorgArchivePrefix + "*",
		"--keep-daily", strconv.Itoa(b.Cfg.Retention.Daily),
		"--keep-weekly", strconv.Itoa(b.Cfg.Retention.Weekly),
		"--keep-monthly", strconv.Itoa(b.Cfg.Retention.Monthly),
		b.Cfg.Repo}
	_, err = r.Run(ctx, nil, argv...)
	return err
}

// Compact frees the space of pruned archives.
func (b Borg) Compact(ctx context.Context) error {
	r, err := b.runner()
	if err != nil {
		return err
	}
	_, err = r.Run(ctx, nil, BorgBin, "compact", b.Cfg.Repo)
	return err
}

// Check verifies the repository.
func (b Borg) Check(ctx context.Context) error {
	r, err := b.runner()
	if err != nil {
		return err
	}
	_, err = r.Run(ctx, nil, BorgBin, "check", b.Cfg.Repo)
	return err
}

// List returns the mailadmin archives of the repository.
func (b Borg) List(ctx context.Context) (string, error) {
	r, err := b.runner()
	if err != nil {
		return "", err
	}
	return r.Output(ctx, BorgBin, "list", "--glob-archives", BorgArchivePrefix+"*", b.Cfg.Repo)
}

// CheckDue reports whether the repository check is due. every is "1w" or "30d"; an
// empty value means never. The stamp file's modification time records the last check.
func CheckDue(stamp, every string, now time.Time) (bool, error) {
	if every == "" {
		return false, nil
	}
	m := reEvery.FindStringSubmatch(every)
	if m == nil {
		return false, fmt.Errorf("backup: check_every %q must be like 1w or 30d", every)
	}
	n, _ := strconv.Atoi(m[1])
	period := time.Duration(n) * 24 * time.Hour
	if m[2] == "w" {
		period = time.Duration(n) * 7 * 24 * time.Hour
	}
	fi, err := os.Stat(stamp)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return now.Sub(fi.ModTime()) >= period, nil
}

// MarkChecked records a completed check at now.
func MarkChecked(stamp string, now time.Time) error {
	if err := os.WriteFile(stamp, []byte(now.UTC().Format(time.RFC3339)+"\n"), 0o600); err != nil {
		return err
	}
	return os.Chtimes(stamp, now, now)
}

// Run archives source, then prunes, compacts and checks as the config says. It returns
// the archive name. A failed step stops the run; prune, compact and check run only
// after a successful create.
func (b Borg) Run(ctx context.Context, sources []string, stamp string, now time.Time) (string, error) {
	if len(sources) == 0 {
		sources = []string(b.Cfg.Source)
	}
	name, err := b.Create(ctx, sources, now)
	if err != nil {
		return "", fmt.Errorf("borg create: %w", err)
	}
	if b.Cfg.Prune {
		if err := b.Prune(ctx); err != nil {
			return name, fmt.Errorf("borg prune: %w", err)
		}
	}
	if b.Cfg.Compact {
		if err := b.Compact(ctx); err != nil {
			return name, fmt.Errorf("borg compact: %w", err)
		}
	}
	due, err := CheckDue(stamp, b.Cfg.CheckEvery, now)
	if err != nil {
		return name, err
	}
	if due {
		if err := b.Check(ctx); err != nil {
			return name, fmt.Errorf("borg check: %w", err)
		}
		if err := MarkChecked(stamp, now); err != nil {
			return name, err
		}
	}
	return name, nil
}
