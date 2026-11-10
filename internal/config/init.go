package config

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
)

// DefaultConfigURL is the default configuration of the latest release. Each
// release ships its own copy, so `config init` always gets the newest one.
const DefaultConfigURL = "https://github.com/MalteKiefer/mailadmin/releases/latest/download/config.default.toml"

// maxDefaultBytes bounds the download; the default file is a few kilobytes.
const maxDefaultBytes = 1 << 20

// FetchDefault returns the default config file. It downloads url and checks
// that the result decodes as TOML with no unknown keys. If the download or the
// check fails, the copy built into the binary is used. source says which one.
func FetchDefault(ctx context.Context, url string, builtin []byte) (data []byte, source string) {
	data, err := download(ctx, url)
	if err == nil {
		if err = checkDefault(data); err == nil {
			return data, "release " + url
		}
	}
	return builtin, fmt.Sprintf("built-in copy (download failed: %v)", err)
}

func download(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 25 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxDefaultBytes+1))
}

// checkDefault refuses a default file that is not valid TOML or has keys the
// binary does not know.
func checkDefault(data []byte) error {
	if len(data) > maxDefaultBytes {
		return fmt.Errorf("default file too large")
	}
	var c Config
	md, err := toml.Decode(string(data), &c)
	if err != nil {
		return err
	}
	if u := md.Undecoded(); len(u) > 0 {
		return fmt.Errorf("unknown key %s", u[0])
	}
	return nil
}

// Init writes content as the config file in dir, owner-only, because the file
// can hold secrets. The directory is created (0755) if needed. An existing
// config file is kept unless force is set. It returns the path written.
func Init(dir string, content []byte, force bool) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("%w: empty target directory", ErrInvalidConfig)
	}
	// #nosec G301 -- the directory is traversable; the config file itself is 0600
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("config init: mkdir: %w", err)
	}
	if !force {
		if existing, err := Discover(dir); err == nil {
			return "", fmt.Errorf("config init: %s exists (use --force to replace it)", existing)
		}
	}
	path := filepath.Join(dir, "config.toml")
	if force {
		_ = os.Remove(path)
	}
	if err := writeNew(path, content, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// FetchDefaultFor downloads the default config file of a given release tag. Unlike
// FetchDefault it has no built-in fallback: the caller compares against the file
// of exactly the release it updated to.
func FetchDefaultFor(ctx context.Context, tag string) ([]byte, error) {
	url := "https://github.com/MalteKiefer/mailadmin/releases/download/" + tag + "/config.default.toml"
	data, err := download(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := checkDefault(data); err != nil {
		return nil, fmt.Errorf("default config of %s: %w", tag, err)
	}
	return data, nil
}
