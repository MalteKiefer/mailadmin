// Package install provisions a mail host: vendor repositories, packages, the
// PostgreSQL schema, service accounts, the mailadmin config, and the binary.
//
// Every privileged step goes through Exec (in production *sys.Runner), so each
// external command is argument-vector based, time-bounded and recorded.
package install

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"mailadmin/internal/sys"
)

// ErrUnsupported marks a distribution or architecture install does not support.
var ErrUnsupported = errors.New("unsupported platform")

// Exec runs an external command. *sys.Runner satisfies it.
type Exec interface {
	Run(ctx context.Context, stdin []byte, argv ...string) (sys.Result, error)
}

// Distro is the host distribution as read from /etc/os-release.
type Distro struct {
	ID       string // ubuntu or debian
	Codename string // VERSION_CODENAME, e.g. noble or bookworm
	Pretty   string // PRETTY_NAME, for messages
}

// ParseOSRelease reads an os-release file and rejects anything except Ubuntu
// and Debian.
func ParseOSRelease(r io.Reader) (Distro, error) {
	vals := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		vals[key] = strings.Trim(val, `"'`)
	}
	if err := sc.Err(); err != nil {
		return Distro{}, fmt.Errorf("read os-release: %w", err)
	}
	d := Distro{ID: vals["ID"], Codename: vals["VERSION_CODENAME"], Pretty: vals["PRETTY_NAME"]}
	if d.ID != "ubuntu" && d.ID != "debian" {
		return Distro{}, fmt.Errorf("%w: distribution %q (supported: ubuntu, debian)", ErrUnsupported, d.ID)
	}
	if d.Codename == "" {
		return Distro{}, errors.New("os-release has no VERSION_CODENAME")
	}
	return d, nil
}

// CheckArch accepts the architectures the vendor repositories publish.
func CheckArch(goarch string) error {
	switch goarch {
	case "amd64", "arm64":
		return nil
	}
	return fmt.Errorf("%w: architecture %q (supported: amd64, arm64)", ErrUnsupported, goarch)
}
