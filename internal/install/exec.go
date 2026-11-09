package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mailadmin/internal/sys"
)

// trustedDirs are searched for bare command names, in this order. PATH is not
// used: install runs as root, and a PATH entry that a non-root user can write to
// would let that user supply the binary that root then runs.
var trustedDirs = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// Resolve wraps x so every command name is looked up in trustedDirs first. The sys
// runner accepts only absolute paths, and install calls distribution tools by
// name (apt-get, env, runuser), which live in different directories per release.
func Resolve(x Exec) Exec { return resolvingExec{inner: x} }

type resolvingExec struct{ inner Exec }

func (r resolvingExec) Run(ctx context.Context, stdin []byte, argv ...string) (sys.Result, error) {
	if len(argv) == 0 {
		return sys.Result{}, errors.New("empty command")
	}
	if !filepath.IsAbs(argv[0]) {
		p, err := lookTrusted(argv[0])
		if err != nil {
			return sys.Result{}, err
		}
		argv = append([]string{p}, argv[1:]...)
	}
	return r.inner.Run(ctx, stdin, argv...)
}

// lookTrusted returns the first regular executable named name in trustedDirs.
func lookTrusted(name string) (string, error) {
	for _, dir := range trustedDirs {
		p := filepath.Join(dir, name)
		fi, err := os.Stat(p)
		if err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: not found in %s", name, strings.Join(trustedDirs, ":"))
}
