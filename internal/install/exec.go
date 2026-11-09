package install

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"

	"mailadmin/internal/sys"
)

// Resolve wraps x so every command name is looked up on PATH first. The sys
// runner accepts only absolute paths, and install calls distribution tools by
// name (apt-get, env, runuser), which live in different directories per release.
func Resolve(x Exec) Exec { return resolvingExec{inner: x} }

type resolvingExec struct{ inner Exec }

func (r resolvingExec) Run(ctx context.Context, stdin []byte, argv ...string) (sys.Result, error) {
	if len(argv) == 0 {
		return sys.Result{}, errors.New("empty command")
	}
	if !filepath.IsAbs(argv[0]) {
		p, err := exec.LookPath(argv[0])
		if err != nil {
			return sys.Result{}, fmt.Errorf("%s: %w", argv[0], err)
		}
		argv = append([]string{p}, argv[1:]...)
	}
	return r.inner.Run(ctx, stdin, argv...)
}
