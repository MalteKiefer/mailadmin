// Package sys is the single privileged-exec chokepoint for mailadmin.
//
// Every external command runs through Runner.Run: arguments are passed as a
// slice (never a shell string, there is no "sh -c" anywhere), a per-call
// timeout is enforced via context, combined output is captured and capped, and
// each invocation is recorded so auditing/logging stays consistent and
// injection-free. Callers pass an absolute binary path and already-validated
// arguments.
package sys

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// maxOutput caps captured output per stream (bytes) to avoid unbounded memory.
// Output beyond it is an error (ErrOutputTruncated), never silently dropped:
// callers parse journal windows and queue dumps and would report partial data.
const maxOutput = 64 << 20 // 64 MiB

// killGrace is how long Run waits for the output pipes after the process group
// was killed, so a grandchild holding them cannot block Run forever.
const killGrace = 10 * time.Second

// DefaultTimeout applies when a Runner is created without an explicit timeout.
const DefaultTimeout = 30 * time.Second

var (
	// ErrEmptyArgv is returned when Run is called without a command path.
	ErrEmptyArgv = errors.New("sys: empty argv")

	// ErrNotAbsolute is returned when argv[0] is not an absolute binary path.
	// Requiring an absolute path avoids PATH-lookup surprises and keeps the set
	// of executable binaries explicit (least privilege).
	ErrNotAbsolute = errors.New("sys: command path must be absolute")

	// ErrNonZeroExit is returned by Run and Output when the command exits with a
	// non-zero status. Errors.Is matches it; the concrete error also carries the
	// captured stderr via *ExitError for callers that want detail.
	ErrNonZeroExit = errors.New("sys: command exited non-zero")

	// ErrOutputTruncated is returned when stdout exceeded maxOutput.
	ErrOutputTruncated = errors.New("sys: command output exceeded the capture limit")
)

// ExitError wraps a non-zero command exit. It intentionally exposes the stderr
// tail (capped) so callers can surface a reason without re-running, while never
// including stdin (which may carry secrets). Errors.Is(err, ErrNonZeroExit) is
// true for any ExitError.
type ExitError struct {
	Argv     []string
	ExitCode int
	Stderr   []byte
}

func (e *ExitError) Error() string {
	msg := bytes.TrimSpace(e.Stderr)
	if len(msg) == 0 {
		return fmt.Sprintf("%s: exit %d", commandName(e.Argv), e.ExitCode)
	}
	return fmt.Sprintf("%s: exit %d: %s", commandName(e.Argv), e.ExitCode, msg)
}

func (e *ExitError) Is(target error) bool { return target == ErrNonZeroExit }

// commandName returns the base name of argv[0] for concise, non-leaking error
// messages (full paths and arguments are omitted to avoid echoing tokens).
func commandName(argv []string) string {
	if len(argv) == 0 {
		return "command"
	}
	return filepath.Base(argv[0])
}

// Result is the outcome of one command invocation.
type Result struct {
	Argv     []string
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}

// Recorder receives one entry per invocation (for audit/debug). Implementations
// must not log secret argument values; sys passes argv verbatim, so callers are
// responsible for never placing secrets in argv.
type Recorder interface {
	Record(argv []string, exitCode int, dur time.Duration)
}

// Runner executes external commands under a timeout with output capture.
type Runner struct {
	timeout  time.Duration
	recorder Recorder
	env      []string // extra KEY=value entries for every command, on top of the environment
}

// WithEnv returns a Runner that adds kv (KEY=value entries) to the environment of
// every command it runs. Used for tools that take settings from the environment,
// such as borg's BORG_RSH and BORG_PASSPHRASE, so no secret ends up in argv.
func (r *Runner) WithEnv(kv ...string) *Runner {
	c := *r
	c.env = append(append([]string(nil), r.env...), kv...)
	return &c
}

// New builds a Runner. A zero timeout falls back to DefaultTimeout. recorder may
// be nil.
func New(timeout time.Duration, recorder Recorder) *Runner {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Runner{timeout: timeout, recorder: recorder}
}

// Run executes argv[0] with argv[1:] as arguments. argv[0] must be an absolute
// path to a binary (there is no PATH lookup and no shell). stdin, if non-nil, is
// written to the process's standard input. A per-call timeout derived from the
// Runner is layered on top of ctx; whichever fires first cancels the process.
//
// Captured stdout and stderr are each bounded to maxOutput bytes. Run returns a
// populated Result on both success and non-zero exit; on non-zero exit the
// accompanying error wraps ErrNonZeroExit (as *ExitError). Failure to start the
// command, or context cancellation/timeout, returns a %w-wrapped error and a
// zero-value Result. Every attempt that produced an exec.Cmd is recorded once.
func (r *Runner) Run(ctx context.Context, stdin []byte, argv ...string) (Result, error) {
	var in io.Reader
	if len(stdin) > 0 {
		in = bytes.NewReader(stdin)
	}
	return r.RunReader(ctx, in, argv...)
}

// RunReader is Run with stdin read from a reader, so a large input (a database
// dump) streams from its file instead of being loaded into memory. A nil reader
// means no stdin.
func (r *Runner) RunReader(ctx context.Context, stdin io.Reader, argv ...string) (Result, error) {
	if len(argv) == 0 || argv[0] == "" {
		return Result{}, ErrEmptyArgv
	}
	if !filepath.IsAbs(argv[0]) {
		return Result{}, fmt.Errorf("%w: %s", ErrNotAbsolute, commandName(argv))
	}

	runCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Copy argv so a caller mutating its slice after the call cannot affect the
	// recorded/echoed arguments.
	args := make([]string, len(argv))
	copy(args, argv)

	// This is the single privileged-exec chokepoint. argv[0] is required to be an
	// absolute path (checked above) and arguments are passed as a slice, there is
	// no shell and no PATH lookup, so no shell metacharacter can be interpreted.
	// Callers pass already-validated tokens; G204's dynamic-argv warning is by design.
	cmd := exec.CommandContext(runCtx, args[0], args[1:]...) // #nosec G204 -- absolute path, arg slice, no shell; the audited exec chokepoint
	if stdin != nil {
		cmd.Stdin = stdin
	}
	if len(r.env) > 0 {
		cmd.Env = append(os.Environ(), r.env...)
	}
	// The command runs in its own process group, and a timeout or cancel kills
	// the whole group: a wrapper such as runuser would otherwise die alone while
	// its child (pg_restore) keeps running and holding the output pipes.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = killGrace
	var outBuf, errBuf capBuffer
	outBuf.limit = maxOutput
	errBuf.limit = maxOutput
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	start := time.Now()
	runErr := cmd.Run()
	dur := time.Since(start)

	// A cancelled or timed-out context takes precedence: CommandContext kills the
	// process, so cmd.Run reports an *exec.ExitError (signalled, exit -1) that
	// would otherwise masquerade as a normal non-zero exit. Report the context
	// cause instead so callers can match DeadlineExceeded / Canceled.
	if cerr := runCtx.Err(); cerr != nil {
		return Result{}, fmt.Errorf("%s: %w", commandName(args), cerr)
	}

	// Distinguish "command ran and exited non-zero" from "command could not run".
	// *exec.ExitError means it ran to completion with a status.
	var ee *exec.ExitError
	if runErr != nil && !errors.As(runErr, &ee) {
		// The process never produced a status; nothing worth recording.
		return Result{}, fmt.Errorf("%s: %w", commandName(args), runErr)
	}

	exitCode := cmd.ProcessState.ExitCode()
	if r.recorder != nil {
		r.recorder.Record(args, exitCode, dur)
	}

	res := Result{
		Argv:     args,
		Stdout:   outBuf.Bytes(),
		Stderr:   errBuf.Bytes(),
		ExitCode: exitCode,
		Duration: dur,
	}
	if exitCode != 0 {
		return res, &ExitError{Argv: args, ExitCode: exitCode, Stderr: res.Stderr}
	}
	if outBuf.truncated {
		return res, fmt.Errorf("%s: %w (%d bytes)", commandName(args), ErrOutputTruncated, maxOutput)
	}
	return res, nil
}

// Output runs argv and returns trimmed stdout, erroring on non-zero exit. It is
// a convenience wrapper over Run for the common read-only case with no stdin.
func (r *Runner) Output(ctx context.Context, argv ...string) (string, error) {
	res, err := r.Run(ctx, nil, argv...)
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(res.Stdout)), nil
}

// capBuffer is a bytes.Buffer that silently drops writes once limit bytes have
// been stored, bounding memory for pathological command output. A zero or
// negative limit means unbounded.
type capBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if c.limit > 0 {
		room := c.limit - c.buf.Len()
		if room <= 0 {
			// Report full consumption so the process's writer does not error out;
			// the surplus is discarded and Run reports ErrOutputTruncated.
			c.truncated = c.truncated || len(p) > 0
			return len(p), nil
		}
		if len(p) > room {
			c.buf.Write(p[:room])
			c.truncated = true
			return len(p), nil
		}
	}
	return c.buf.Write(p)
}

func (c *capBuffer) Bytes() []byte { return c.buf.Bytes() }
