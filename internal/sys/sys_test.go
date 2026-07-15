package sys

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// helperCmd builds an argv that re-executes this test binary as a controllable
// child process. The child dispatches on GO_SYS_HELPER and exits before running
// any tests, so behaviour is identical on macOS and Linux without depending on
// system binaries such as /bin/echo.
func helperCmd(mode string, extra ...string) []string {
	exe, err := os.Executable()
	if err != nil {
		panic(err)
	}
	argv := []string{exe, "-test.run=TestHelperProcess", "--", mode}
	return append(argv, extra...)
}

func helperRunner(t *testing.T, timeout time.Duration, rec Recorder) *Runner {
	t.Helper()
	r := New(timeout, rec)
	return r
}

// TestHelperProcess is not a real test; it is the child-process entry point.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv("GO_SYS_HELPER")
	if mode == "" {
		return
	}
	// Arguments after "--" are ours.
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "echo":
		if len(args) > 1 {
			_, _ = os.Stdout.WriteString(strings.Join(args[1:], " "))
		}
	case "cat": // copy stdin to stdout
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				_, _ = os.Stdout.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	case "stderr":
		_, _ = os.Stderr.WriteString(strings.Join(args[1:], " "))
		os.Exit(3)
	case "fail":
		os.Exit(7)
	case "sleep":
		d, _ := time.ParseDuration(args[1])
		time.Sleep(d)
	case "spam": // write more than the cap wants
		n, _ := strconv.Atoi(args[1])
		chunk := strings.Repeat("x", 64*1024)
		for written := 0; written < n; written += len(chunk) {
			_, _ = os.Stdout.WriteString(chunk)
		}
	}
	os.Exit(0)
}

// runHelper wires GO_SYS_HELPER into the child env for a single invocation.
func withHelperEnv(t *testing.T, mode string) {
	t.Helper()
	t.Setenv("GO_SYS_HELPER", mode)
}

type capturingRecorder struct {
	mu      sync.Mutex
	calls   int
	lastArg []string
	lastRC  int
}

func (c *capturingRecorder) Record(argv []string, exitCode int, _ time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.lastArg = argv
	c.lastRC = exitCode
}

func TestRunGuards(t *testing.T) {
	r := New(time.Second, nil)
	ctx := context.Background()

	tests := []struct {
		name string
		argv []string
		want error
	}{
		{"empty argv", nil, ErrEmptyArgv},
		{"empty first element", []string{""}, ErrEmptyArgv},
		{"relative path", []string{"echo", "hi"}, ErrNotAbsolute},
		{"bare name", []string{"ls"}, ErrNotAbsolute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.Run(ctx, nil, tc.argv...)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Run(%v) err = %v, want Is %v", tc.argv, err, tc.want)
			}
		})
	}
}

func TestRunSuccessAndOutput(t *testing.T) {
	withHelperEnv(t, "1")
	rec := &capturingRecorder{}
	r := helperRunner(t, 5*time.Second, rec)
	ctx := context.Background()

	res, err := r.Run(ctx, nil, helperCmd("echo", "hello", "world")...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "hello world" {
		t.Fatalf("stdout = %q, want %q", got, "hello world")
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d, want 0", res.ExitCode)
	}
	if res.Duration <= 0 {
		t.Fatalf("duration not measured")
	}
	if rec.calls != 1 || rec.lastRC != 0 {
		t.Fatalf("recorder calls=%d rc=%d, want 1/0", rec.calls, rec.lastRC)
	}

	out, err := r.Output(ctx, helperCmd("echo", "trimmed")...)
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	if out != "trimmed" {
		t.Fatalf("Output = %q, want %q", out, "trimmed")
	}
}

func TestRunStdin(t *testing.T) {
	withHelperEnv(t, "1")
	r := helperRunner(t, 5*time.Second, nil)
	res, err := r.Run(context.Background(), []byte("piped-input"), helperCmd("cat")...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(res.Stdout) != "piped-input" {
		t.Fatalf("stdout = %q, want piped-input", res.Stdout)
	}
}

func TestRunNonZeroExit(t *testing.T) {
	withHelperEnv(t, "1")
	rec := &capturingRecorder{}
	r := helperRunner(t, 5*time.Second, rec)

	res, err := r.Run(context.Background(), nil, helperCmd("stderr", "boom")...)
	if err == nil {
		t.Fatal("expected error on non-zero exit")
	}
	if !errors.Is(err, ErrNonZeroExit) {
		t.Fatalf("err = %v, want Is ErrNonZeroExit", err)
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("err = %v, want *ExitError", err)
	}
	if ee.ExitCode != 3 {
		t.Fatalf("exit = %d, want 3", ee.ExitCode)
	}
	// Result is still populated on non-zero exit.
	if res.ExitCode != 3 || !strings.Contains(string(res.Stderr), "boom") {
		t.Fatalf("res = %+v, want exit 3 stderr boom", res)
	}
	// Non-zero exit is still recorded.
	if rec.calls != 1 || rec.lastRC != 3 {
		t.Fatalf("recorder calls=%d rc=%d, want 1/3", rec.calls, rec.lastRC)
	}
	// Error message must not leak full argv (only base name).
	if strings.Contains(ee.Error(), "-test.run") {
		t.Fatalf("error leaks argv: %q", ee.Error())
	}
}

func TestOutputPropagatesError(t *testing.T) {
	withHelperEnv(t, "1")
	r := helperRunner(t, 5*time.Second, nil)
	_, err := r.Output(context.Background(), helperCmd("fail")...)
	if !errors.Is(err, ErrNonZeroExit) {
		t.Fatalf("Output err = %v, want ErrNonZeroExit", err)
	}
}

func TestRunTimeout(t *testing.T) {
	withHelperEnv(t, "1")
	r := helperRunner(t, 100*time.Millisecond, nil)
	start := time.Now()
	_, err := r.Run(context.Background(), nil, helperCmd("sleep", "5s")...)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("timeout not enforced promptly")
	}
}

func TestRunContextCancel(t *testing.T) {
	withHelperEnv(t, "1")
	r := helperRunner(t, 5*time.Second, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := r.Run(ctx, nil, helperCmd("sleep", "5s")...)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want Canceled", err)
	}
}

func TestRunStartError(t *testing.T) {
	r := New(time.Second, nil)
	_, err := r.Run(context.Background(), nil, "/nonexistent/definitely/not/here")
	if err == nil {
		t.Fatal("expected start error")
	}
	if errors.Is(err, ErrNonZeroExit) {
		t.Fatalf("start failure should not be ErrNonZeroExit: %v", err)
	}
}

func TestOutputCapped(t *testing.T) {
	withHelperEnv(t, "1")
	r := helperRunner(t, 30*time.Second, nil)
	// Ask for well over maxOutput bytes; captured stdout must be capped.
	res, err := r.Run(context.Background(), nil, helperCmd("spam", strconv.Itoa(maxOutput+1<<20))...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Stdout) > maxOutput {
		t.Fatalf("stdout len = %d, exceeds cap %d", len(res.Stdout), maxOutput)
	}
	if len(res.Stdout) < maxOutput/2 {
		t.Fatalf("stdout len = %d, suspiciously small", len(res.Stdout))
	}
}

func TestDefaultTimeoutFallback(t *testing.T) {
	r := New(0, nil)
	if r.timeout != DefaultTimeout {
		t.Fatalf("timeout = %v, want DefaultTimeout %v", r.timeout, DefaultTimeout)
	}
	r = New(-1, nil)
	if r.timeout != DefaultTimeout {
		t.Fatalf("negative timeout not defaulted: %v", r.timeout)
	}
}

func TestCapBuffer(t *testing.T) {
	tests := []struct {
		name   string
		limit  int
		writes []string
		want   string
	}{
		{"under limit", 10, []string{"abc", "de"}, "abcde"},
		{"exact limit", 5, []string{"abcde"}, "abcde"},
		{"truncate single", 3, []string{"abcdef"}, "abc"},
		{"truncate across writes", 4, []string{"ab", "cdef", "gh"}, "abcd"},
		{"unbounded zero", 0, []string{"abcdef"}, "abcdef"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var b capBuffer
			b.limit = tc.limit
			for _, w := range tc.writes {
				n, err := b.Write([]byte(w))
				if err != nil || n != len(w) {
					t.Fatalf("Write(%q) = %d,%v; want full consume", w, n, err)
				}
			}
			if got := string(b.Bytes()); got != tc.want {
				t.Fatalf("buffer = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCommandNameNoLeak(t *testing.T) {
	tests := []struct {
		argv []string
		want string
	}{
		{[]string{"/usr/sbin/postqueue", "-p"}, "postqueue"},
		{[]string{"/usr/bin/doveadm", "pw", "-s", "secret"}, "doveadm"},
		{nil, "command"},
	}
	for _, tc := range tests {
		if got := commandName(tc.argv); got != tc.want {
			t.Fatalf("commandName(%v) = %q, want %q", tc.argv, got, tc.want)
		}
	}
}

func TestArgvCopied(t *testing.T) {
	withHelperEnv(t, "1")
	rec := &capturingRecorder{}
	r := helperRunner(t, 5*time.Second, rec)
	argv := helperCmd("echo", "orig")
	res, err := r.Run(context.Background(), nil, argv...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Mutate caller's slice after the call; Result/recorder must be unaffected.
	for i := range argv {
		argv[i] = "MUTATED"
	}
	if res.Argv[0] == "MUTATED" {
		t.Fatal("Result.Argv aliases caller slice")
	}
	if rec.lastArg[0] == "MUTATED" {
		t.Fatal("recorder argv aliases caller slice")
	}
}

// ensure exec import stays referenced if the file is trimmed later.
var _ = exec.ErrNotFound
