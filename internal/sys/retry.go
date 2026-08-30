package sys

import (
	"bytes"
	"context"
	"time"
)

// RunWithRetry calls Run up to attempts times, retrying on any failure —
// a failed start, a timeout, or a non-zero exit — the shape of transient,
// environment-level failures a single-node CLI can plausibly recover from on
// its next try (e.g. `systemctl reload` racing a unit that is still
// re-validating its config, or `cscli` momentarily unable to reach its local
// LAPI socket). It exists only for call sites whose command is safe to repeat
// — reloading a service and re-asserting a CrowdSec decision/allowlist entry
// are idempotent, so a spurious retry after a transient failure does not
// compound. Do not use it for a mutation that is not idempotent.
//
// attempts must be >= 1 (fewer is treated as 1 — always try at least once).
// backoff is the fixed delay between attempts; it is not applied after the
// final attempt or if ctx is done. The context passed to Run governs the
// overall deadline across all attempts, so callers should size ctx's timeout
// accordingly (each Run also layers the Runner's own per-call timeout on
// top). The error from the final attempt is returned on exhaustion.
//
// This intentionally stays a plain fixed/linear backoff — exponential backoff
// with jitter is overkill for a handful of local, single-node subprocess
// calls with a 2-3 attempt ceiling.
func (r *Runner) RunWithRetry(ctx context.Context, attempts int, backoff time.Duration, stdin []byte, argv ...string) (Result, error) {
	if attempts < 1 {
		attempts = 1
	}
	var (
		res Result
		err error
	)
	for attempt := 1; attempt <= attempts; attempt++ {
		res, err = r.Run(ctx, stdin, argv...)
		if err == nil {
			return res, nil
		}
		if attempt == attempts {
			break
		}
		if backoff > 0 {
			select {
			case <-ctx.Done():
				return res, ctx.Err()
			case <-time.After(backoff):
			}
		}
	}
	return res, err
}

// OutputWithRetry is the RunWithRetry analogue of Output: trimmed stdout on
// success, using the same retry-any-failure semantics.
func (r *Runner) OutputWithRetry(ctx context.Context, attempts int, backoff time.Duration, argv ...string) (string, error) {
	res, err := r.RunWithRetry(ctx, attempts, backoff, nil, argv...)
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(res.Stdout)), nil
}
