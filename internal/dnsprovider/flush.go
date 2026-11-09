package dnsprovider

import (
	"context"
	"errors"
)

// Flusher is implemented by providers that defer a post-write step, such as the
// DNSSEC rectify on servfail, to the end of a batch of writes.
type Flusher interface {
	Flush(ctx context.Context, domain string) error
}

// FlushBatch runs p's deferred post-write step for domain, if it has one. Batch
// writers call it once after their loop, on error paths too.
func FlushBatch(ctx context.Context, p Provider, domain string) error {
	if f, ok := p.(Flusher); ok {
		return f.Flush(ctx, domain)
	}
	return nil
}

// flushInto joins a batch's deferred flush error into *err. Batch functions call
// it with defer so the flush runs on every return path.
func flushInto(ctx context.Context, p Provider, domain string, err *error) {
	*err = errors.Join(*err, FlushBatch(ctx, p, domain))
}
