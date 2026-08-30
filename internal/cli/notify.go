package cli

import (
	"context"
	"fmt"
	"os"

	"mailadmin/internal/notify"
)

// notifyConfig builds a notify.Config from the loaded config + secrets. It
// returns a zero Config (a clean no-op for notify.Send) if config cannot be
// loaded at all — an alerting misconfiguration must never be surfaced in
// place of, or ahead of, the caller's own error.
func (a *App) notifyConfig() notify.Config {
	cfg, secrets, err := a.Config()
	if err != nil {
		return notify.Config{}
	}
	return notify.Config{URL: cfg.Notify.URL, Token: secrets.NtfyToken()}
}

// notifySend posts msg through notify.Send using this app's configured ntfy
// target. Any failure to deliver is written to stderr and otherwise
// swallowed — see internal/notify's package doc for why: a broken notify
// channel must never mask or replace the caller's own report/exit code.
func (a *App) notifySend(ctx context.Context, msg notify.Message) {
	_ = notify.Send(ctx, a.notifyConfig(), msg, func(warning string) {
		fmt.Fprintln(a.stderr(), warning)
	})
}

// hostnameOrUnknown returns os.Hostname(), falling back to a fixed string so
// a hostname lookup failure never blocks building a notification body.
func hostnameOrUnknown() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown-host"
	}
	return h
}
