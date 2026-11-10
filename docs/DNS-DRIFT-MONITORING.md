# DNS drift monitoring

`mailadmin dns drift-check` compares every domain's desired mail DNS
record-set against what is actually live in public DNS, the same comparison
[`dns check`](DNS.md#dns-show--dns-check) does, and exits non-zero (runtime
error, exit code 1) if anything is missing or has drifted. That makes it a
good fit for a periodic, unattended job: a registrar-side edit, an expired
zone, a botched manual change, or (for automated providers) a `dns publish`
that silently failed will all show up here well before a mailbox operator
notices delivery problems.

```sh
mailadmin dns drift-check --all              # human-readable table + exit code
mailadmin dns drift-check --all -o json      # {"domain":...,"total":...,"matched":...,"drift":...} per domain
mailadmin dns drift-check example.com        # a single domain
mailadmin dns drift-check --all --notify     # + one ntfy alert if anything drifted (see below)
```

## Push alerting: `--notify`

Both `dns drift-check` and [`doctor`](#running-doctor-notify-on-a-schedule)
can push exactly one [ntfy](https://ntfy.sh/) notification per run when
`--notify` is passed, summarising every domain that drifted or could not be
checked, not one message per domain. On a clean run it stays silent: silence
is the success signal. Add `--notify-heartbeat` if you also want a low-priority "all clean" ping
on a fully healthy run (useful as a dead-man's-switch check that the timer is
still firing at all).

`--notify` needs two things configured, both optional (unset means the flag
cleanly no-ops instead of erroring):

`/etc/mailadmin/config.toml`:

```toml
[notify]
url = "https://ntfy.sh/your-topic"   # or your own self-hosted ntfy instance
```

`/etc/mailadmin/secrets.env` (mode 0600):

```sh
NTFY_TOKEN=tk_your_ntfy_access_token
```

`mailadmin config check` reports `notify_url` / `ntfy_token` alongside the
other config/secret checks so a missing token is caught before the timer ever
fires silently into the void.

## Running it on a schedule: a systemd timer

This follows the same style as the DANE-rollover unit in
[`docs/DNS.md`](DNS.md#certificate-renewal--rollover): a plain oneshot
service plus a `.timer` unit, both under `/etc/systemd/system/`.

`/etc/systemd/system/mailadmin-drift-check.service`:

```ini
[Unit]
Description=mailadmin DNS drift check (all domains)
# Only makes sense once the mail stack (and its DB) is actually up.
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=oneshot
# --yes: never prompt (drift-check does not mutate anything, but --yes keeps
# this future-proof if a shared confirm() path is ever added upstream).
# --notify: push one ntfy alert if anything drifted (no-ops if [notify].url /
# NTFY_TOKEN are not configured, see "Push alerting" above).
# A non-zero exit (drift found, or a domain could not be checked) marks the
# unit failed, systemd records that in `systemctl status` / `journalctl`,
# which is what the OnFailure alerting hook further down also reacts to.
ExecStart=/usr/local/bin/mailadmin --yes dns drift-check --all --notify
User=root
```

`/etc/systemd/system/mailadmin-drift-check.timer`:

```ini
[Unit]
Description=Run mailadmin DNS drift check periodically

[Timer]
# Every 4 hours, staggered a little so it doesn't line up with other cron-ish
# jobs on the box.
OnCalendar=*-*-* 0/4:17:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable it:

```sh
systemctl enable --now mailadmin-drift-check.timer
```

Inspect recent runs:

```sh
systemctl status mailadmin-drift-check.service
journalctl -u mailadmin-drift-check.service --since -1d
```

## Running `doctor --notify` on a schedule

[`mailadmin doctor`](DNS.md) is the other half of the observability gap:
service/port/TLS/DANE/MTA-STS health, also previously manual-only. The same
timer shape works, just with a longer interval, a wedged service or a
missing listening port doesn't need hourly polling the way DNS drift does.

`/etc/systemd/system/mailadmin-doctor.service`:

```ini
[Unit]
Description=mailadmin health check (services, ports, TLS, DANE, MTA-STS)
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=oneshot
# --notify: push one ntfy alert naming every FAILing check, if any (WARN/ERROR
# rows are advisory and never page, see internal/cli/doctor.go). No-ops if
# [notify].url / NTFY_TOKEN are not configured.
ExecStart=/usr/local/bin/mailadmin --yes doctor --notify
User=root
```

`/etc/systemd/system/mailadmin-doctor.timer`:

```ini
[Unit]
Description=Run mailadmin doctor periodically

[Timer]
# Daily is enough for a health check this cheap; drop to a few hours if you
# want faster detection of a flapping service.
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

```sh
systemctl enable --now mailadmin-doctor.timer
```

## Push alerting beyond `--notify`

`--notify` covers the common case: one ntfy alert per unhealthy run, silent
otherwise. If you want a *systemd-level* alert too (e.g. because the binary
itself crashed, or you already have OnFailure-based alerting for everything
else on the box), it composes fine with `--notify` rather than replacing it:
add to either service above:

```ini
[Unit]
OnFailure=mailadmin-drift-check-alert.service
```

`/etc/systemd/system/mailadmin-drift-check-alert.service`:

```ini
[Unit]
Description=Notify on mailadmin drift-check failure

[Service]
Type=oneshot
ExecStart=/usr/bin/curl -fsS -d "mailadmin dns drift-check failed on %H, see: journalctl -u mailadmin-drift-check.service" https://ntfy.sh/YOUR-TOPIC
```

This stays a separate, coarser channel from `--notify`: it fires on any
non-zero exit (including a crash before any check even ran), with no detail
about *which* check failed, whereas `--notify`'s ntfy message always names
the specific failing checks/domains.
