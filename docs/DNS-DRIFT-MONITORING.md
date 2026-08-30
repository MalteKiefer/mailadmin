# DNS drift monitoring

`mailadmin dns drift-check` compares every domain's desired mail DNS
record-set against what is actually live in public DNS — the same comparison
[`dns check`](DNS.md#dns-show--dns-check) does — and exits non-zero (runtime
error, exit code 1) if anything is missing or has drifted. That makes it a
good fit for a periodic, unattended job: a registrar-side edit, an expired
zone, a botched manual change, or (for automated providers) a `dns publish`
that silently failed will all show up here well before a mailbox operator
notices delivery problems.

```sh
mailadmin dns drift-check --all              # human-readable table + exit code
mailadmin dns drift-check --all -o json      # {"domain":...,"total":...,"matched":...,"drift":...} per domain
mailadmin dns drift-check example.com        # a single domain
```

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
# A non-zero exit (drift found, or a domain could not be checked) marks the
# unit failed — systemd records that in `systemctl status` / `journalctl`,
# which is what the alerting hook below reacts to.
ExecStart=/usr/local/bin/mailadmin --yes dns drift-check --all
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

## Wiring up an actual alert (deliberately out of scope here)

`mailadmin` has no built-in push-notification integration — no ntfy, no
Slack/Discord webhook, no email-on-failure. That is consistent with the rest
of the CLI: it is a single, console-only static binary with no background
daemon and no outbound integrations of its own (see
[`docs/ARCHITECTURE.md`](ARCHITECTURE.md) — no HTTP server, no scheduler).
Turning "the service unit failed" into a notification is left to the
operator, using whatever they already use for the rest of the box's alerting.
Two common, low-effort options:

**A `OnFailure=` unit that fires a webhook** (e.g. to
[ntfy](https://ntfy.sh/)) — add to the service above:

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
ExecStart=/usr/bin/curl -fsS -d "mailadmin dns drift-check failed on %H — see: journalctl -u mailadmin-drift-check.service" https://ntfy.sh/YOUR-TOPIC
```

**A wrapper script** that runs `drift-check` itself and only notifies on
failure, if you'd rather not add a second unit:

```sh
#!/bin/sh
# /usr/local/sbin/mailadmin-drift-check-notify
if ! /usr/local/bin/mailadmin --yes dns drift-check --all; then
  curl -fsS -d "mailadmin dns drift-check found DNS drift on $(hostname)" \
    https://ntfy.sh/YOUR-TOPIC
fi
```
...then point the service's `ExecStart=` at the wrapper instead.

Either way, `mailadmin` itself stays notification-free; it only promises the
non-zero exit code that makes both approaches possible.
