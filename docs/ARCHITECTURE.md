# mailadmin — Go CLI architecture

Single static binary, console-only, run as root over hardened SSH. Replaces the
old bash CLI + the (removed) mailadmin-web. No HTTP server, no OIDC.

## Command tree (locked)

```
mailadmin
  domain     list | show <d> | add <d> [--selector] [--dns njalla|manual]
             | remove <d> | enable <d> | disable <d>
             | set-dkim <d> <sel> | regen-dkim <d>
  mailbox    list [--domain d] | show <a> | add <a> [--quota] | remove <a> [--purge]
             | passwd <a> | set-quota <a> <bytes> | enable <a> | disable <a> | dedupe <a>
             app-password list <a> | add <a> <label> | remove <a> <label>
  alias      list [--domain d] | show <src> | add <src> <dst> [--catch-all] | remove <src> [<dst>]
  dns        show <d> | check <d> | publish <d> | takeover <d> [--keep-web] | restore <d> <backup>
  security   ban list|add <ip> [--dur]|remove <ip>
             allowlist list|add <ip>|remove <ip>
             firewall show | open <proto> <port> | close <proto> <port>
             overview
  queue      list | show <qid> | flush | hold <qid> | release <qid> | delete <qid>
  service    list | status <unit> | start|stop|restart|reload <unit>
  log        show <unit> [-n] | tail <unit>
  stats      inbound | outbound | spam | domain <d>
  sieve      show <a> | set <a> <file> | edit <a>
  audit      list [-n]
  doctor                                   # health check (services, ports, TLS, rspamd config)
  config     show | check | edit | init
  version | completion <shell>
```

Conventions:
- Verbs: `list show add remove enable disable` are canonical; resource-specific
  verbs (passwd, regen-dkim, flush) where they read naturally.
- Global flags: `-o, --output table|json|plain` (default table), `--yes` (skip
  confirm), `--dry-run` (mutating external state, esp. dns), `-q, --quiet`,
  `--config <path>`.
- Destructive ops: interactive confirm unless `--yes`. `--dry-run` prints the plan.
- Exit codes: 0 ok, 1 runtime error, 2 usage error, 3 not-found, 4 confirmation declined.

## Config (locked: TOML + secrets.env)

`/etc/mailadmin/config.toml` (world-readable, non-secret):
```toml
[postgres]
service      = "mail-admin"
service_file = "/var/lib/mailadmin/.pg_service.conf"
[mail]
hostname         = "mail.kiefer-networks.de"
dkim_dir         = "/var/lib/rspamd/dkim"
default_selector = "mail2026"
[server]
ipv4 = "152.53.156.62"
ipv6 = "2a0a:4cc0:c2:78e1:e8dd:7eff:fe13:2b56"
[dns]
resolver = "1.1.1.1:53"
[backup]
dns_backup_dir = "/var/lib/mailadmin/dns-backups"
[logs]
units = ["postfix","dovecot","rspamd","caddy","crowdsec","postgresql"]
```
`/etc/mailadmin/secrets.env` (mode 0600, root): `NJALLA_TOKEN=…`,
`RSPAMD_CONTROLLER_PW=…`. Loaded into memory; NEVER echoed, logged, or put in
error messages. Env `MAILADMIN_*` overrides config keys.

## Package map

| Package | Role |
|---|---|
| `cmd/mailadmin` | main(); builds root cobra command |
| `internal/cli` | cobra command definitions (one file per resource group), flag wiring, output |
| `internal/config` | TOML + secrets loader, validation, `config` command backend |
| `internal/output` | table/json/plain renderer (`-o`); one place, no per-command formatting |
| `internal/db` | Postgres (pgx) — domains/mailboxes/aliases/app-passwords/audit **(done)** |
| `internal/dnsprovider` | registrar DNS (Njalla), Plan/Reconcile/Backup/ReplaceAll/Restore **(done)** |
| `internal/mail` | DKIM key read/gen, desired-record set, MTA-STS policy id |
| `internal/dnscheck` | verify SPF/DKIM/DMARC/MX/MTA-STS/TLS-RPT (miekg/dns) |
| `internal/sys` | thin, audited exec wrapper (context, timeout, no shell, arg slices) |
| `internal/postfixq` | postqueue/postsuper |
| `internal/security` | cscli (crowdsec), nft (read + fw-port), fail2ban |
| `internal/services` | systemctl (explicit unit allowlist) |
| `internal/logs` | journalctl / caddy logs |
| `internal/stats` | postfix+rspamd log parsing → series |
| `internal/sieve` | doveadm sieve |
| `internal/quota` | doveadm quota |
| `internal/dovecotpw` | argon2id hashing via `doveadm pw` |
| `internal/audit` | append audit_log rows (wraps db.Log) for every mutation |

`internal/sys` is the single privileged-exec chokepoint: no `sh -c`, args as
slices, per-call timeout via context, output capped, and it records every
invocation so `audit`/logging is consistent and injection-free.
