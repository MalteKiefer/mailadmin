# Changelog

All notable changes to `mailadmin` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/).

This file was populated retroactively from `git log` and `docs/SECURITY-AUDIT.md`
for every tagged release (`v1.14.0` onward). History before `v1.14.0` was
squashed into a single "Initial import" commit before this file existed, so it
is summarized rather than itemized commit-by-commit.

## Upgrading

### To v1.14.0 or later, `DESEC_TOKEN` may now be required

Release **v1.14.0** added deSEC as a supported DNS provider and, as part of the
same audit-remediation pass, added `DESEC_TOKEN` handling to `config init` /
`config check` (see `docs/SECURITY-AUDIT.md`, "L-6, L-7, I-1, I-3, I-4" and
"released as 1.14.0"). If you set a domain's `dns_provider` to `desec` (see
`docs/DNS.md`), `secrets.env` must define `DESEC_TOKEN`, or `dns publish` /
`dns migrate` / DANE rollover against that domain will fail. Domains left on
`manual` or another provider are unaffected. Run `mailadmin config check` after
upgrading to confirm your `secrets.env` has everything the configured
providers need.

## [Unreleased]

### Changed
- `git` is installed with the other packages. It is needed for the `dns.config_repo` flow.
- `gh` (GitHub CLI) is installed. Install asks to log in with `gh auth login` when it is not logged in. `dns sync` opens pull requests with it.

## [v1.35.0] - 2026-11-11

### Added
- `mailadmin dns tlsa-pr <domain>` (with `dns.config_repo`): writes the mail host's TLSA record into the mailadmin block of `dnsconfig.js` on a new branch, commits, pushes and opens a pull request. Nothing is merged by mailadmin.
- `mailadmin dns tlsa-status <domain>`: exit 0 when the merged record is live, 5 while pending, 3 without a pending change, 1 when the pull request was closed.
- The cert sync helper uses the pull request flow in repository mode: it installs the renewed certificate once `tlsa-status` reports the record live.

- `[dns] config_repo`: absolute path to a local DNSControl repository (`dnsconfig.js`). When set, mailadmin refuses the commands that write DNS records (`dns publish`, `dns publish --dane`, `dns takeover`, `dns restore`, `dns migrate`, `dns zone create`). The repository is the source of truth.

## [v1.34.1] - 2026-11-11

### Changed
- Table colours use a Nord-based palette (256-colour codes). Status colours: green ok, yellow drift, red missing or failed, cyan info. The header is bright and bold.
- All tables use one layout: bold header, a rule under the header, no outer border, two spaces between columns. Key-value output uses the same layout.

## [v1.34.0] - 2026-11-11

### Changed
- The mail certificate copy is renewed only when the live certificate expires within seven days, or when the host's domain was added or changed. Caddy's earlier renewals are not installed before that.
- `mailadmin upgrade` shows one summary table. The output of each step goes to `/var/lib/mailadmin/upgrade-<time>.log`. The last lines of a failing step are shown.
- `primary_domain` is part of the default config, so an existing config is not marked obsolete.
- `mailadmin update` rewrites config.toml in one layout on every run: `key = value` with single spaces, no indentation, one blank line before each table, comments and values unchanged. Keys added by a sync use the same layout.

## [v1.33.0] - 2026-11-11

### Changed
- `mailadmin update` also runs the config sync when the binary is already current. Keys the release added are written into config.toml. Keys the release dropped stay in place with a comment `# obsolete since <tag>` above them, and their values are kept.

## [v1.32.1] - 2026-11-11

### Changed
- `mailadmin update` adds the keys a new release introduced to config.toml. It saves the old file as `config.toml.before-<tag>` first. Existing values, comments and `[secrets]` stay as they are. Keys added are shown in a table. YAML and JSON configs still get the review hint only.
- `mailadmin upgrade` prints the plan as a table before it asks, colours the step headings and shows the summary as a table.

## [v1.32.0] - 2026-11-11

### Added
- `mailadmin upgrade`: backup, self-update, `install --adopt` from config, config check and doctor, in that order. A summary table shows each step. A failed step stops the steps after it.
- `[mail] primary_domain`: the main mail domain. Written by install, stored by adopt when it was asked for.

### Changed
- `install --adopt` reads hostname, IPv4/IPv6, the primary domain and the repository fingerprints from config.toml. It asks only for values the config lacks. Without a terminal, a missing value is a usage error.
- An adopt run no longer asks for the CrowdSec enrollment key.

## [v1.31.0] - 2026-11-11

### Added
- `[mail] dns_ttl` (default 3600): TTL of the published DNS records. Range 60 to 86400 seconds.
- `[timeouts]` section: `command` (default 30s) bounds one privileged command, `db_tool` (default 30m) bounds pg_dump and pg_restore. Values are Go durations, above 0 and at most 2h.

## [v1.30.2] - 2026-11-10

### Fixed
- The generated alps config has a `[webauthn]` section with the webmail domain as relying party id and origin. Without it alps could not register or check a second factor.

## [v1.30.1] - 2026-11-10

### Added
- `mailadmin webmail-passwd <address>`: the password helper for the webmail. It reads the current and the new password from stdin, checks the current password against the stored hash, then changes it and writes an audit entry. alps calls it through a sudoers rule that allows only this command for the `alps` user.
- Dovecot creates and advertises the default folders Drafts, Sent, Junk, Trash and Archive (SPECIAL-USE), so webmail clients show them.

### Changed
- `[webmail]` takes `url` (the alps binary, https) and `sha256` of that binary instead of `version` and the release zip. The alps binary is the upstream main commit 18c1877, which has the `trusted_origins` CSRF option that the v1 release lacks.
- The alps config lists every plugin explicitly, because one plugin section switches off the plugins it does not name.
- `sudo` is an installed package.

## [v1.30.0] - 2026-11-10

### Added
- Webmail: `install` sets up the alps webmail client when `[webmail] enabled = true`. The release zip is refused unless its sha256 matches the pinned `[webmail] sha256`. alps runs as the `alps` system user (`mailadmin-webmail.service`), listens on `[webmail] listen` and is routed through Caddy for `[webmail] domain`.
- Config: `[webmail]` and `[backup.borg]` sections, validated only when enabled. `BORG_PASSPHRASE` is a `[secrets]` key. Borg archiving itself is not installed yet.
- The managed Dovecot config enables IMAP METADATA (`mail_attribute`, `imap_metadata`), which the webmail needs to store its settings.

## [v1.29.6] - 2026-11-10

### Added
- Migration `006_indexes.sql`: index on `mailbox (domain, username)` and an expression index on the domain part of `alias.source`. Measured on 100k rows: domain mailbox listing 3.1 ms to 0.5 ms, alias listing for a domain 8.4 ms to 1.2 ms.

### Changed
- `dns drift-check` reads the domain table once and opens the database before its workers start. It no longer runs one lookup per domain, and parallel domain arguments no longer open the pool concurrently.
- Mailbox lists, completion and backup read address, quota and state only. Mailbox show and the list reads no longer load the password hash. The audit list no longer loads IP and user agent, which were never printed.
- Alias queries match the domain part with `split_part(source, '@', 2)` instead of `LIKE`, so the new index is used.

### Fixed
- AXFR transfer drains its channel after an error, so the transfer goroutine and its TCP connection are released.
- Mailbox paths cannot resolve to the mail root. A purge of such a path would have removed every mailbox. No current command reaches it, the address validator blocks it first.
- Backup help and dry-run text name the `[secrets]` table instead of `secrets.env`.

### Upgrade
- Apply migration 006 with `mailadmin install --adopt` on each host, then update the binary.

## [v1.29.5] - 2026-11-10

### Fixed
- `backup restore` checks everything before the first change: the config merge, the database dump, the sieve scripts, the DKIM directory and its owner. A refusal no longer leaves the host half restored. `--dry-run` runs the same checks.
- `backup restore` records the audit entry and syncs Caddy and rspamd for components that finished before a failure. A failed audit write is reported next to a failed restore.
- `backup restore` requires root, as `install` does. The dry-run stays available without root.
- `backup restore --dry-run` fails for an unreadable database dump, as the real restore does.
- Migration 002 sets the `p37.nexus` provider only while it is still `manual`, so a replay after a restore cannot undo a later choice.

## [v1.29.4] - 2026-11-10

### Fixed
- `update` no longer prints a "config check skipped" warning on a host without a config file.
- `config check` judges a symlinked `--config` file by its target, as `load` does.
- `backup restore` onto a dangling config symlink creates the file the link names instead of replacing the link.
- `backup restore --dry-run` runs the same config merge as the real restore and reports a refusal (live YAML or JSON config).
- Removed the unused `CopyFileFollow` helper. The restore of `config.toml` has a test that covers the secret-keeping path.

## [v1.29.3] - 2026-11-10

### Fixed
- Security and data: `backup restore` replaced the live `config.toml` with the bundle copy. Since v1.29.2 that copy has no `[secrets]` table, so a restore dropped API tokens and the rspamd controller password. The live `[secrets]` table is now kept. Bundles that still carry secrets win.
- `backup restore` refuses a live config that is YAML or JSON, instead of writing TOML under that name. The file is replaced atomically at mode 0600, and a symlink at the config path is followed.
- `config check` requires mode 0600 only for a config that holds secrets, as `load` does. A 0644 config without secrets no longer fails.
- `update` names the config in use (`--config`) when it prints the new-keys hint.

## [v1.29.2] - 2026-11-10

### Fixed
- Security: `backup create` copied `config.toml` with its `[secrets]` table into the bundle, so API tokens and the rspamd controller password were in the bundle. The bundle now stores the config without `[secrets]`. After a restore, add the table back by hand.
- `config check` failed `secrets_file` with "secrets.env missing" because secrets live in `config.toml` since v1.28. The check now reads the mode of the config file and reports a legacy `secrets.env` only as information.
- The mailadmin read grants moved from install code into migration `005_mailadmin_grants.sql`, so a database built from the migrations matches an installed one.

## [v1.29.1] - 2026-11-10

### Fixed
- `install` aborted on a fresh host when the CrowdSec firewall bouncer started before its API key was registered ("access forbidden"). The bouncer is now enabled after the key is set.

## [v1.29.0] - 2026-11-10

### Added
- `mailadmin update` compares the host config with the default config of the release it installed. It saves that default as `/etc/mailadmin/config.default.toml` for a diff and lists the keys the host config lacks. The host config is never changed. A failed download is a warning only.

## [v1.28.0] - 2026-11-10

### Added
- One configuration file for everything: `/etc/mailadmin/config.<ext>`, where `<ext>` is `toml`, `yaml`, `yml` or `json`. Exactly one file is allowed. Secrets are in its `[secrets]` table (owner-only, 0600). A legacy `secrets.env` is still read and moved into the file by `install --adopt`.
- `mailadmin config init` writes the default configuration of the latest release (`config.default.toml`, a release asset). Without network access the copy built into the binary is used (`--offline`). `--force` replaces an existing file.
- `[mail] quota_default`, `tls_mode`, and `[hardening] system`, `ssh`, `crowdsec` switches (all on by default).
- `mailadmin uninstall` removes what `install` added. It writes a verified full backup first to `/var/backups/mailadmin-uninstall-<time>/` (database, mail directories, DKIM keys, config with secrets, install record), then removes services, firewall table, packages install installed, repositories, the database and its cluster, users and data directories. `--no-backup` skips the backup, `--dry-run` shows the plan, `--yes` skips the host name prompt.
- `install` keeps an install record in `/var/lib/mailadmin/install.json`, with a copy of each file it changed. Uninstall uses it to restore the originals.

### Changed
- `install` writes the single config file (0600) instead of `config.toml` and `secrets.env`.

## [v1.27.1] - 2026-11-10

### Fixed
- `doveadm ... -A` (for example `doveadm quota get -A`) failed with "User listing returned failure": the Dovecot userdb now has an iterate query, and the auth workers that run it connect as the dovecot user (as root, PostgreSQL peer authentication refused them). Run `mailadmin install --adopt` after the update.

## [v1.27.0] - 2026-11-10

### Upgrade
- Run `mailadmin install --adopt` after `mailadmin update`. The Postfix alias map, the Dovecot config, the fstab entry for the Postfix socket mount and the CrowdSec acquisition only change through install.
- Dovecot enforces each mailbox's `quota_bytes` since v1.26.0. `mailbox add` stored 5 GiB by default without enforcing it, so check usage first (`doveadm quota get -A`) and raise the quota of large mailboxes with `mailbox set-quota`, or their new mail bounces.
- Sieve scripts now live in `/var/vmail/sieve/<domain>/<user>`. Scripts stored with v1.26.0 under the mailbox directory have to be set again with `mailadmin sieve set`.

### Security
- A catch-all alias took all mail of the domain, also for existing mailboxes. It now applies only to addresses that are neither a mailbox nor an alias.
- SSH hardening could still lock the operator out: an RSA key shorter than 3072 bits was cut off by RequiredRSASize, any unrestricted key in authorized_keys (a backup key, for example) switched password login off, ECDSA and RSA certificates were refused, and a login uid outside /etc/passwd fell back to root's keys. Password login is now switched off only when sshd's journal shows that the operator's last login used a key from their authorized_keys that the hardened sshd accepts.
- CrowdSec counted Postfix and Dovecot lines twice or three times on hosts with rsyslog. Install now adds a journal source only for logs no other acquisition file reads.

### Fixed
- An alias with several destinations delivered to only one of them.
- Dovecot listed the active Sieve script link as a mail folder; script storage moved out of the mailbox directory.
- `mailbox show` reported quota usage and limit 1024 times too small, and used a doveadm formatter Dovecot 2.4 does not have.
- `backup restore` of the database now updates rspamd's selector map and the Caddy includes.
- A DKIM selector map that mailadmin did not write is no longer replaced by domain commands.
- App password labels with upper case letters, spaces or other characters outside Dovecot's login set could never log in; new labels are limited to lower case letters, digits, `.`, `-` and `_`.
- A mailbox name with `+` is refused: Dovecot's LMTP cuts the local part at `+`, so such a mailbox never received mail.
- `mailbox dedupe` did not find the Maildir of mailboxes set up by install.
- `queue hold`, `release` and `delete` reported success for an unknown queue id.
- `security greylist` and `ratelimit` failed on hosts without local.d files; `greylist show` marks values written before v1.26.0 that rspamd reads as millions of seconds.
- The Postfix socket mount no longer fails when an unrelated tmpfiles entry fails at boot.
- install can be rerun right after a run: apt waits for a running unattended-upgrades, and the AIDE baseline is scheduled once, 30 minutes after install, so it hashes the updated system.
- A rerun of install no longer fetches the CrowdSec hub, restarts CrowdSec or replaces the bouncer key unless something changed; replacing the key flushed every ban.
- sshd logs at INFO instead of VERBOSE, so keys an SSH agent offers in vain no longer count as failed logins for CrowdSec.
- `install --adopt` keeps stricter sshd settings the operator had (`PermitRootLogin no`, multi factor `AuthenticationMethods`).
- The firewall opens the ports sshd really listens on (also `SSHD_OPTS -p` and `ssh.socket`), not only those in sshd_config.
- A host without an NTP service no longer aborts install at `timedatectl`.
- The PostgreSQL config permission change no longer follows links.
- The TLS group probe uses the distribution's openssl, and `apt-cache` runs in the C locale.
- Unchanged config files are not rewritten, so AIDE stays quiet and reloads happen only on change; Postfix settings are written with one postconf call.
- External commands are killed as a process group on timeout or Ctrl+C, and output beyond 64 MiB is an error instead of being cut silently.
- `backup restore` streams the dump, takes the database from the libpq service (no `service_file` required), and `pg_dump` and `pg_restore` get 30 minutes.
- Audit failures of security and mailbox changes are reported, and audit entries are written even after Ctrl+C.
- `service stop postgresql` records its audit entry before the database stops.
- `-o json` of `backup create` and `dns takeover` includes the bundle directory and the zone backup.
- `-q` no longer hides the one-time app password.
- `dns zone create` honours `--dry-run`, asks for confirmation and writes an audit entry.
- `domain remove` refuses while aliases of the domain exist.
- `domain set-dkim` warns that signing switches before the DNS record is published.
- `config check` fails for domains whose DNS provider has no credentials.
- `doctor` reports an expired or expiring certificate and an unreachable database, and checks MTA-STS endpoints in parallel.
- `security overview` shows whether the CrowdSec bouncer runs (instead of fail2ban), `security ban` accepts CIDR ranges, and `security firewall show` lists inline port sets and reads only mailadmin's table.
- `security learn-spam` and `learn-ham` by queue id train on the message only, not the envelope.
- `queue show` decodes only the requested entry.
- rspamd: a rate unit `w` is refused (rspamd reads it as seconds), nested objects in ratelimit.conf are parsed correctly, and local.d files are written atomically.
- Cloudflare: TXT values are unquoted when read, and TLSA records are written through the API's data fields.
- DNS checks use EDNS0 with a TCP fallback and report a failed lookup as an error, not as a missing record.
- DNS takeover and restore never touch SOA and the apex NS records; IP addresses are compared in canonical form.
- deSEC writes reuse the listed zone and need one request per changed record set.
- `dns drift-check --all` checks domains in parallel.
- The certificate deploy script stages the renewed pair, publishes its TLSA record and switches only after the TTL.
- Self update, the Caddy includes and rspamd files are synced to disk before they replace the old file.
- Install answers are normalized (lower case, no trailing dot, canonical IPv6).
- Release checksums are signed with the release key (`SHA256SUMS.asc`).

## [v1.26.0] - 2026-11-10

### Fixed
- SSH hardening could lock the operator out. Password login is now turned off only when the account the operator logged in with has a key the hardened sshd accepts (Ed25519, ECDSA, RSA with 3072 bits or more, no forced command). Root keeps password login when the operator logs in as root without such a key. ECDSA user keys (also FIDO) are accepted.
- CrowdSec read sshd twice and Postfix not at all: every failed SSH login counted double, so an operator was banned after about three typos, and Postfix attacks were never seen. Postfix is read from `postfix.service` (and `postfix@-.service` on older releases).
- `security ban list` was always empty with current cscli, `security firewall show` left out every port in the `allowed_tcp` and `allowed_udp` sets, and `security allowlist` and `security overview` failed because the allowlist did not exist. Install now creates it.
- unattended-upgrades did not update CrowdSec. The vendor sites now come from the repository list.
- A repository key download holding more than one key is refused; before, only the first key was checked and all were trusted.
- Dovecot never ran Sieve scripts on delivery and enforced no quota. LMTP now loads the sieve and quota plugins, the personal script storage is configured, and the userdb returns each mailbox's quota.
- A new domain, an enabled or disabled one, or a changed DKIM selector (set-dkim, rotation) now updates rspamd's selector map at once instead of after the next install.
- `domain dkim-rotate-start` and `dkim-rotate-finish` failed on domains without a DNS provider token ("closed pool").
- `backup restore` failed on hosts set up by install: pg_restore now runs as postgres in a single transaction and is no longer killed after 30 seconds.
- `mailadmin update` replaced a newer source build (`git describe` versions such as 1.25.1-3-gabc1234) with the older release.
- The Postfix socket bind mount is ordered after `systemd-tmpfiles-setup` and before Postfix, so it survives a reboot.
- `security greylist set --timeout 5m` wrote a value rspamd reads as 5,000,000 seconds; minutes are now written as `5min`.
- A `Port` line with a trailing comment in sshd_config was ignored, so the firewall opened only port 22.
- `sieve show`, `sieve edit` and backups did not find the active script with Pigeonhole 2.4.
- The units config written by install includes `crowdsec` and `crowdsec-firewall-bouncer`. On existing hosts, add them to `logs.units` in config.toml by hand; `install --adopt` keeps that file.

## [v1.25.1] - 2026-11-10

### Fixed
- `mailadmin update` treats a pre-release build (`1.25.0-dev`) as older than the release `1.25.0`, as SemVer requires. Before, it reported "already up to date".

## [v1.25.0] - 2026-11-10

### Added
- `mailadmin install` hardens the host along BSI SYS.1.3 and the CIS Debian Benchmark, Level 1 and 2. See `docs/HARDENING.md` for every control and the deliberate deviations.
- SSH: key only login (only when an authorized key exists, so nobody is locked out), no forwarding, `MaxAuthTries 3`, `MaxSessions 2`, hybrid post quantum key exchange `mlkem768x25519`, AEAD ciphers, SHA 2 MACs, RSA keys of at least 3072 bit. The config is checked with `sshd -t` and rolled back if rejected.
- TLS for Postfix and Dovecot: TLS 1.2 and 1.3 only, ECDHE with AEAD only, `X25519MLKEM768` first where OpenSSL 3.5 is installed, server cipher preference. IMAP port 143 is closed. Caddy sends HSTS on the mail host.
- Postfix: strict HELO, sender and recipient checks, per client rate limits, banner without version.
- System: sysctl hardening, blocked kernel modules, no core dumps, persistent journal, auditd rules, AIDE, AppArmor, time sync, `login.defs` policy, pwquality, libpam-tmpdir, process accounting, sysstat, debsums, cron and PostgreSQL config permissions, legal login banner.
- Updates: unattended-upgrades for the distribution and the vendor repositories with reboot at 04:00 when needed, needrestart, and a first update run during install.
- CrowdSec with the nftables bouncer replaces fail2ban. The repository key is checked like the others (`--crowdsec-fingerprint`). `--crowdsec-enroll-key` (asked during an interactive install) enrolls the instance in the CrowdSec console.

### Fixed
- `backup create` failed because the migrations left `schema_migrations` and the sequences unreadable for the mailadmin role. Install now grants read access.
- `doctor` checks port 587.
- `config check` no longer fails for provider tokens that are not used.
- The missing fingerprint error names the right flag (`--caddy-fingerprint`).
- mailadmin runs with umask 022, so files it creates for other services stay readable under a hardened login umask. Repository keyrings are written with an explicit mode.

## [v1.24.1] - 2026-11-10

### Fixed
- A trailing slash in `dkim_dir` no longer bypasses the symlink check.
- Restore creates a missing DKIM directory with mode 0750, not 0700, so rspamd can read the keys.
- The DKIM helper refuses a link at the key directory. The reload marker is replaced by a rename, so a planted FIFO or file is never opened.
- The snapshot directory must not be a link. Snapshots are synced before a wipe.
- `dns restore` checks the snapshot provider before the dry run and the prompt.
- Audit rows for `dns takeover`, `dns restore` and `dns migrate` are written after Ctrl+C. The clean audit has a 30 second timeout.
- Prompted hostname and domain, and the selector flag, are lower cased.
- Disabled records match Unicode case variants the way `EqualFold` does.

## [v1.24.0] - 2026-11-09

### Fixed
- Root-run paths can no longer be redirected through links: DKIM key generation commits by `mv -T` from a root-owned temp directory, the reload marker is written with noclobber, the DKIM owner change works through an `os.Root`, and owned host directories are changed through `O_NOFOLLOW` descriptors.
- Snapshot files are created with `O_EXCL|O_NOFOLLOW`.
- `env` and `runuser` receive absolute paths for the commands they run, so a user-writable `PATH` entry cannot supply `apt-get` or `psql`.
- The firewall table replaces itself with `add` and `delete` instead of `destroy`, which needs nftables 1.0.7 (Debian 12 ships 1.0.6). `nftables.conf` is written only after the table passes `nft -c`.
- `dns restore` refuses a snapshot taken at another provider.
- The certificate wait retries only when the sync helper reports "no certificate yet" (exit 3).
- Disabled DNS records are matched on normalised content, so a case difference no longer re-adds or re-enables them.
- The `dns migrate --clean` audit row survives Ctrl+C, and a failed audit write is reported.
- Restore creates a missing DKIM directory instead of aborting.
- Hostname and domain are lower-cased before they reach the units and helpers.

## [v1.23.1] - 2026-11-09

### Fixed
- Backup restore refuses a symlinked DKIM directory, and the owner change no longer reaches entries behind a link.
- Backup copy reads its source through an `os.Root`, so a directory swapped for a symlink during the backup cannot leak files from outside the tree.
- DKIM keys are generated in a root-owned temp directory and renamed into place, key last. A killed run leaves no partial key that later runs accept.
- The install refuses symlinks only on directories mailadmin owns. Other links, such as a vmail volume, work as before.
- `secrets.env`, `config.toml`, `pg_hba.conf`, `pg_ident.conf` and the nftables persist file are written atomically and synced, so a crash never leaves them truncated.
- The cert sync stages both certificate and key before renaming either, so a failed copy no longer leaves the new certificate next to the old key.
- `dns publish --dane` does not add a TLSA record that is already live.
- `dns migrate --clean` saves a snapshot first and writes an audit row, also when the clean stops midway.
- DNS record replacement keeps disabled records disabled instead of switching them back on.
- Bare command names are resolved in fixed system directories, not through `PATH`.

## [v1.23.0] - 2026-11-09

### Added
- `mailadmin install` for Ubuntu and Debian. It installs PostgreSQL and Caddy from their vendor repositories (key fingerprints must match), the mail packages, and configures Postfix, Dovecot 2.4, rspamd, Caddy, nftables and the certificate sync. It refuses existing mail state unless `--adopt` is given.

### Fixed
- Firewall reads the sshd ports (`Port` and `ListenAddress`) instead of a fixed port 22, so a host on another SSH port is not locked out.
- DNS takeover, migrate, restore, set-bimi and dkim-rotate-start record audit and output when a rectify fails after the change is live. `migrate --clean` and DKIM record removal flush correctly.
- DKIM selectors accept the characters `valid.Selector` allows. `--adopt` keeps the stored selector. The key helper no longer writes through planted symlinks.
- rspamd no longer signs for a From domain that differs from the login. `mail.tls_cert` is written so the TLSA rollover reads the new certificate.
- The cert sync retries a failed reload. App-password labels with `+` or `@` can be revoked.
- Backup restore skips the dkim component for bundles without a dkim directory.
- `scripts/mail-cert-deploy.sh` restores the previous certificate pair when installing the new one fails.
- `config init` sets the file mode explicitly, so a umask no longer narrows `config.toml`.

## [v1.22.0] - 2026-08-30

### Added
- Rspamd ratelimit and greylist tuning in the security CLI.
- Push alerting: `doctor` and `dns drift-check` report via ntfy.
- Audit list filters by actor, action, target, since and until.
- CI runs the internal/db integration tests against a real Postgres service.

### Fixed
- App-password `last_used` is no longer presented as tracked data.
- `mailbox` queries include the password column (lint and gosec findings from the merge).

## [v1.21.0] - 2026-08-30

### Added
- Rspamd Bayes feedback loop (`learn-spam`, `learn-ham`).
- `queue bounces` and log-derived rspamd and Postfix statistics.
- Sieve `vacation` and `vacation-off` autoresponder commands.
- Backup and restore commands with a DR runbook and a baseline migration.
- BIMI provisioning, two-step DKIM rotation and a cron-friendly DNS drift check.
- `valid.PathUnder` for realpath-confined path validation.

### Fixed
- Lint findings from merged branches (errorlint, gofmt, duplicate fuzz targets).

## [v1.20.3] - 2026-08-30

### Fixed
- `--dry-run` is now honoured across `mailbox`, `sieve`, `security`,
  `service`, `queue`, and `config` mutating commands (previously only
  `domain`/`alias` checked it), so a dry run never touches the DB, an
  external command, or a file for these command groups either.

### Changed
- Bumped the `go` directive to 1.26.6.

## [v1.20.2] - 2026-08-30

### Fixed
- `--dry-run` is now honoured in `domain` and `alias` mutating commands.
- The MTA-STS Caddy `include` is now kept in sync with a domain's lifecycle
  (added/removed alongside the domain) instead of drifting.

## [v1.20.1] - 2026-07-23

### Fixed
- `dns check --njalla` / `--desec` now force that specific provider's API
  regardless of the domain's configured `dns_provider`, matching the
  documented "verify a zone before switching providers" workflow.

## [v1.20.0] - 2026-07-23

### Added
- `--registrar` / `--desec` flags on `dns check`, to diff desired vs. live
  records at the provider's API instead of public DNS.

## [v1.19.0] - 2026-07-17

### Added
- End-to-end DANE verification:
  - `dns audit` now fetches the live certificate over STARTTLS and confirms
    the published `3 1 1` TLSA still matches it, catching a stale TLSA after
    a key rotation.
  - `doctor` gained outbound-DANE checks: `dane-outbound` (Postfix
    `smtp_tls_security_level` / `smtp_dns_support_level`), `dane-smtpd-cert`
    (served cert matches the cert that feeds the TLSA), and `dane-resolver`
    (loopback validating resolver present).

### Docs
- Documented DANE verification (`dns audit` live-cert match, `doctor`
  checks) and the design/implementation plan behind it.

## [v1.18.0] - 2026-07-17

### Added
- `domain set-provider <domain> <provider>` to point a domain at a DNS
  backend; `dns migrate` now offers to run it automatically on success.

## [v1.17.0] - 2026-07-16

### Added
- Inbound-SMTP DANE support: derive and manage a `3 1 1` TLSA record
  (`dns show --dane`, `dns publish --dane`), additive publishing so an
  in-progress certificate rollover never breaks delivery.

## [v1.16.1] - 2026-07-16

### Fixed
- deSEC API calls now retry `502`/`503`/`504` with exponential backoff, in
  addition to the existing `429` (`Retry-After`) handling, so a large publish
  or migration doesn't fail on a transient provider error.

## [v1.16.0] - 2026-07-16

### Added
- `dns migrate` retries on deSEC `429`, skips copying `NS`/`SOA` records
  (delegation belongs to the target zone), and gained `--clean` to wipe the
  target zone for a clean 1:1 replacement.

## [v1.15.0] - 2026-07-15

### Added
- Four new DNS providers: Cloudflare, INWX, Servercow, and servfail.network
  (alongside the existing Njalla/deSEC/manual), each with its own credential
  set in `secrets.env`.

### Security
- Recorded audit remediation status: sudoers and five orphaned privileged
  helper scripts removed on the server; `errcheck`/`ineffassign` cleared;
  deSEC errors now use a typed `*apiError` + `errors.As`; five dead functions
  and the queue-summary cluster removed; `DESEC_TOKEN` added to
  `config init`/`config check` (see [Upgrading](#upgrading)).

### CI
- Bumped `actions/checkout` to v5 and `actions/setup-go` to v6.

## [v1.14.0] - 2026-07-15

Initial tagged release. Squashed "Initial import" commit, the full CLI
(`domain`, `mailbox`, `alias`, `app-password`, `dns show`/`check`/`publish`/
`migrate`/`takeover`/`restore`, `dns audit`, `queue`, `sieve`, `security`
ban/allowlist/firewall, `service`, `audit list`, `doctor`, `stats`, `config`,
self-update) plus the Postgres-backed `internal/db` layer, Njalla/deSEC DNS
providers, and the injection-defence `internal/valid` package, as they stood
at the security audit dated 2026-07-15 (see `docs/SECURITY-AUDIT.md`, which
supersedes a 2026-07-14 report predating this tag).

[v1.20.3]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.20.3
[v1.20.2]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.20.2
[v1.20.1]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.20.1
[v1.20.0]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.20.0
[v1.19.0]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.19.0
[v1.18.0]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.18.0
[v1.17.0]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.17.0
[v1.16.1]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.16.1
[v1.16.0]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.16.0
[v1.15.0]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.15.0
[v1.14.0]: https://github.com/MalteKiefer/mailadmin/releases/tag/v1.14.0
