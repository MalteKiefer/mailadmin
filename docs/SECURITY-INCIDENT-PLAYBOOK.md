# Security Incident Playbook

Concrete, ordered runbooks for the incidents most likely to hit a `mailadmin`
mail host. Every step below names a command that exists today
(`mailadmin --help` for the full tree; `docs/DNS.md` and `docs/ARCHITECTURE.md`
for background). Nothing here assumes a command from a branch that hasn't
landed — if a step you expect isn't here, it isn't implemented yet.

Conventions used below:
- Commands are shown without global flags; add `--yes` to skip the
  interactive confirmation when scripting a response, and `--dry-run` to
  preview a mutating command before running it for real.
- Every mutating command here writes to the append-only audit log
  (`mailadmin audit list`); that's your primary post-incident timeline.

- [1. A mailbox / app-password appears compromised](#1-a-mailbox--app-password-appears-compromised)
- [2. A domain's DNS appears hijacked or tampered](#2-a-domains-dns-appears-hijacked-or-tampered)
- [3. CrowdSec shows a sustained attack pattern](#3-crowdsec-shows-a-sustained-attack-pattern)
- [General post-incident checklist](#general-post-incident-checklist)

---

## 1. A mailbox / app-password appears compromised

**Detection signs**: a spike in `queue list` entries with an internal
`SENDER`, a spam/abuse complaint naming one of your addresses, unexpected
volume in `mailadmin stats`, a successful Dovecot login for the mailbox from
an unfamiliar IP in `mailadmin log show dovecot` (app-password use is *not*
tracked in `app-password list` — see docs/SECURITY-AUDIT.md — so the auth
log is the only place this shows up, and it identifies the mailbox, not
which app-password label was used), or an external report of spam apparently
sent "from" one of your domains.

### Containment (do these first, in order)

1. **Stop further sending immediately.**
   ```sh
   mailadmin mailbox disable <address>
   ```
   This flips the mailbox inactive — Dovecot/Postfix stop authenticating it —
   without deleting any data, so you keep everything for review.

2. **Kill every application password on the mailbox**, not just the one you
   suspect — if one leaked, assume any others issued around the same time may
   have too:
   ```sh
   mailadmin mailbox app-password list <address>
   mailadmin mailbox app-password remove <address> <label>   # repeat per label
   ```

3. **Force a password reset** so re-enabling the mailbox later doesn't hand
   the attacker back the same credential:
   ```sh
   mailadmin mailbox passwd <address>
   ```
   This prompts for a new password interactively — do not script a value
   into a shell history; if you must automate it, pipe it via the same
   stdin prompt from a secrets manager, never as a CLI argument.

4. **Stop anything already queued from the compromised account** before it
   delivers:
   ```sh
   mailadmin queue list
   ```
   Scan the `SENDER` column for the compromised address, then for each
   matching `QUEUE ID`:
   ```sh
   mailadmin queue hold <qid>      # freeze it while you investigate
   mailadmin queue delete <qid>    # or drop it outright once confirmed abusive
   ```
   `queue show <qid>` prints the full message (headers + envelope) if you
   need to confirm it's actually spam before deleting.

5. **Ban the source IP(s)** the abuse came from, if you can identify them
   from `queue show` (Received headers) or your MUA/webmail logs:
   ```sh
   mailadmin security ban add <ip> --dur 24h
   ```
   Omit `--dur` for CrowdSec's default decision duration; use a longer
   `--dur` (e.g. `72h`) if the same IP keeps reappearing.

### Post-incident (once containment is confirmed)

6. **Review the audit trail** for everything that touched this mailbox and
   its app-passwords, to establish when the compromise started and what else
   the attacker may have touched:
   ```sh
   mailadmin audit list --lines 500
   ```
   Filter/grep the output for the mailbox's address and for
   `mailbox.`/`app_password.` actions.

7. **Check DKIM wasn't also touched.** A mailbox compromise doesn't imply a
   DKIM key compromise, but if the attacker had any elevated access, verify
   the domain's key hasn't been rotated or the selector changed without your
   knowledge:
   ```sh
   mailadmin dns audit <domain> --selector <sel>
   ```
   A `fail`/`warn` on DKIM here that you didn't cause is itself an incident —
   go to [scenario 2](#2-a-domains-dns-appears-hijacked-or-tampered).

8. **Re-enable once you're confident the credential is rotated and nothing
   is still queued**:
   ```sh
   mailadmin mailbox enable <address>
   ```

9. Work through the [general post-incident checklist](#general-post-incident-checklist).

---

## 2. A domain's DNS appears hijacked or tampered

**Detection signs**: `mailadmin dns audit <domain>` reports an unexpected
`fail`/`warn` on MX, DKIM, DMARC, or DANE; `mailadmin dns check <domain>`
shows a live record that doesn't match the desired set and that you didn't
change; mail delivery reports (DMARC aggregate reports, bounces) show traffic
from an MX or IP you don't recognize; a registrar/provider login alert you
didn't trigger.

### Detection (confirm before you act)

1. **Diff live public DNS against the desired record set:**
   ```sh
   mailadmin dns check <domain>
   ```
   This resolves through the fixed `dns.resolver` and reports, per record,
   whether it matches, drifts, or is missing.

2. **Diff what's actually configured at the provider** (in case DNS caching
   is hiding a change that's already live at the API, or vice versa):
   ```sh
   mailadmin dns check <domain> --registrar
   ```
   This also lists stale records the provider has that aren't part of the
   managed mail set — useful for spotting a record the attacker *added*
   (e.g. a rogue MX or a second DKIM selector) rather than one they changed.

3. **Grade the full posture** to see everything at once (SPF/DKIM/DMARC/
   DNSSEC/DANE/MTA-STS/TLS-RPT/BIMI):
   ```sh
   mailadmin dns audit <domain>
   ```
   Pay special attention to DNSSEC: if the zone is DNSSEC-signed and
   `dns audit` still reports DNSSEC as failing/unsigned, that itself is
   evidence of tampering (a legitimate change wouldn't break the chain).

### Containment

4. **If the domain is on an automated provider** (`manual` domains have
   nothing to revert here — see step 4b), republish the correct record set
   to overwrite whatever was tampered with:
   ```sh
   mailadmin dns publish <domain> --dry-run    # confirm the plan first
   mailadmin dns publish <domain>
   ```
   `publish` is idempotent and reconciles the desired set without touching
   anything it doesn't manage, so this is safe to run even if you're not
   100% sure what changed.

   If the tampering also planted *extra*, unmanaged records (a rogue MX, a
   webshell-serving A record on a mail subdomain, etc.) that `publish` won't
   touch, a full reset of the zone is the stronger option:
   ```sh
   mailadmin dns takeover <domain> --dry-run
   mailadmin dns takeover <domain>
   ```
   `takeover` replaces the **entire** zone with the correct mail record set
   and snapshots the old (tampered) zone to `backup.dns_backup_dir` first —
   keep that snapshot as evidence. Use `--keep-web` if the domain also
   serves a website you don't want touched (verify the web A/AAAA/CNAME
   weren't themselves the attack vector first).

   If you have a known-good snapshot from before the incident (an earlier
   `takeover` backup, or one taken proactively), you can restore it directly
   instead of re-deriving from config:
   ```sh
   mailadmin dns restore <domain> <backup>
   ```

4b. **If the domain is `manual`** (no automated provider), `mailadmin` can't
    push a fix for you — `dns show <domain>` prints the correct record set;
    log into the registrar/DNS host directly (through a channel you trust —
    not any link from the incident itself) and correct the records by hand,
    then re-run `dns check <domain>` to confirm.

5. **Check whether the domain's provider account itself is compromised**
   (as opposed to just the records): if `dns check --registrar` shows
   records neither you nor `mailadmin` published, rotate the provider API
   credential (`NJALLA_TOKEN` / `DESEC_TOKEN` / `CLOUDFLARE_API_TOKEN` /
   `INWX_*` / `SERVERCOW_*` / `SERVFAIL_*` in `secrets.env`, per
   `docs/DNS.md`) at the provider's own console, then update `secrets.env`
   on the mail host and re-run `mailadmin config check`.

6. **If DANE/TLSA was the target** (an attacker publishing their own TLSA to
   either break delivery or MITM DANE-validating senders), `dns publish
   <domain> --dane` republishes the value derived from your actual
   certificate (`mail.tls_cert` in `config.toml`), which is additive and
   will not remove a malicious record on its own — use `dns takeover` (step
   4) if a rogue TLSA needs to be actively removed, then republish DANE.

### Notification / post-incident

7. Confirm the fix took: `mailadmin dns audit <domain>` should return to a
   clean bill of health (DANE should read `pass — N TLSA, authenticated` if
   the domain uses it).
8. Review `mailadmin audit list` for the window around the change to see if
   it originated from `mailadmin` itself (a leaked local credential) or
   purely at the provider (a leaked provider API token / registrar account).
9. Notify anyone relying on this domain's mail security posture (downstream
   admins, users if delivery was disrupted) and, if a registrar/provider
   account was compromised, that provider's abuse/security team.
10. Work through the [general post-incident checklist](#general-post-incident-checklist).

---

## 3. CrowdSec shows a sustained attack pattern

**Detection signs**: `mailadmin security overview` shows a growing `bans:`
count or an unfamiliar `scenario` recurring across many IPs (credential
stuffing, SMTP auth brute-force, IMAP brute-force), or CrowdSec's own metrics
show a sustained volume against the mail ports.

### Response

1. **Get the current picture:**
   ```sh
   mailadmin security overview
   ```
   This aggregates active bans, the allowlist, open ports, and whether
   fail2ban is running (hosts set up by `mailadmin install` use CrowdSec
   instead, so it reports false there), in one call — start here so you don't act on stale
   information.

2. **Inspect active bans in detail** if you need to correlate scenario/
   origin/duration across many IPs:
   ```sh
   mailadmin security ban list
   ```

3. **Extend containment beyond CrowdSec's own decisions** for IPs/ranges
   that keep reappearing or that CrowdSec hasn't caught yet (e.g. a slow,
   low-and-slow credential-stuffing pattern under its detection threshold):
   ```sh
   mailadmin security ban add <ip-or-cidr> --dur 24h
   ```
   Prefer a CIDR over single IPs once you see the same /24 or /64 rotating
   through addresses. Use progressively longer `--dur` (or omit it for
   CrowdSec's default) as the pattern persists.

4. **Verify the allowlist hasn't been polluted** — an attacker who gained
   any privileged access could have allowlisted their own source to defeat
   future bans:
   ```sh
   mailadmin security allowlist list
   ```
   Remove anything you don't recognize:
   ```sh
   mailadmin security allowlist remove <ip>
   ```

5. **Check exposed surface** — confirm nothing was opened that shouldn't be
   (a wider attack surface makes a sustained campaign more effective):
   ```sh
   mailadmin security firewall show
   ```
   Close anything unexpected:
   ```sh
   mailadmin security firewall close <proto> <port>
   ```

6. **If the pattern is targeting one service specifically** (e.g. IMAP
   brute-force but SMTP submission is clean), consider whether that service
   needs a temporary restriction beyond what CrowdSec/nft already provide —
   at minimum, confirm via `mailadmin doctor` that the service's own
   hardening (rate limits, `dane-outbound`, TLS config) is intact and wasn't
   itself weakened as part of the attack.

### Post-incident

7. `mailadmin security ban list` again after the pattern subsides to decide
   which bans should be made longer-lived (or permanent, if your CrowdSec
   config supports it) versus left to expire.
8. `mailadmin audit list` to confirm no ban/allowlist/firewall change during
   the window was made by anything other than you or CrowdSec's automatic
   decisions — an attacker who could add themselves to the allowlist implies
   a deeper compromise than the network-level attack alone.
9. Work through the [general post-incident checklist](#general-post-incident-checklist).

---

## General post-incident checklist

Run after any of the scenarios above are contained:

- [ ] `mailadmin audit list --lines 1000` reviewed for the full incident
      window; save a copy off-host as your incident record.
- [ ] `mailadmin dns audit <domain>` clean for every domain that was in
      scope.
- [ ] `mailadmin doctor` clean (catches config drift introduced or exposed
      during the incident).
- [ ] `mailadmin security overview` reviewed once more, a day later, to
      confirm the attack pattern hasn't resumed.
- [ ] Any credential touched during the incident (mailbox password,
      app-password, DNS provider API token) has been rotated, not just
      disabled.
- [ ] `secrets.env` permissions re-verified (`mailadmin config check`) —
      an incident is a good trigger to confirm nothing loosened it.
