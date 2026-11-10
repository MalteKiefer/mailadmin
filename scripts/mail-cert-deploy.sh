#!/usr/bin/env bash
#
# mail-cert-deploy, installs a freshly-issued mail TLS certificate and rolls
# the DANE TLSA record over before the new certificate goes live.
#
# Deployment on the mail server (NOT this repo checkout):
#   installed at:  /usr/local/sbin/mail-cert-deploy
#   invoked by:    a systemd oneshot service triggered by a `path` unit that
#                  watches Caddy's certificate output directory, so a renewal
#                  runs this script automatically. Because the script sleeps
#                  out the TLSA TTL (see below), the oneshot service needs an
#                  unbounded start timeout:
#
#                    # /etc/systemd/system/mail-cert-deploy.service.d/timeout.conf
#                    [Service]
#                    TimeoutStartSec=infinity
#
# This file is the single source of truth for the script; keep the server
# copy in sync with this one (deploy by copying this file to
# /usr/local/sbin/mail-cert-deploy, `chmod 0750`, owned by root). See
# docs/DNS.md "Certificate renewal & rollover" for the full writeup.
#
# ASSUMPTIONS (docs/DNS.md only ever showed the excerpt below, the umask,
# install(1) calls, dns publish/sleep, and reload, not the whole script, so
# the following scaffolding around it is inferred rather than copied
# verbatim; adjust to match the real deployment if it differs):
#   - $SRC_CRT / $SRC_KEY point at Caddy's freshly-issued leaf cert/key
#     (e.g. passed as argv from the triggering path/oneshot unit, or exported
#     by a wrapper, the path unit's WorkingDirectory/ExecStart supplies
#     these on the server; not documented in docs/DNS.md).
#   - $DOMAIN is the mail domain whose DANE record is rolled (also not
#     documented as to how it's supplied, likely a fixed value or argv on
#     a single-domain mail host).
#   - `set -euo pipefail` and root-only key files (0600) match the cert-sync helper
#     choices consistent with the rest of this repo's privileged scripts,
#     not literally quoted in docs/DNS.md.
set -euo pipefail

: "${SRC_CRT:?SRC_CRT must be set to the fullchain Caddy just issued}"
: "${SRC_KEY:?SRC_KEY must be set to the private key Caddy just issued}"
: "${DOMAIN:?DOMAIN must be set to the mail domain to roll DANE for}"

# --- verbatim from docs/DNS.md "Certificate renewal & rollover" -----------

umask 027
# The new pair is staged next to the live one and goes live only after its TLSA
# record had a TTL to propagate. Installing it first would let every new smtpd
# serve it while DANE senders still cache only the old TLSA, and they would
# defer mail for up to an hour on every renewal.
stage=$(mktemp -d /etc/ssl/mail/.staged.XXXXXX)
trap 'rm -rf "$stage"' EXIT
if ! { install -o root -g root -m 0600 "$SRC_CRT" "$stage/fullchain.pem" &&
       install -o root -g root -m 0600 "$SRC_KEY" "$stage/privkey.pem"; }; then
  echo "mail-cert-deploy: staging the new cert failed, the served cert is unchanged" >&2
  exit 1
fi

# DANE rollover: publish the NEW leaf's TLSA, read from the staged pair. Additive:
# the old TLSA stays valid during the overlap. Wait out the TTL so validators see
# the new TLSA before the served cert switches.
if out=$(MAILADMIN_MAIL_TLS_CERT="$stage/fullchain.pem" mailadmin --yes dns publish "$DOMAIN" --dane 2>&1); then
  sleep 3900            # > TLSA TTL (deSEC minimum is 3600)
else
  case "$out" in
  *"manage its zone manually"*)
    # No automated DNS provider: the TLSA record cannot be published from here, so the
    # renewal goes ahead. DANE validation fails for this domain until the new TLSA
    # record is published by hand.
    echo "warning: $DOMAIN has no automated DNS provider, continuing without a TLSA update; publish the new TLSA record by hand" >&2
    ;;
  *)
    printf '%s\n' "$out" >&2
    echo "mail-cert-deploy: TLSA publish failed, the served cert is unchanged" >&2
    exit 1
    ;;
  esac
fi

# Both files are renamed into place from the same file system, each atomically.
mv -f "$stage/privkey.pem" /etc/ssl/mail/privkey.pem
mv -f "$stage/fullchain.pem" /etc/ssl/mail/fullchain.pem
if ! systemctl reload-or-restart postfix dovecot; then
  echo "mail-cert-deploy: reload failed, postfix and dovecot still serve the old certificate; reload them by hand" >&2
  exit 1
fi

# --- end verbatim excerpt ---------------------------------------------------
