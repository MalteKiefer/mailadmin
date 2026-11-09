-- Dovecot authenticates app-password logins (user@domain+label) against
-- app_password joined to the active mailbox (internal/install/mailconf.go).
-- 001 granted dovecot only domain and mailbox, so this is the missing read grant.
GRANT SELECT ON app_password TO dovecot;
