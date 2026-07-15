-- 002_dns_provider.sql
-- Adds per-domain registrar selection for automated mail-DNS management
-- (internal/dnsprovider). Additive + safe on a live server: postfix/dovecot
-- select explicit columns, and the table-level GRANT SELECT to postfix covers
-- the new column.
--
-- Applied to the live `mail` DB on 2026-07-14.

ALTER TABLE domain
    ADD COLUMN IF NOT EXISTS dns_provider text NOT NULL DEFAULT 'manual';
    -- values: 'manual' (no automation) | 'njalla'

-- p37.nexus is hosted at Njalla.
UPDATE domain SET dns_provider = 'njalla' WHERE name = 'p37.nexus';
