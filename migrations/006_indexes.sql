-- 006_indexes.sql
--
-- Two indexes for lookups the CLI runs by domain. Both are additive: no table
-- is rewritten and no row changes. IF NOT EXISTS keeps a rerun harmless.
--
-- mailbox: the primary key is (username, domain), so a lookup by domain alone
-- (ListMailboxes(domain), CountMailboxesInDomain, the cascade of a domain delete
-- through mailbox_domain_fkey) cannot use it. Measured on 100k mailboxes, the
-- domain listing went from 3.1 ms (primary key with 112 index searches) to 0.5 ms
-- (1 index search).
CREATE INDEX IF NOT EXISTS mailbox_domain_username_idx ON mailbox (domain, username);

-- alias: ListAliases(domain) and CountAliasesInDomain match the domain part of
-- the source. Written as LIKE '%@domain' no index applies, and the planner
-- scanned the table. The queries now use split_part(source, '@', 2), which this
-- expression index serves directly; the catch-all "@domain" yields the same
-- domain part. Measured on 100k aliases: 8.4 ms (sequential scan) to 1.2 ms.
CREATE INDEX IF NOT EXISTS alias_domain_idx ON alias ((split_part(source, '@', 2)));
