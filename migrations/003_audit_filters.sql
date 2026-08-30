-- 003_audit_filters.sql
-- Adds indexes backing the new `mailadmin audit list` filters
-- (--actor/--action/--target/--since/--until, internal/db/db.go's
-- AuditFilter). 001_baseline.sql only ever indexed (ts DESC), because
-- ListAudit only ever took a row-count limit; actor/action/target were
-- unindexed WHERE-able columns until now. Additive + safe on a live server:
-- CREATE INDEX IF NOT EXISTS, no table rewrite, no data change.
--
-- target has no dedicated index: AuditFilter's target match is
-- `target=$n OR target LIKE '%@'||$n`, and a plain btree index only serves
-- the exact-match half (the LIKE '%@'||$n half is a suffix search a btree
-- can't use). Given the audit_log table's expected size (append-only,
-- pruned/archived per operational policy, not a high-cardinality analytics
-- table), a sequential scan for --target is acceptable; revisit with a
-- trigram (pg_trgm) index if that assumption stops holding.

CREATE INDEX IF NOT EXISTS audit_log_actor_idx ON audit_log (actor);
CREATE INDEX IF NOT EXISTS audit_log_action_idx ON audit_log (action);
