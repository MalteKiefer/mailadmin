-- 005_mailadmin_grants.sql
--
-- Read access for the mailadmin role on everything the migrations create. The
-- migrations run as postgres, so without these grants mailadmin cannot read
-- schema_migrations or the sequences, and pg_dump in `backup create` fails.
-- The default privileges cover tables and sequences that later migrations add.
--
-- Until now these statements lived in install code (GrantMailadminRead), so a
-- database built from the migrations alone lacked them. They are idempotent.

GRANT SELECT ON ALL TABLES IN SCHEMA public TO mailadmin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mailadmin;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT SELECT ON TABLES TO mailadmin;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO mailadmin;
