-- Database roles and grants. Owned by the foundation (SPEC "Database roles").
--
-- Two roles:
--   esign_owner  owns every object and runs migrations.
--   esign_app    is the runtime role. SELECT, INSERT only on the append-only tables; full DML on
--                the rest; no DDL, no TRUNCATE.
--
-- The grants are the first line of defence and the append-only triggers in 0001 are the second.
-- Both are tested: the app role is denied outright, and the owner role -- which the grants do not
-- stop -- still hits the trigger.
--
-- This file is idempotent: it can be re-run against a database that already has the roles, and it
-- is run against every freshly created test database. Passwords are set only when a role is
-- created here, and only to a dev value that matches docker-compose.yml. A production deployment
-- creates these roles out of band with real credentials, and this migration then leaves them alone.

-- ---------------------------------------------------------------- roles
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'esign_owner') THEN
    CREATE ROLE esign_owner LOGIN PASSWORD 'esign_owner_dev';
  END IF;
EXCEPTION WHEN duplicate_object THEN
  NULL;  -- another migration runner created it between the check and the CREATE
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'esign_app') THEN
    CREATE ROLE esign_app LOGIN PASSWORD 'esign_app_dev';
  END IF;
EXCEPTION WHEN duplicate_object THEN
  NULL;
END
$$;

-- ---------------------------------------------------------------- schema access
DO $$
BEGIN
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO esign_app', current_database());
END
$$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO esign_app;

-- The app role never creates, alters or drops anything.
REVOKE CREATE ON SCHEMA public FROM esign_app;

-- ---------------------------------------------------------------- append-only tables
-- No UPDATE, no DELETE, no TRUNCATE. Evidence is added to, never edited.
REVOKE ALL ON TABLE
  audit_events,
  blobs,
  document_revisions,
  consent_texts,
  reauth_attestations
FROM esign_app;

GRANT SELECT, INSERT ON TABLE
  audit_events,
  blobs,
  document_revisions,
  consent_texts,
  reauth_attestations
TO esign_app;

-- ---------------------------------------------------------------- mutable tables
-- Full DML, still no TRUNCATE (never granted) and no DDL.
REVOKE ALL ON TABLE
  hosts,
  templates,
  template_versions,
  envelopes,
  signers,
  signing_sessions,
  signature_captures,
  idempotency_keys,
  seal_jobs,
  webhook_deliveries
FROM esign_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
  hosts,
  templates,
  template_versions,
  envelopes,
  signers,
  signing_sessions,
  signature_captures,
  idempotency_keys,
  seal_jobs,
  webhook_deliveries
TO esign_app;

-- ---------------------------------------------------------------- migration bookkeeping
REVOKE ALL ON TABLE schema_migrations FROM esign_app;
GRANT SELECT ON TABLE schema_migrations TO esign_app;

-- ---------------------------------------------------------------- default privileges
-- So a later migration (evidence 01xx, sealing 02xx, ...) that adds a table does not have to
-- remember to grant anything for the app role to work. A new append-only table is the exception
-- and must REVOKE UPDATE, DELETE in its own migration, next to its trigger.
DO $$
DECLARE
  granting_role text;
BEGIN
  FOREACH granting_role IN ARRAY ARRAY[current_user::text, 'esign_owner'::text] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = granting_role) THEN
      EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
        'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO esign_app', granting_role);
      EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
        'GRANT USAGE, SELECT ON SEQUENCES TO esign_app', granting_role);
      EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
        'GRANT EXECUTE ON FUNCTIONS TO esign_app', granting_role);
    END IF;
  END LOOP;
END
$$;

-- ---------------------------------------------------------------- existing functions
GRANT EXECUTE ON FUNCTION forbid_mutation() TO esign_app;
GRANT EXECUTE ON FUNCTION template_versions_guard() TO esign_app;
