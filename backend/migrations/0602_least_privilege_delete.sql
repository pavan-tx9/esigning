-- Integration (SPEC "Migrations": integration owns the 0600s).
--
-- Least privilege on the evidence-bearing mutable tables.
--
-- `0002_roles.sql` gave `esign_app` SELECT, INSERT, UPDATE, DELETE on every non-append-only table.
-- The application issues exactly one kind of DELETE, on `idempotency_keys` (the worker's
-- housekeeping sweep and the idempotency helper). Everything else that grant allows is a capability
-- nothing uses -- and `signers`, `signing_sessions` and `signature_captures` are the rows the
-- certificate of completion is built from. A compromise of the runtime role could erase them while
-- the append-only tables stayed intact, which is a worse story to tell than it needs to be.
--
-- UPDATE stays: the state machine needs it (envelope status, signer status, session revocation).
-- SPEC section 2 is updated in the same commit.

REVOKE DELETE ON TABLE
  hosts,
  templates,
  template_versions,
  envelopes,
  signers,
  signing_sessions,
  signature_captures,
  seal_jobs,
  webhook_deliveries
FROM esign_app;

-- `idempotency_keys` keeps DELETE: it is a cache with a TTL, not evidence.
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE idempotency_keys TO esign_app;

-- And stop handing DELETE out by default, so a later module migration that adds a table has to say
-- so deliberately rather than inheriting the capability. `0002` set these; this narrows them.
DO $$
DECLARE
  granting_role text;
BEGIN
  FOREACH granting_role IN ARRAY ARRAY[current_user::text, 'esign_owner'::text] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = granting_role) THEN
      EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
        'REVOKE DELETE ON TABLES FROM esign_app', granting_role);
    END IF;
  END LOOP;
END
$$;
