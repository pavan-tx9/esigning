-- 0100: the missing TRUNCATE guard on `blobs`. Evidence module (SPEC "Migrations", 01xx range).
--
-- `0001` gives every append-only table a BEFORE UPDATE OR DELETE trigger, but only `audit_events`
-- also gets a BEFORE TRUNCATE one. For `blobs` that left exactly one line of defence: the app
-- role has no TRUNCATE privilege, so the runtime cannot do it -- but the owner role, which runs
-- migrations and which the grants do not stop, could erase the whole blob index with
-- `TRUNCATE TABLE blobs CASCADE` and hit nothing. SPEC section 12 asks for both defences on the
-- append-only tables, and the blob index is the map from a document hash to the bytes that prove
-- it: losing it silently is the worst outcome in this system.
--
-- This adds the guard for `blobs` using the `forbid_mutation()` function `0001` already defines.
-- `document_revisions`, `consent_texts` and `reauth_attestations` have the same gap and the same
-- one-line fix, but they belong to other modules; that is reported to the architecture owner
-- rather than patched from here.
--
-- CREATE OR REPLACE (Postgres 14+) so re-running against a database that somehow already has the
-- trigger is not an error. No data is touched and no privilege is granted.

CREATE OR REPLACE TRIGGER blobs_no_truncate BEFORE TRUNCATE ON blobs
  FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
