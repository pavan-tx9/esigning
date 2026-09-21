-- Integration (SPEC "Migrations": integration owns the 0600s).
--
-- 0001 gave only `audit_events` a BEFORE TRUNCATE trigger. The other append-only tables had
-- BEFORE UPDATE OR DELETE only, so the owner role could erase them with `TRUNCATE ... CASCADE` and
-- hit nothing -- which contradicts SPEC section 2 ("the append-only triggers are the second line
-- of defence") and section 12 ("the owner role hits the trigger"). `blobs` was closed by the
-- evidence module in 0100; this closes the remaining three.
CREATE OR REPLACE TRIGGER document_revisions_no_truncate BEFORE TRUNCATE ON document_revisions
  FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
CREATE OR REPLACE TRIGGER consent_texts_no_truncate BEFORE TRUNCATE ON consent_texts
  FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
CREATE OR REPLACE TRIGGER reauth_attestations_no_truncate BEFORE TRUNCATE ON reauth_attestations
  FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
