-- Envelopes tables (SPEC "Migrations": the 0500s), added by the integration owner.
--
-- `signature_captures` is the raw signer input: the drawn PNG's content hash, or the typed text.
-- It had full DML for `esign_app` and no append-only trigger, so the one row that ties the ink a
-- patient drew to the field it was drawn for could be repointed at another blob, or deleted, by
-- anything holding the runtime role -- and nothing would notice, because `signer.signed` records
-- only `field_id` and `kind`.
--
-- Nothing in the codebase updates or deletes one: `insert_capture` is the only statement that
-- touches this table. So it gets the same two lines of defence as every other piece of evidence:
-- the grant, then the trigger that also stops the owner role.
REVOKE UPDATE, DELETE ON TABLE signature_captures FROM esign_app;

CREATE OR REPLACE TRIGGER signature_captures_append_only
  BEFORE UPDATE OR DELETE ON signature_captures
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

CREATE OR REPLACE TRIGGER signature_captures_no_truncate
  BEFORE TRUNCATE ON signature_captures
  FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
