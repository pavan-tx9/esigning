-- Envelopes tables (SPEC "Migrations": the 0500s), for SPEC section 16 A.
--
-- A guardian or proxy signs "on behalf of" the envelope's `patient_ref`, and `patient_ref` is
-- required to be opaque (`contracts.is_opaque_id`, SPEC section 4) because it reaches the
-- append-only audit trail as `on_behalf_of`. That was fine while the intent confirmation was a
-- screen of its own with the document's own words around it. Addendum 3 A made the primary button
-- the single act that signs the document and the whole of the intent confirmation -- "Sign as
-- Grace Okafor, on behalf of mrn-100907" -- so the one sentence standing for a parent's intent was
-- the one sentence they could not read.
--
-- This column is the host's own words for the same person, beside the reference rather than
-- instead of it: the attribution in the record is unchanged and still opaque, and what changes is
-- only what the signing UI puts in front of the person pressing the button. It is PHI and carries
-- exactly the treatment `display_name` carries (SPEC section 10): the database and the PDF, never
-- a log line, a URL, an error message, a webhook payload or audit `data`.
--
-- The CHECK keeps it paired with `on_behalf_of`, which the schema already ties to the guardian and
-- proxy capacities: a display name for a person nobody is acting for would be a name on a row with
-- nothing to attach it to. No grant changes: no new table, and `signers` already takes INSERT and
-- UPDATE from the runtime role.
ALTER TABLE signers ADD COLUMN on_behalf_of_display text;

ALTER TABLE signers ADD CONSTRAINT signers_on_behalf_of_display
  CHECK (on_behalf_of_display IS NULL OR on_behalf_of IS NOT NULL);

COMMENT ON COLUMN signers.on_behalf_of_display IS
  'PHI: how the person on_behalf_of names is shown to the signer acting for them. Database and '
  'PDF only -- never audit data, webhooks, logs or error messages. NULL falls back to on_behalf_of.';
