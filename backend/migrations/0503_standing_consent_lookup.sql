-- Envelopes tables (SPEC "Migrations": the 0500s), for Addendum 3 C (SPEC section 16 C).
--
-- Standing consent adds no column and no table: it is *found* in the `signers` rows that are
-- already written (SPEC section 8). What it does add is a lookup shape `signers` has never been
-- asked for -- "this host user's acceptances of this consent text, most recent first" -- on a
-- route a signer hits on every load of the signing UI. Without an index that is a sequential scan
-- of every signer row this deployment has ever created, growing for as long as the retention
-- period, on a page a patient is waiting for.
--
-- Partial, because a row with no `consented_at` can never be an answer: only a signer who has
-- actually accepted a disclosure is a candidate, and that is a small fraction of the table for as
-- long as most envelopes are in flight. `host_user_id` leads because it is the most selective
-- column and the one every query fixes; `consent_text_id` narrows to the disclosure (version and
-- locale together -- `consent_texts` is unique on the pair); `consented_at DESC` serves both the
-- span cutoff and "the most recent one".
--
-- No grant changes: no new table, and reading `signers` is what the runtime role already does.
CREATE INDEX signers_consent_by_user
  ON signers (host_user_id, consent_text_id, consented_at DESC)
  WHERE consented_at IS NOT NULL;

COMMENT ON INDEX signers_consent_by_user IS
  'Addendum 3 C: finds a standing acceptance of one disclosure by one host user, most recent '
  'first. Read by envelopes.repository.standing_consent; nothing writes through it.';
