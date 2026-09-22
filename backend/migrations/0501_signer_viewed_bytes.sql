-- Envelopes tables (SPEC "Migrations": the 0500s), added by the integration owner.
--
-- `sign()` required the *session* to have been presented something, but `viewed` is a signer-level
-- status carried across sessions and the hash actually viewed lived only on the `document.viewed`
-- event. So a signer who viewed in session 1 could, after the host opened session 2, fetch the
-- document and sign in session 2 with no `document.viewed` covering the bytes that session was
-- served -- and in a parallel envelope `signer.signed.presented_sha256` could then name a revision
-- no `document.viewed` covers.
--
-- Storing the hash makes the precondition checkable: signing requires the bytes this session was
-- served to be the bytes this signer said they had read.
ALTER TABLE signers
  ADD COLUMN viewed_sha256 bytea REFERENCES blobs(sha256);

COMMENT ON COLUMN signers.viewed_sha256 IS
  'The revision this signer last confirmed they had read every page of. Written by record_viewed; '
  'sign() requires the session''s presented hash to equal it.';
