-- Envelopes module (SPEC "Migrations": envelopes owns the 0500s).
--
-- A sealed envelope is corrected by creating a new one with `supersedes_envelope_id`. The service
-- takes the old envelope's row lock before it checks that nothing already supersedes it, which is
-- enough on its own -- but "which envelope replaced this one?" is a question the evidence has to
-- answer with exactly one row, and that guarantee belongs in the schema rather than in the memory
-- of whoever reads the service next. A second superseding envelope now fails to insert.
CREATE UNIQUE INDEX envelopes_supersedes_unique
  ON envelopes (supersedes_envelope_id)
  WHERE supersedes_envelope_id IS NOT NULL;

-- The seal job runner asks for "everything due now" on every tick; without this it is a seq scan
-- over every envelope ever sealed.
CREATE INDEX seal_jobs_due
  ON seal_jobs (next_attempt_at)
  WHERE completed_at IS NULL;
