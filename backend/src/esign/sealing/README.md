# Sealing

One seal, applied once, at the very end of an envelope. It is a **PAdES certification signature**
over the signed document plus its certificate of completion, with **DocMDP level 1 — no changes
permitted** — and an **RFC 3161 timestamp**. Everything else in this module exists to make that
one act honest.

```python
sealer = build_sealer(settings, clock)  # esign.sealing
result = sealer.seal(pdf, reason="...", envelope_id=envelope_id)
report = sealer.validate(result.sealed_pdf)  # the caller must check this before storing
```

`seal` raises `ValidationFailed` (the input is not a sealable PDF) or `SealUnavailable`
(infrastructure), and nothing else — with one deliberate exception: an `IntegrityFailure` is
re-raised rather than flattened into a retryable failure, because `contracts.py` says never to
swallow it. `validate` never raises at all.

## Two rules

**Never fail open.** If KMS, the timestamp authority or the revocation source cannot be reached,
`seal` produces nothing and raises `SealUnavailable`, so the envelope stays
`completed_pending_seal` and the job backs off. There is no branch anywhere that returns an
unsigned document, a document without a timestamp, or a document sealed at a weaker profile than
the configured one. After signing, `_confirm_seal` re-reads the output and checks the structure it
promised — exactly one signature, certified at NO_CHANGES, a timestamp present, a DSS for B-LT, a
document timestamp for B-LTA. If any of that is missing the result is discarded and
`SealUnavailable` is raised with code `seal_profile_not_achieved`. A downgrade is a failure.

**Never trust the document.** Trust roots come from `TRUST_ROOTS_PATH` and nowhere else.
Certificates embedded in a PDF are material for building a path, never a reason to believe one.
If the trust roots file is missing or empty, every document is untrusted (`trust_roots_unavailable`)
— never "trust whatever is in the file".

## Profiles

`SEAL_PROFILE` is an explicit setting with three values, and the value actually achieved comes
back in `SealResult.profile` and is recorded in the `document.sealed` audit event.

| Profile | What it adds | Where it is used |
|---|---|---|
| `PAdES-B-T` | signature + signature timestamp | explicit dev/test choice only |
| `PAdES-B-LT` | + embedded revocation info (DSS) | the production default |
| `PAdES-B-LTA`| + a document (archive) timestamp | long archival |

**Offline B-LT works.** `esign dev-pki` issues a CRL for both dev CAs, and the signing validation
context is given those CRLs directly with `revocation_mode="hard-fail"`. Hard-fail is deliberate:
if revocation information cannot be assembled, sealing fails rather than quietly emitting a file
with an empty DSS that claims to be B-LT. So B-T is never a silent fallback — it only happens
when someone sets `SEAL_PROFILE=PAdES-B-T`.

For the `aws_kms` backend there is no local CRL, so the long-term profiles fetch revocation data
from the CA's published endpoints. Unreachable endpoints raise `SealUnavailable`, which is the
point.

## Key backends

`SEAL_KEY_BACKEND=local` reads the dev PKI (`esign dev-pki`, git-ignored `.dev-pki/`): root CA ->
intermediate CA -> seal certificate, plus a timestamp-authority certificate. Private keys are
written `0600` into a `0700` directory. Regeneration refuses to overwrite an existing hierarchy
unless forced, because every document sealed with the old key would stop validating.

`SEAL_KEY_BACKEND=aws_kms` uses a key that never leaves KMS. `KmsSigner` is a pyHanko `Signer`
whose only operation is one `kms:Sign` call over the CMS signed attributes; the certificate and
chain come from `SEAL_CERT_PATH` and `SEAL_CHAIN_PATH`. RSA PKCS#1 v1.5 SHA-256 and ECDSA P-256
SHA-256 are supported; anything else is refused rather than approximated. pyHanko's dry run (used
to size the signature container) never reaches KMS, and a real signature longer than the reserved
container is refused instead of being truncated into a file that looks sealed and is not.

No private key material lives in the repository, in environment variables or in an image.

## Timestamps

`TSA_URL` names an RFC 3161 authority. When it is empty, and only when `APP_ENV` is not `prod`,
the dev PKI's TSA certificate drives an in-process authority so that tests and laptops work with
no network. In production an empty `TSA_URL` refuses to seal (`tsa_not_configured`). The
timestamper is rebuilt per attempt so that it stamps `clock.now()` rather than the time the
process started.

## What `validate` decides, and how

Each failure gets its own stable string (see `problems.py`), because "it failed" is not evidence.
The ones a reviewer will look for:

| Problem | Means |
|---|---|
| `not_signed` | no signature, including one that was stripped out |
| `byte_range_digest_mismatch` | the signed bytes were altered |
| `signature_invalid` / `signature_malformed` | the CMS does not verify, or does not decode |
| `content_appended_after_seal` | bytes exist that the seal does not account for |
| `docmdp_violation` | the document was changed in a way DocMDP level 1 forbids |
| `multiple_signatures` | more than one signature; ours is meant to be the only one |
| `not_a_certification_signature` / `certification_permits_changes` | the wrong kind of signature |
| `untrusted_chain` | the chain does not reach a configured root |
| `certificate_revoked` | a certificate in the chain was revoked; the document's own DSS says so |
| `revocation_unknown` | revocation could not be decided from what the document carries |
| `timestamp_missing` / `timestamp_invalid` | no trusted time, or one we do not believe |
| `trust_roots_unavailable` | we could not read the trust roots, so nothing is trusted |
| `coverage_undetermined` | the change analysis was inconclusive — treated as a failure |

Three points worth knowing:

*Appended content.* A B-LT or B-LTA seal legitimately carries later revisions holding the DSS and
archive timestamps, so "signature covers the whole file" is not the test. The test is that the
change analysis classifies everything after the signature as an LTA update and no further, and
that the file contains nothing past the terminator of the last revision the reader recognises.
That second check matters: concatenating a whole second PDF onto a sealed one leaves the final
`startxref` pointing into the first, so a parser-based check alone would never see the second.

*Point-in-time validation.* Retention is ten years; a signing certificate is not. The chain is
therefore checked at the moment the timestamp authority attested, not today, so a seal keeps
validating after its certificate expires. That moment is read from the document, so it is capped:
a token claiming a time beyond our own clock is rejected as `timestamp_invalid`, and the token's
own signature and TSA chain still have to validate against our trust roots.

*The signature container.* `/Contents` is the one region a signature cannot cover — it holds the
signature. Flipping a byte there breaks validation whenever the CMS depends on that byte, and is
inert when it does not (the zero padding, or a redundant embedded copy of a root we take from the
trust store anyway). That is inherent to PDF signatures, not a gap in this code.

## Known limits

- Revocation checking during `validate` reads the document's own DSS (`DocumentSecurityStore`)
  and runs `hard-fail` against it: `validate_pdf_signature` does not consult the DSS by itself, so
  the context has to be built from it. A document with no DSS is `soft-fail` when `SEAL_PROFILE` is
  `PAdES-B-T` (which carries no revocation data by design) and `revocation_unknown` when a long-term
  profile is configured. Fetching stays disabled: a validator that reaches the network answers a
  different question each time it runs, and stops answering once the endpoints are gone. What
  `validate` still cannot see is a revocation published *after* the DSS was written and never folded
  into the document -- that remains an operational control.
- `SealValidation.ok` in `contracts.py` is computed from four booleans and ignores `problems`, so
  problems with no flag of their own (a second signature, an approval signature instead of a
  certification one) are folded into `covers_whole_document`, which is what they really deny: the
  document is not locked against further change. See `_STRUCTURAL` in `sealer.py`.
