# How our signatures work, and how to verify one

For the engineer, lawyer or auditor holding a disputed document. It answers four questions:

1. What evidence exists, and where does it live?
2. How do I check a document by hand, without trusting this codebase?
3. What exactly is the audit hash, byte for byte?
4. When a check fails, what does that mean?

The normative definition of the audit hash is `backend/src/esign/audit/README.md`, which
`backend/tests/audit/test_readme_vector.py` recomputes from the live code on every test run. This
document restates it and puts it in context; if the two ever disagree, that file is right and a
test is failing.

Nothing here requires you to believe our software. Every claim below can be rechecked from a
database dump, the stored files, and a general-purpose PDF reader.

---

## 1. What a signature actually is here

A signed document is not one artefact. It is five, and they corroborate each other:

| # | Evidence | Where it lives | Can it be changed? |
|---|---|---|---|
| 1 | **The sealed PDF** — the document, the signature marks, and the certificate of completion, under one PAdES certification signature with an RFC 3161 timestamp | blob store, content-addressed by its own SHA-256; S3 Object Lock in production | No. Any byte change breaks the seal |
| 2 | **Every intermediate revision** — what was presented, and what the document looked like after each signer | same blob store, one blob per revision; `document_revisions` is the index | No. Append-only table, write-once object, re-hashed on every read |
| 3 | **The audit trail** — a hash-chained event per step, per envelope | `audit_events` | No. The runtime role has `SELECT, INSERT` only; a database trigger refuses `UPDATE`, `DELETE` and `TRUNCATE` even for the owner |
| 4 | **The raw signer input** — the drawn PNG as it left the pad, or the typed text | `signature_captures` plus a blob for the image; a saved signature (§5) keeps its ink once, in `adopted_signatures`, and the capture points at that row | No. Append-only since migration `0502`; `adopted_signatures` rows are never deleted and take exactly one UPDATE, the revocation |
| 5 | **The working rows** — `envelopes`, `signers`, `signing_sessions` | ordinary tables | **Yes.** They are mutable, and that is why nothing depends on them alone |

Row 5 is the important admission. `signers.signed_at`, `capacity`, `role_key` and the rest are
updatable by the application role, because the application has to write them as it goes. So they
are treated as a *convenience copy* of facts the append-only trail already holds:

- The certificate of completion is built from the trail, not from those rows
  (`EnvelopeServiceImpl._certificate_summary`). Each signer's viewed, consented and signed times
  come from `document.viewed`, `consent.accepted` and `signer.signed`; the IP and user agent come
  from the `signer.signed` event's own request context; the authentication method and kiosk details
  come from `session.created`.
- The rows are compared against those events before anything is sealed. A disagreement raises
  `IntegrityFailure(certificate_evidence_mismatch)` and the envelope stays unsealed rather than
  being certified around a rewritten row.
- Verification re-runs the same comparison afterwards, as `envelope_row_matches_trail` and
  `signer_rows_match_trail`, for a document that was already sealed when somebody edited a row.

One subtlety worth knowing before a deposition: `signing_sessions.ip` and `user_agent` are the
**host EHR backend's**, because the host opens the session server to server. They are not the
signer's. The signer's own address and browser are in the `signer.signed` event, which is what the
certificate prints.

### What one seal at the end does and does not prove

There is exactly one cryptographic signature on the file, applied by the organisation's key after
the last signer, covering the document *and* the certificate of completion, with DocMDP level 1
("no changes permitted") and a trusted timestamp.

It is not one cryptographic signature per signer, and it is worth being able to say why. The
certificate of completion has to be inside the sealed bytes — a certificate stapled on afterwards
is a separate, unsigned file — and appending pages after a PDF signature invalidates it. So:

- **What the seal proves:** these exact bytes, including the certificate of completion listing
  every signer and every hash, existed in this form at the time the timestamp authority attested,
  were produced by the holder of this organisation's key, and have not changed by one bit since.
- **What the seal does not prove on its own:** that a particular person made a particular mark.
  That is what the audit chain, the per-signer stored revisions and the capture digests prove — and
  the seal covers a certificate that quotes the chain's length and head hash, which nails the two
  together. Break the chain and the head hash printed inside the sealed bytes stops matching.

So the honest formulation is: *the seal is evidence about the document; the chain is evidence about
the people; the certificate inside the seal binds one to the other.*

### The chain of hashes, end to end

```
template PDF  ──sha256──▶  templates.pdf_sha256, blob
      │ prepare (prefill + flatten, server-side)
      ▼
revision 1 "presented"  ──sha256──▶  envelopes.presented_sha256
                                     document_revisions(1)
                                     document.prepared.document_sha256
                                     document.presented.document_sha256  (the bytes actually served)
                                     document.viewed.document_sha256     (the bytes the signer confirmed)
      │ signer 1's marks stamped on
      ▼
revision 2 "signer_applied" ─────▶   document_revisions(2)
                                     signer.signed.presented_sha256      = what they were shown
                                     signer.signed.base_revision_sha256  = what the marks went onto
                                     signer.signed.revision_sha256       = what came out
                                     signer.signed.captures[].image_sha256 / typed_text_sha256
      │ … one more revision per signer …
      ▼
revision N "final_unsealed"  ────▶   certificate of completion appended
                                     document.finalized.document_sha256
                                     document.finalized.audit_head_hash  ← the chain, quoted
      │ PAdES seal, DocMDP 1, RFC 3161 timestamp, KMS key
      ▼
revision N+1 "sealed"  ──────────▶   envelopes.sealed_sha256
                                     document.sealed.document_sha256
                                     document.sealed.signer_cert_sha256
```

For a host-supplied document (Addendum 2, section 6) the first two rows of that diagram are the
only thing that differs — everything from revision 2 down is identical:

```
host's upload  ──sha256──▶  blob (kind supplied_pdf)
                            document.supplied.upload_sha256
      │ flatten_supplied (every widget and annotation removed, nothing drawn, nothing added)
      ▼
revision 1 "supplied"  ───▶  envelopes.presented_sha256
                             document_revisions(1), kind 'supplied', page_count
                             blob (kind presented_pdf)
                             document.supplied.document_sha256 = .presented_sha256
                             document.presented / document.viewed, exactly as above
```

There is no template and no `document.prepared`; `document.supplied` is the event that says which
bytes revision 1 is, and it carries *both* ends of the transformation so that "we showed the signer
what you sent us" is checkable rather than asserted.

`signer.signed` records all three hashes deliberately. In a parallel envelope another signer may
move the document between the moment this one read it and the moment they sign, and that has to be
visible rather than smoothed over — which is also why signing is refused (`409 not_viewed`) when
the bytes a session was served are no longer the current revision. The signature never lands on a
revision nobody showed the signer.

---

## 2. Verifying a document

### The fast way: the CLI

```sh
cd backend && uv run esign verify <envelope id>
```

Exit status 0 means nothing that was checked failed; 1 means something did. `--json` prints the
whole report for a script. The same report is available over the Host API at
`GET /v1/envelopes/{id}/verification`, which is always HTTP 200 for an envelope that exists — a
failed verification is a finding, not a transport error.

A real run on a sealed envelope:

```
envelope 280ee839-293b-4a3b-b7c1-162b72bf4742: sealed
  PASSED  revision_numbers_gapless
  PASSED  revision_1_presented_hash  9edfa99718c7fa4c4485d0783c7ad0f3d371507ff8ac36a34e114008602feb32
  PASSED  revision_2_signer_applied_hash  cf3629c7fa49364031748caeda77449c759ef526dbd6eeb187d64558122132a7
  PASSED  revision_3_final_unsealed_hash  279b42584eedaa3bbb11035da78c73492e597f280ec7c881024f35af895a527d
  PASSED  revision_4_sealed_hash  3e5acf26ee8af13a13c107a44a63edaaf3d14053cec67df520db964c3f425c9b
  PASSED  envelope_presented_pointer
  PASSED  envelope_current_revision_pointer
  PASSED  envelope_sealed_pointer
  PASSED  audit_chain  13 events
  PASSED  trail_presented_hash
  PASSED  trail_signed_revision_hashes
  PASSED  trail_sealed_hash
  PASSED  trail_final_unsealed_hash
  PASSED  envelope_row_matches_trail
  PASSED  signer_rows_match_trail
  PASSED  capture_images_intact
  PASSED  captures_match_trail
  PASSED  sealed_pages_match_final_revision
  PASSED  seal_intact
  PASSED  seal_covers_whole_document
  PASSED  seal_trusted
  PASSED  seal_timestamp_valid
  PASSED  seal_no_problems
  PASSED  seal_matches_record
  PASSED  seal_bound_to_envelope
  PASSED  certificate_head_hash
  PASSED  certificate_head_hash_in_document
audit trail: 13 events
RESULT: verified. The seal, every stored hash and the audit chain all check out.
```

Running it appends `verification.performed` to the trail, recording what was found. The trail
therefore also says who checked and when, which is why the event count above is 13 and the next run
will say 14.

Three outcomes, and they are different:

- **`verified`** — `ok` and `complete`: sealed, every check ran, none failed.
- **`consistent so far, but NOT complete`** — `ok` but not sealed. Everything that could be checked
  holds; the seal checks were skipped because there is no seal yet. This is not a signed document.
- **`FAILED`** — at least one check failed. Read the named checks in section 4.

A check that could not be run is reported `skipped`, never silently passed.

### The slow way: by hand, trusting nothing

Six things to check for any document, and two more for the evidence Addendum 1 added — a paper
archive's attestation (g) and a saved signature (h). Everything you need is a database dump, the
blob files and Python.

#### (a) The sealed file is the file the record names

Blobs are content-addressed: a digest `abcdef…` lives at `<prefix>/ab/cd/abcdef…` under
`BLOB_FS_ROOT` or the S3 prefix. So the filename *is* the claimed hash.

```sh
psql -c "SELECT encode(sealed_sha256,'hex') FROM envelopes WHERE id = '<envelope id>'"
#  3e5acf26ee8af13a13c107a44a63edaaf3d14053cec67df520db964c3f425c9b

shasum -a 256 .blobstore/3e/5a/3e5acf26ee8af13a13c107a44a63edaaf3d14053cec67df520db964c3f425c9b
#  3e5acf26ee8af13a13c107a44a63edaaf3d14053cec67df520db964c3f425c9b  …
```

The same digest appears in `document.sealed.document_sha256`, in the `envelope.sealed` webhook
payload the EHR received, and in the EHR's own record of what it filed. Four independent places.

#### (b) The seal covers the bytes, and nothing was added

Read the signature's `/ByteRange` yourself. It is two spans: everything before the signature
container and everything after it.

```python
import re, hashlib
data = open("…/3e5acf26…", "rb").read()
a, b, c, d = (int(x) for x in re.search(
    rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", data).groups())
print(a, b, c, d, "file size:", len(data))
# 0 261073 282417 760   file size: 289089
signed = data[a:a + b] + data[c:c + d]
print(hashlib.sha256(signed).hexdigest())
```

The gap between `a+b` and `c` is the `/Contents` string holding the CMS signature — the one region
a signature cannot cover, because it holds the signature. That is inherent to PDF signatures.

`c + d` will usually be **less** than the file size, and that is expected for a `PAdES-B-LT` or
`-B-LTA` seal: the document security store (the embedded revocation data) and any archive timestamp
are written as later incremental updates. What must be true is that everything after the signed
span is *only* that. Our validator establishes it by classifying the change as an LTA update and
checking that nothing exists past the terminator of the last revision the reader recognises — which
matters, because concatenating a whole second PDF onto a sealed one leaves the final `startxref`
pointing into the first, and a parser-based check alone would never see the second file.

#### (c) The seal is bound to this envelope

```python
print(re.search(rb"/Location\s*\((.*?)\)", data).group(1))
# b'envelope\\072280ee839\\055293b\\0554a3b\\055b7c1\\055162b72bf4742'
```

PDF string literals octal-escape punctuation: `\072` is `:` and `\055` is `-`. Decoded, that reads
`envelope:280ee839-293b-4a3b-b7c1-162b72bf4742`. If it names a different envelope, this sealed PDF
is not the one the record is talking about, however intact its signature is. Verification reports
this as `seal_bound_to_envelope`.

#### (d) The certificate of completion agrees with the trail

Open the sealed PDF and read the last pages. Under "Audit trail" it prints the number of events and
the head hash *at the moment it was written*, and both are inside the seal. Compare:

```sh
# what the certificate printed, taken from the event that recorded writing it
psql -At -c "SELECT data->>'audit_event_count', data->>'audit_head_hash'
             FROM audit_events
             WHERE stream_type='envelope' AND stream_id='<envelope id>'
               AND event_type='document.finalized'"

# and what that event number hashes to now
psql -At -c "SELECT encode(event_hash,'hex') FROM audit_events
             WHERE stream_type='envelope' AND stream_id='<envelope id>'
               AND sequence = <the count above>"
```

The trail will have grown since — every download and every verification adds an event — but the
first *N* events must still be there and event *N* must still hash to the printed value. That is
exactly what the `certificate_head_hash` check does, and `certificate_head_hash_in_document`
confirms the value is really printed on a page inside the seal rather than merely recorded.

Also on those pages, for every signer: name, role, capacity, signer id, authentication method,
re-authentication, consent version, the viewed/consented/signed times in UTC, IP, user agent, and
any kiosk staff member and identity check. That page is designed to stand alone in front of a
reader who has none of this infrastructure.

Two of those lines say more than they used to, and both are Addendum 1 (section 5):

- **Re-authentication** is "not required", or the method with *when and for what*. A real one:
  `password, at 2026-09-22 08:00:10 UTC for this document` — or, when the confirmation was borrowed
  from an earlier document in the same signing queue, `password, at 2026-09-22 08:00:10 UTC in an
  earlier session, 5 seconds before signing`. The second wording is the weakening stated on the
  page a court reads, in words, rather than left in a configuration file.
- **Saved signature** appears only when the mark was one the signer had saved earlier: `signed with
  a saved signature adopted on 2026-09-22`.

A paper archive's certificate has no signer table at all. In its place it prints the attestation —
who attested, their staff id, the statement, what became of the original, and the paper signers by
name and capacity — plus the sentence about what the seal proves (see (g)).

#### (e) Re-verify the audit chain from the dump

This script imports nothing from our codebase. It rebuilds the canonical JSON from the stored
columns using the rules in section 3, hashes it, and walks the chain.

```python
import hashlib, json, sys, psycopg

COLUMNS = (
    "id, stream_type, stream_id, sequence, event_type, actor_user_id, actor_role, actor_capacity, "
    "on_behalf_of, auth_method, session_id, host(ip) AS ip, user_agent, "
    "encode(document_sha256, 'hex') AS document_sha256, "
    "to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS occurred_at, "
    "encode(prev_event_hash, 'hex') AS prev_event_hash, "
    "data, encode(event_hash, 'hex') AS event_hash"
)

def canonical(value):
    if isinstance(value, dict):
        return "{" + ",".join(f"{json.dumps(k, ensure_ascii=False)}:{canonical(v)}"
                              for k, v in sorted(value.items())) + "}"
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return json.dumps(value, ensure_ascii=False)

dsn, envelope_id = sys.argv[1], sys.argv[2]
with psycopg.connect(dsn, row_factory=psycopg.rows.dict_row) as conn:
    rows = conn.execute(
        f"SELECT {COLUMNS} FROM audit_events "
        "WHERE stream_type = 'envelope' AND stream_id = %s ORDER BY sequence",
        (envelope_id,)).fetchall()

previous, problems = "0" * 64, []
for index, row in enumerate(rows, start=1):
    event_hash = row.pop("event_hash")
    for key in ("id", "stream_id", "session_id"):
        row[key] = None if row[key] is None else str(row[key])
    computed = hashlib.sha256(canonical(row).encode("utf-8")).hexdigest()
    if row["sequence"] != index:            problems.append(f"sequence gap at {row['sequence']}")
    if row["prev_event_hash"] != previous:  problems.append(f"wrong prev_event_hash at {row['sequence']}")
    if computed != event_hash:              problems.append(f"hash mismatch at {row['sequence']}")
    previous = event_hash
    print(f"{row['sequence']:>3}  {row['event_type']:<24} {computed}"
          f"  {'ok' if computed == event_hash else 'MISMATCH'}")
print(f"\n{len(rows)} events, head {previous}")
print("problems:", problems or "none")
```

```
  1  envelope.created         add2de15011a9e67edc36e9ecd067f3cd4d2c40b4313a1511c6ac21c325ec9ed  ok
  2  document.prepared        c80646d2ae6aa5b74d418e0450419157df230cbad35b2bfceec24d467af960f6  ok
  …
 14  verification.performed   6d523695b4e07dffff4d64b25130a9a1d732e9084c4486d8754be92a049dfa35  ok

14 events, head 6d523695b4e07dffff4d64b25130a9a1d732e9084c4486d8754be92a049dfa35
problems: none
```

Note `host(ip)`: Postgres stores the address as `inet` and renders it `198.51.100.24/32` by
default, which is not what was hashed. `host()` gives back the plain address.

#### (f) And open it in Adobe Acrobat

The independent check that matters to a non-engineer, and the one the developer guide asks for
explicitly. Acrobat's signature panel should show one certification signature, "no changes
permitted", and a trusted timestamp. With a certificate issued under the organisation's own CA it
will report the signature as *valid but of unknown validity* unless that CA is in Acrobat's trust
list — that is a purchasing decision (see `docs/RUNBOOK.md`), not a defect in the document. What
Acrobat must never show is a signature that fails: if it does, and `esign verify` passes, believe
Acrobat and escalate.

#### (g) A paper archive: checking the attestation

A paper archive (section 5) is verified by exactly the procedure above — the seal, the pointers,
the chain — with one difference in what the evidence *is*. Revision 1 is the scan rather than a
rendered template, and the two facts a reader cares about are "this is the scan that was filed" and
"this is who said it was a true copy". A real run:

```
$ uv --directory backend run esign verify d46a3548-f58d-485e-b9e4-a0fef192ef5e
envelope d46a3548-f58d-485e-b9e4-a0fef192ef5e: sealed
  PASSED  revision_numbers_gapless
  PASSED  revision_1_scan_hash  a3a74b6443ae260bf5663136d66d3782d6fec39520d3e00a6304dd1f0aee8240
  PASSED  revision_2_final_unsealed_hash  028df7a5a0d39111fe5052c1678f19f98bccfa41e6c667c0fc84b467c28e8db5
  PASSED  revision_3_sealed_hash  fa92d74f4f165f4132a06451e65174643699f69a0d8c7a16d3f645204c30a3ea
  PASSED  envelope_row_matches_trail
  PASSED  sealed_pages_match_final_revision
  PASSED  certificate_head_hash_in_document
  …
audit trail: 5 events
RESULT: verified. The seal, every stored hash and the audit chain all check out.
```

There are no signers, so `signer_rows_match_trail` and `reauth_attestations_match_trail` pass with
nothing to compare, and `capture_images_intact` reports "no drawn or typed signature was captured".
The check that carries the weight here is `sealed_pages_match_final_revision`: it compares the
pages inside the seal against the stored scan, **one page in**, because the cover page precedes it.
A scan swapped inside the sealed bytes is caught there; a scan swapped in the blob store is caught
by `revision_1_scan_hash`.

By hand, the attestation is two records that have to agree, plus a page you can read:

```sh
# what the mutable envelope row says
psql -At -c "SELECT jsonb_pretty(attestation) FROM envelopes WHERE id = '<envelope id>'"
# {"statement": "true_copy", "paper_signers": [{"capacity": "self", "display_name": "Maria Alvarez"}],
#  "staff_user_id": "staff-3310", "staff_display_name": "Alice Wu", "original_disposition": "retained"}

# what the append-only trail recorded at the moment of filing
psql -At -c "SELECT jsonb_pretty(data) FROM audit_events
             WHERE stream_type='envelope' AND stream_id='<envelope id>'
               AND event_type='archive.attested'"
# {"statement": "true_copy", "staff_user_id": "staff-3310",
#  "paper_signer_count": 1, "original_disposition": "retained",
#  "attested_detail_sha256": "5c2e…"}
```

The trail holds the opaque staff id, the statement, the disposition and a *count* — the names
themselves are PHI, and they live in the row and inside the sealed PDF, nowhere else. But names a
trail cannot contradict are not evidence, and for an archive they are the whole attribution: there
is no signer row, no session and no stamped revision behind them. So the trail also holds
`attested_detail_sha256`, one SHA-256 over the canonical JSON of the attesting staff member's
display name, the ordered paper signers and the paper signing date:

```sh
python - <<'PY'
import hashlib, json
detail = {
    "staff_display_name": "Alice Wu",
    "paper_signers": [{"display_name": "Maria Alvarez", "capacity": "self"}],
    "paper_signed_on": "2026-03-10",
}
print(hashlib.sha256(json.dumps(detail, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=False).encode()).hexdigest())
PY
```

Read `staff_display_name`, `paper_signers` and `paper_signed_on` out of the row (the last from the
`envelopes.paper_signed_on` column, as `YYYY-MM-DD`), recompute, and it must equal what
`archive.attested` recorded. One *joint* digest rather than one per field on purpose: a SHA-256 of
a bare date is brute-forceable in seconds, and publishing one would put a date-shaped value about a
patient back in the trail — joint, the preimage is a name plus an ordered list plus a date.

Verification compares all of it as `envelope_row_matches_trail`, and the seal refuses
(`certificate_evidence_mismatch`) before printing names that disagree, so an edited `attestation`
column or an edited `paper_signed_on` is a finding rather than a new truth. `archive.created`
carries the scan's hash, size and page count, and its `occurred_at` is the filing time the cover
page and the certificate print.

Then read page 1 of the sealed PDF. It is inside the seal, so it cannot have been changed after the
fact, and it says in plain words what this document is worth:

> The seal on this document proves that this scan has not changed since it was filed, and who filed
> and attested to it. It does not prove that the signature on the paper is genuine: that rests on
> the paper original and on the person who attested to this copy.

**The honest formulation for an archive:** the seal and the chain are evidence about the *scan and
the filing*; the ink is evidence about the signing, and it lives on paper. Where the original was
destroyed under a retention policy (`original_disposition`), this attestation is what remains of
it — which is why who attested, and when, is on the cover page, on the certificate, and in the
trail as an actor with the `staff` role.

#### (h) A saved signature: follow the pointer

A capture of kind `adopted` (section 5) holds no ink of its own. It names the `adopted_signatures`
row whose image or text was stamped, and the numbers still have to add up:

```sh
# the capture, and the row it points at
psql -At -F ' | ' -c "SELECT c.field_id, c.kind, c.adopted_signature_id
                      FROM signature_captures c JOIN signers s ON s.id = c.signer_id
                      WHERE s.envelope_id = '<envelope id>'"
# clinician_signature | adopted | aae3234d-a5ee-46ce-abd9-d4f35a87b4c1

psql -At -F ' | ' -c "SELECT kind, encode(sha256(convert_to(typed_text,'UTF8')),'hex'),
                             created_by_session_id, created_in_envelope_id, created_at, revoked_at
                      FROM adopted_signatures WHERE id = 'aae3234d-a5ee-46ce-abd9-d4f35a87b4c1'"
# typed | e2935ea1e1d93a150b2f1ef8b48a757a5ba9f8afe21bd628d3edb40f643f2426 | fec905f9-… | 1ed8d217-… | 2026-09-22 08:00:10+00 |
```

Three comparisons turn that mark into evidence rather than an assertion:

1. **The trail of the signature that used it.** `signer.signed.captures[]` for that field records
   `{"kind": "adopted", "image_sha256": null, "typed_text_sha256": "e2935ea1…"}` — the digest of
   what was actually stamped. It must equal the digest of the row above. Verification does this as
   `captures_match_trail`, following the pointer; for a drawn signature `capture_images_intact`
   also re-reads the stored PNG and re-hashes it.
2. **The trail of the adoption.** `signature.adopted`, on the envelope stream of the session the
   signature was *created* in, carries the same id and the same digest:

   ```sh
   psql -At -F ' | ' -c "SELECT stream_id, sequence, data->>'typed_text_sha256'
                         FROM audit_events WHERE event_type='signature.adopted'
                           AND data->>'adopted_signature_id' = 'aae3234d-a5ee-46ce-abd9-d4f35a87b4c1'"
   # 1ed8d217-ce9a-44d2-9d4c-1a8911e519c8 | 10 | e2935ea1e1d93a150b2f1ef8b48a757a5ba9f8afe21bd628d3edb40f643f2426
   ```

   That stream is a different envelope — the document this person was signing when they saved it —
   and it is hash-chained in the same way. `created_by_session_id` names the session, which
   `session.created` in that stream dates and attributes.
3. **The certificate.** The sealed certificate of completion prints, under that signer: "Saved
   signature — signed with a saved signature adopted on 2026-09-22". A reader holding only the PDF
   knows the mark was not drawn in this session, and knows when it was.

What a saved signature does **not** weaken: the signer still reviewed this document, consented in
this session, applied the signature to each field by an explicit action, and confirmed intent
before it was sent. What it does mean is that the ink was captured once, earlier, by that same
person in their own authenticated session — never by staff, never on a kiosk, and never through a
host API, because none exists.

A revoked row still verifies. Revocation stops the signature being *offered*; `revoked_at` and
`revoke_reason` (`replaced`, `user`, `host`) say when and at whose request,
`signature.adoption_revoked` on the `system` stream for that host records the same, and the row is
never deleted — precisely so that the documents already signed with it stay checkable.

---

## 3. The audit hash, exactly

One chain per stream. The usual stream is `envelope`; there are also `template` and `system`
streams. `sequence` starts at 1 and has no gaps. The first event's `prev_event_hash` is 32 zero
bytes. Every later event's `prev_event_hash` is the previous event's `event_hash`.

```
event_hash = SHA-256( canonical_json( the event without event_hash ) )
```

Writers serialise per stream with `pg_advisory_xact_lock` on a hash of `(stream_type, stream_id)`,
read the head, then insert, all inside the caller's transaction — so two concurrent writers cannot
produce the same sequence number or skip one. `occurred_at` comes from the server's `Clock`, never
from a client, and an append whose timestamp is earlier than the head of its stream is **refused**
(`IntegrityFailure`, `audit_clock_regression`) rather than written or clamped: the trail is
append-only, so an out-of-order event could never be corrected.

### The hashed fields

Exactly these seventeen — the `audit_events` column list minus `event_hash` itself, so every stored
column is covered and a change to any one of them breaks the hash.

| Field | Source | Canonical form |
|---|---|---|
| `actor_capacity` | server | `self`, `guardian`, `proxy`, `witness`, `interpreter`, `clinician`, or `null` |
| `actor_role` | server | `patient`, `clinician`, `staff`, `host`, `system`, or `null` |
| `actor_user_id` | host, via the API key | opaque id string (no whitespace), or `null` |
| `auth_method` | server | lowercase token, e.g. `portal_otp`, `api_key`, or `null` |
| `data` | server, validated per event type | JSON object, keys sorted, same rules recursively |
| `document_sha256` | server | 64 lowercase hex characters, or `null` |
| `event_type` | server | the event type, e.g. `signer.signed` |
| `id` | server | lowercase UUID string |
| `ip` | request, honouring `TRUSTED_PROXY_CIDRS` | the address as Postgres stores it, or `null` |
| `occurred_at` | `Clock` | RFC 3339 UTC, exactly six fractional digits, `Z` |
| `on_behalf_of` | host | opaque id string, or `null` |
| `prev_event_hash` | chain | 64 lowercase hex characters |
| `sequence` | chain | integer |
| `session_id` | server | lowercase UUID string, or `null` |
| `stream_id` | server | lowercase UUID string |
| `stream_type` | server | `envelope`, `template` or `system` |
| `user_agent` | request header | string, truncated to 512 characters before hashing, or `null` |

### Canonical JSON

1. Objects are written with their keys sorted by UTF-8 code point, recursively.
2. No insignificant whitespace: `{"a":1,"b":2}`, never `{"a": 1, "b": 2}`.
3. The output is UTF-8. Non-ASCII characters are written literally, not `\uXXXX`-escaped.
4. `bytes` are lowercase hex. A SHA-256 digest is 64 hex characters.
5. UUIDs are their lowercase canonical string.
6. Timestamps are RFC 3339 in UTC with exactly six fractional digits and a `Z` suffix:
   `2026-03-17T14:31:02.481073Z`. A naive timestamp is an error, not an assumption.
7. Absent values are `null`. A field is never simply left out.
8. Floats are rejected. No evidence field is a float, and their text form is not portable.

### What may appear in `data`

Ids, enums, hashes, versions, counts, error codes and server-recorded timestamps. Nothing else.
Every event type has a closed Pydantic model in `esign/audit/events.py` (`EVENT_DATA_MODELS`) with
`extra="forbid"` and strict types, and every string field is a constrained pattern — so a
32-character name cannot validate as a 32-byte digest, and `OpaqueId` forbids whitespace, which is
what stops a display name being passed where a host user id belongs. There is exactly one
definition of this allowlist; the envelope module's tests validate through it, so the two cannot
drift.

A rejected append names the field and the rule, never the value:

```
audit data rejected for signer.declined: note (extra_forbidden)
```

**This is why a signer's name is not in the trail.** It is not an oversight: there is no field for
it. The name lives in the `signers` table and on the certificate of completion inside the sealed
PDF, which is where PHI belongs.

### Worked example

A `signer.signed` event, the seventh on its stream. These are the stored column values:

| Column | Value |
|---|---|
| `id` | `0f2c9a44-1d3b-4e57-8a66-b1c2d3e4f5a6` |
| `stream_type` | `envelope` |
| `stream_id` | `1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9` |
| `sequence` | `7` |
| `event_type` | `signer.signed` |
| `actor_user_id` | `host-user-1187` |
| `actor_role` | `patient` |
| `actor_capacity` | `self` |
| `on_behalf_of` | `NULL` |
| `auth_method` | `portal_otp` |
| `session_id` | `b4d5e6f7-8a9b-4c0d-9e1f-2a3b4c5d6e7f` |
| `ip` | `198.51.100.24` |
| `user_agent` | `Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X)` |
| `document_sha256` | `\x9a8b7c6d5e4f30211203f4e5d6c7b8a9f0e1d2c3b4a59687786950413223145f` |
| `occurred_at` | `2026-03-17 14:31:02.481073+00` |
| `prev_event_hash` | `\x5d41402abc4b2a76b9719d911017c592a1b2c3d4e5f60718293a4b5c6d7e8f90` |
| `data` | the object inside the JSON below |

The canonical JSON is **1263 bytes on one line** (wrapped here only for the page; there is no
whitespace in the real thing):

```json
{"actor_capacity":"self","actor_role":"patient","actor_user_id":"host-user-1187","auth_method":"portal_otp","data":{"base_revision_sha256":"3b1f8c2d4e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e","capacity":"self","capture_count":1,"captures":[{"field_id":"patient_sig","image_sha256":"c1d2e3f405162738495a6b7c8d9eaf0112233445566778899aabbccddeeff001","kind":"drawn","typed_text_sha256":null}],"consent_version":"2026-09","presented_sha256":"3b1f8c2d4e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e","reauth_method":null,"reauth_used":false,"revision_no":2,"revision_sha256":"9a8b7c6d5e4f30211203f4e5d6c7b8a9f0e1d2c3b4a59687786950413223145f","role_key":"patient","signer_id":"7c3f1d2e-5a64-4b8f-9c10-2e4a6b8d0f31"},"document_sha256":"9a8b7c6d5e4f30211203f4e5d6c7b8a9f0e1d2c3b4a59687786950413223145f","event_type":"signer.signed","id":"0f2c9a44-1d3b-4e57-8a66-b1c2d3e4f5a6","ip":"198.51.100.24","occurred_at":"2026-03-17T14:31:02.481073Z","on_behalf_of":null,"prev_event_hash":"5d41402abc4b2a76b9719d911017c592a1b2c3d4e5f60718293a4b5c6d7e8f90","sequence":7,"session_id":"b4d5e6f7-8a9b-4c0d-9e1f-2a3b4c5d6e7f","stream_id":"1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9","stream_type":"envelope","user_agent":"Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X)"}
```

SHA-256 of those bytes:

```
a9dbdc657ce901145f97860f9258ec2de28d39f280d508fba2b425fb1c2eb90e
```

which is what `audit_events.event_hash` holds for this row, and what the eighth event's
`prev_event_hash` must be. Reproduce it with `printf '%s' '<the JSON above>' | shasum -a 256`.

### The events, and what each one is evidence of

| Event | Evidence for |
|---|---|
| `envelope.created` | which template version, which document type, how many signers, when the clock says it started |
| `document.prepared` | the hash of the exact bytes the server rendered, and how many prefill fields went in (a count, never the values) |
| `document.supplied` | Addendum 2, and a host document's `document.prepared`: the hash of the upload the host sent (`upload_sha256`), the hash of the flattened bytes revision 1 became (`presented_sha256`, which is also the event's own `document_sha256`), the `page_count` persisted on the revision, whether the fields came from the PDF's widget names or the request's rects (`field_source`), the digest of the signer roles the envelope was created with (`signer_roles_sha256`), and the host's opaque `host_document_ref`. No prefill exists on this path, and nothing from inside the file — not a widget name, not a field value — appears anywhere in it |
| `session.created` | the host's attestation: how and when this person authenticated, and the kiosk context |
| `session.rejected` | a refused attempt to open a session. Committed separately, because the refused request is rolled back and the refusal is still evidence |
| `document.presented` | the hash of the bytes actually served to this session |
| `document.viewed` | the signer confirmed every page, and against which bytes |
| `consent.accepted` | which disclosure, which version, which locale, and the hash of its body — and, where the agreement was given for an earlier document of the same sitting (Addendum 3 C), which envelope it stood on (`relied_on_envelope_id`), when that acceptance was given (`relied_on_accepted_at`) and when the disclosure was last actually *displayed* (`relied_on_root_accepted_at`, carried forward unchanged through a chain, and what the span is measured from). All three are null together on an envelope that collected its own consent |
| `auth.reauthenticated` | the host attested a fresh re-authentication for this session |
| `signer.signed` | the whole act: what they were shown, what the marks went onto, what came out, how each field was filled, the digest of the ink, the consent version, whether re-authentication was used and by what method — and, since Addendum 1, *which* attestation covered it (`reauth_attestation_id`), whether that attestation was made in this session or borrowed (`reauth_scope`), how old it was (`reauth_age_seconds`), and the saved signature applied, if any (`adopted_signature_id`) |
| `signer.declined` / `envelope.declined` | the refusal and its reason code |
| `envelope.completed` | the last signature landed |
| `document.finalized` | the certificate of completion was appended, over this many events ending in this head hash |
| `document.sealed` | the profile achieved, the key backend, the signing certificate's fingerprint, the timestamp authority's time |
| `document.stored` | the sealed bytes went to write-once storage with this retain-until |
| `document.downloaded` | somebody took a copy — the signer or the host |
| `seal.failed` | an attempt failed, with the error code, which attempt it was, and when the next one is due |
| `envelope.voided` / `expired` / `superseded` | how the envelope ended, or what replaced it |
| `verification.performed` | somebody checked, and what they found |
| `archive.created` | a scan of a paper-signed document was filed: which host, which document type, how many pages, how many bytes, the scan's hash — and `occurred_at` is the filing time the cover page prints |
| `archive.attested` | who said it is a true copy: the staff member by opaque id, as the actor and in the data, the statement, what became of the original, and how many people signed the paper. Never a name |
| `signature.adopted` | a signer saved the signature they had just applied: which row, of what kind, and the digest of the image or the typed text. On the envelope stream of the session that created it, after the `signer.signed` it came from and in the same transaction — with `envelope.completed` between the two when that signature was the last one |
| `signature.adoption_revoked` | a saved signature stopped being offered: which row, whose, and why (`replaced`, `user`, `host`). On the **`system`** stream, one chain per host, because a saved signature outlives any one envelope |

---

## 4. What each verification failure means

### Chain and storage

| Check | Failing means |
|---|---|
| `audit_chain` | The chain does not verify. Sub-problems name the row: `sequence gap after 4` (an event is missing), `wrong prev_event_hash at 7` (the chain was re-linked), `hash mismatch at 7` (a column was edited), `non-monotonic occurred_at at 9` (a timestamp was moved backwards), `data keys do not match signer.signed at 7`, `unknown event_type at 11`. All but the last two require database-level access the application role does not have. **`data keys do not match <type>` has a second, innocent cause**: an event's `data` key set is compared against the model *this build* declares, so events written before a release that added a field to that type report it for ever after, with every hash still intact. Addendum 1 did exactly that to `signer.signed` (`reauth_attestation_id`, `reauth_scope`, `reauth_age_seconds`, `adopted_signature_id`), so documents signed before migration `0700` verify `FAILED` on this line and on `reauth_attestations_match_trail` while every stored hash, the seal and `certificate_head_hash` still pass. Addendum 3 did the same to `consent.accepted` (`relied_on_envelope_id`, `relied_on_accepted_at`, `relied_on_root_accepted_at`), so an envelope consented to before that release reports `data keys do not match consent.accepted at N` for ever, whether or not the consent span was ever switched on. Tampering moves a hash; a release does not — `docs/RUNBOOK.md` §6.5 has the triage |
| `revision_numbers_gapless` | `document_revisions` is not `1..n`. A revision row was removed, which needs owner access |
| `revision_N_<kind>_hash` | A stored revision is unreadable, or its bytes no longer hash to what the row claims (`blob_corrupt`), or the row exists and the object is gone (`blob_missing`). This is data loss or tampering in the object store |
| `envelope_presented_pointer` / `envelope_current_revision_pointer` / `envelope_sealed_pointer` | The `envelopes` row points at different bytes than the revision table holds. The row was edited |
| `no_sealed_document_before_sealing` | A sealed revision exists for an envelope that is not sealed |
| `trail_presented_hash` / `trail_signed_revision_hashes` / `trail_sealed_hash` / `trail_final_unsealed_hash` | The hashes the trail recorded are not the hashes of the stored revisions. Either the blobs were swapped or the trail was rewritten — and the trail has a hash chain to say which |
| `capture_images_intact` | A stored drawn-signature image is missing or no longer hashes to its digest |
| `captures_match_trail` | The capture `signer.signed` recorded is gone, or the row now points at a different image. The ink was swapped after the fact. An `adopted` capture (a saved signature, Addendum 1 B) keeps no ink of its own and points at the `adopted_signatures` row; the check follows that pointer, so the saved image is re-hashed and compared too |
| `reauth_attestations_match_trail` | A signature that says it rested on a re-authentication names an attestation row that is missing, made for another user or host, made in a different session than `reauth_scope` claims, or whose method or `auth_time` (to within five seconds of `occurred_at - reauth_age_seconds`) is not what `signer.signed` recorded (Addendum 1 C) |
| `consent_relied_on_matches_trail` | A `consent.accepted` that rested on an earlier acceptance (Addendum 3 C) cannot be corroborated from the envelope it names: that envelope is not in the database, or belongs to another host; its own hash-chained trail holds no acceptance of the same disclosure (`consent_text_id`), by the same person, at the time this event claims; the display time carried forward is not the one that earlier acceptance carried, or is after the acceptance itself; the notice it stands on was displayed more than `CONSENT_SPAN_MAX_SECONDS` (one hour) before this acceptance — a bound the code cannot exceed, so a longer chain describes something this service never produced; or the acceptance it leans on came from a kiosk session, where standing consent is never available in either direction. An envelope that collected its own consent **passes** this check rather than skipping it |
| `envelope_row_matches_trail` | `created_at`, `document_type`, `template_version_id`, template key or version differ from what `envelope.created` recorded. For a paper archive the same check runs against `archive.created` and `archive.attested`: the filing and attestation times, the document type, and the `attestation` column's staff id, statement, disposition and paper-signer count (the scan's own hash is covered by `revision_1_scan_hash` and `trail_presented_hash`). That column is an ordinary jsonb column the application can update, so it is compared exactly as a signer row is. For a host document (Addendum 2) the comparison is against `envelope.created` and `document.supplied`: `template_version_id`, `template_key` and `template_version` must all be absent, `host_document_ref` must be the one recorded, and the SHA-256 of `envelopes.field_definitions['signer_roles']` must equal `document.supplied.signer_roles_sha256` — that column is UPDATE-able and holds the `requires_reauth` flags the certificate prints, so the digest is what stands in for a template version's immutability |
| `signer_rows_match_trail` | A `signers` row disagrees with the trail: a timestamp more than 60 seconds from the event that recorded it, a status that does not match whether `signer.signed` exists, a rewritten `role_key`, `capacity`, `on_behalf_of` or `consent_text_id`, or no `document.viewed` covering the revision the signature was built on |
| `supplied_document_recorded` | (Addendum 2, host documents only.) The envelope's stream does not hold exactly one `document.supplied` event. Either it was never written — which cannot happen through the application, since it is appended in the same transaction as the envelope row — or the stream holds two, which means two creations were recorded against one envelope. Nothing else in the report can be trusted about where this document came from until this passes |
| `supplied_upload_intact` | The upload named by `document.supplied.upload_sha256` cannot be produced from storage: `blob_missing` (the object is gone) or `integrity_failure`/`blob_corrupt` (the stored bytes no longer hash to the name they are filed under — a swapped upload). The half of the evidence that says *what the host sent us* is what is damaged; revision 1, what the signer actually saw, is covered separately by `supplied_revision_matches_trail` and `revision_1_supplied_hash`. The check also reports the blob's `kind` as text and does not assert it: `blobs` is content-addressed and global, so the same bytes stored earlier as a `template_pdf` keep that kind for ever, legitimately |
| `supplied_revision_matches_trail` | The presented hash does not agree across the four places it is written: `document.supplied`'s own `data.presented_sha256`, the event row's `document_sha256`, the stored `supplied` revision, and `envelopes.presented_sha256`. The detail names which pair disagrees. A swapped revision cannot agree with all four, so this is where it shows |

### The seal

| Problem | Meaning |
|---|---|
| `not_signed` | No signature at all, including one that was stripped out |
| `malformed_pdf` / `encrypted_pdf` | Not a readable PDF, or encrypted — the seal covers cleartext bytes and nothing else |
| `byte_range_digest_mismatch` | The signed bytes were altered. **This is the one-byte-change case** |
| `signature_invalid` / `signature_malformed` | The CMS does not verify under the signer's key, or does not decode |
| `content_appended_after_seal` | Bytes exist that the seal does not account for and that are not a legitimate LTA update |
| `coverage_undetermined` | The change analysis was inconclusive. Treated as a failure, never as a pass |
| `docmdp_violation` | The document was changed in a way DocMDP level 1 forbids |
| `multiple_signatures` | More than one signature. Ours is meant to be the only one |
| `not_a_certification_signature` / `certification_permits_changes` | The wrong kind of signature: the document is not locked against further change |
| `untrusted_chain` | The chain does not reach a root in `TRUST_ROOTS_PATH`. A certificate embedded in the document never counts as a reason to trust it |
| `trust_roots_unavailable` | The trust roots could not be read, so nothing is trusted. Fail closed — never "trust whatever is in the file" |
| `certificate_revoked` | A certificate in the chain was revoked at or before the time the timestamp authority attested. Intact, chaining to a trusted root, and not to be believed |
| `revocation_unknown` | Revocation could not be decided from what the document carries — a long-term profile with no document security store, or one that does not cover the chain. The point of embedding validation data is that this is answerable offline years later, so "we could not tell" is a failure |
| `timestamp_missing` / `timestamp_invalid` | No trusted time, or one we do not believe (including a token claiming a time beyond our own clock) |
| `location_mismatch` | The signature's `/Location` is not `envelope:<id>` for this envelope |
| `validation_error` | Validation itself broke unexpectedly. Never a pass |

Two properties of the validator worth being able to state:

- **It never trusts the document.** Trust roots come from `TRUST_ROOTS_PATH` and nowhere else.
- **It validates at the timestamped moment, not today.** Retention is ten years; a signing
  certificate is not. The chain is checked at the time the timestamp authority attested, read from
  the document, so a seal keeps validating after its certificate expires — and that claimed time is
  capped by our own clock, and the token's own signature and TSA chain still have to validate.

### Report-level outcomes

| Field | Meaning |
|---|---|
| `ok: false` | at least one check failed |
| `complete: false` with `ok: true` | consistent, but not sealed, or a check was skipped. Not a signed document |
| `seal.ok: false` | any of the four flags is false **or** `problems` is non-empty. A reported problem denies the seal whatever the flags say |

### If something does fail

1. **Do not touch anything.** There is no delete path in this system by design; do not invent one.
   Snapshot the database and the blob store before anyone investigates.
2. **Read the audit trail for the envelope** (`GET /v1/envelopes/{id}/audit`). It is append-only
   and hash-chained: if it verifies, it is the most reliable thing you have, and it will usually
   say what happened.
3. **Check whether it verified before.** `verification.performed` events carry `ok` and
   `problem_count`, so the trail often dates the change to between two known-good checks.
4. `docs/RUNBOOK.md` has the incident checklists, including what to do about a document that was
   sealed with a key that has since been revoked.

---

## 5. Addendum 1: what changed in the evidence

Three additions (`docs/SPEC-ADDENDUM-1.md`), each with its own weakening and its own containment:

- **A paper archive** is an envelope of `kind = paper_archive`: a scan the host filed, with a
  staff member's attestation, stored write-once as revision 1 (`scan`) and sealed exactly as above
  behind a one-page cover. The seal proves the scan has not changed since filing and who attested
  to it -- `archive.created` and `archive.attested` are the first two events -- and *not* that the
  ink is genuine; the cover page and the certificate say so in those words. Verification runs the
  same checks; a scan replaced in storage fails `revision_1_scan_hash`.
- **A saved signature** (`adopted_signatures`) is created only by the signer, from inside their own
  non-kiosk session, after a signature succeeded, and is never deleted, only revoked. Applying one
  is still an explicit action per field; the capture row records `kind = adopted` and the row's
  id, `signer.signed` carries the digest of what was stamped and `adopted_signature_id`, and the
  certificate says "signed with a saved signature adopted on <date>". A kiosk session is never
  offered one and cannot save one.
- **A re-authentication span** (`REAUTH_SPAN_SECONDS`, default 0, at most 900) lets one attestation
  cover a clinician's other sessions on the same host for that long after its `auth_time`, never
  beyond `REAUTH_MAX_AGE_SECONDS`. What is weakened is per-document proof of the re-authentication;
  what contains it is that every `signer.signed` records `reauth_attestation_id`, `reauth_scope`
  (`session` or `span`) and `reauth_age_seconds`, the certificate prints the method "at <time>
  for this document" or "at <time> in an earlier session, N seconds before signing", and
  `reauth_attestations_match_trail` checks the row against all of it.

How to check each of them by hand is (g) and (h) in section 2, and the certificate wording is
under (d). Two consequences worth stating plainly, because they are the questions an opposing
expert would ask:

- **A paper archive's seal is not evidence that anybody signed anything.** It is evidence about a
  scan and about a filing. The signature it depicts was made on paper, and what stands behind it is
  the paper original and the person who attested to the copy — named on the cover page, in the
  certificate, and in the trail. If the original has been destroyed under policy, say so plainly:
  the disposition is recorded for exactly that reason.
- **A borrowed re-authentication is visible everywhere it matters.** The trail names the
  attestation row, the scope and the age; the certificate prints it in words; and verification
  re-derives the age from the row's `auth_time` (to within five seconds) and refuses a `span`
  attestation that was really made in this session, or one belonging to another user or host. What
  the record cannot show is a *second* deliberate identity proof for the second document, because
  there was not one — which is why the span is off by default and switching it on is a compliance
  decision (`docs/COMPLIANCE-CHECKLIST.md` C10, `docs/RUNBOOK.md` §7).

## 6. Addendum 2: a document the host supplied

Some documents cannot come from a template: a report the EHR renders for one patient, twenty or
thirty pages of their own record, different every time, with a signature block at the end
(`docs/SPEC-ADDENDUM-2.md`). Such an envelope has `source = 'host_document'`, no
`template_version_id`, and its field and role definitions on its own row in
`envelopes.field_definitions` instead of on a published template version.

**What this changes in the evidence, and what it does not.** Nothing downstream of revision 1
differs: the bytes are hashed before anybody sees them, `document.presented` and `document.viewed`
record what was served and confirmed, every signature builds a new revision, and the certificate
and seal are the same. What differs is *provenance* — the content came from the host rather than
from a template somebody published and reviewed — and the trail says so in as many words:
`document.supplied` instead of `document.prepared`, and "Document supplied by the host" on the
certificate, with the upload's hash and the host's document reference printed beside it.

Two things are done so that provenance is still evidence rather than a claim:

- **Both ends of the transformation are kept.** The upload is stored as its own blob
  (`supplied_pdf`), the flattened bytes as revision 1 (`supplied`), and `document.supplied` carries
  both hashes. A reader holding the host's own copy of the report can hash it and match
  `upload_sha256` before asking anything about what happened afterwards.
- **The flattening adds nothing and hides nothing.** `flatten_supplied` removes every widget, every
  annotation and the form itself, draws none of them into the page, and embeds nothing new — and
  re-materialises the document from its page tree, so the removed objects are not merely unlinked
  but absent from the bytes. The page content is untouched and the page count is re-checked on the
  output. It is deterministic: the same upload always produces the same revision 1, which is what
  lets that hash be evidence rather than a property of the moment it was built.

### (i) Checking a host-supplied signature by hand

The walk-through in section 2 applies unchanged from revision 2 onwards. The first two steps are
these instead:

```sh
# 1. The event that says where the document came from, and what it became.
psql -c "SELECT data, encode(document_sha256,'hex')
         FROM audit_events
         WHERE stream_id = '<envelope id>' AND event_type = 'document.supplied'"
# data: {"upload_sha256": "b31c…",        the file the host POSTed
#        "presented_sha256": "260d…",     revision 1, the bytes the clinician was shown
#        "page_count": 30, "field_source": "named_fields",
#        "signer_roles_sha256": "9a7e…", "host_document_ref": "report-88120"}
# document_sha256: 260d…                  the event's own hash column, the same value

# 2. Both hashes, re-derived from what is stored rather than read from a row.
#    Blobs are content-addressed, so the path is the claimed hash (see (a)).
shasum -a 256 upload-as-the-host-still-holds-it.pdf   # must equal upload_sha256
shasum -a 256 .blobstore/26/0d/260d…                  # must equal presented_sha256

# 3. The same presented hash in the two rows that point at it.
psql -c "SELECT encode(presented_sha256,'hex') FROM envelopes WHERE id = '<envelope id>'"
psql -c "SELECT revision_no, kind, page_count, encode(sha256,'hex')
         FROM document_revisions WHERE envelope_id = '<envelope id>' ORDER BY revision_no"
#  1 | supplied | 30 | 260d…
```

All four of those must be the same value; `supplied_revision_matches_trail` is exactly that
comparison, and section 4 says what each failure means. Opening the `260d…` blob should show a
document with no form fields and no annotations whose pages read the same as the host's upload —
that is the whole of what the flattening did, and it is why the two hashes legitimately differ.

**What an opposing expert should ask, and the honest answer.** "Who says the report the clinician
signed is the report the EHR generated?" The service can prove the bytes it presented, that they
came from the upload it was given, and that nothing has changed since. It cannot prove the EHR
generated that upload from the right patient's record — that is the host's evidence, which is why
`host_document_ref` is recorded in the trail and printed on the certificate, and why it must be an
opaque identifier that resolves inside the EHR rather than a description of the patient.

---

## 7. Addendum 3: a shorter flow, and consent for a sitting

Addendum 3 (`docs/SPEC-ADDENDUM-3.md`) took the signing flow from five screens to three — read,
sign, done — and let one agreement to sign electronically cover a sitting. It removed **screens**,
not acts: every page is still displayed before consent (`document.viewed`), consent is still
explicit, each field still takes its own action, and the role that must re-authenticate still does.
Two things about the evidence are worth stating exactly, because both are places where what the
record holds did not change and what it *means* did.

- **Intent is the press of the sign button.** The signer used to tick "I've read the document, and
  I want to sign it as …" and then press "Sign document" — two acts saying the same thing, on a
  screen after the one where they had signed the fields. Now one primary button, "Sign as
  Maria Alvarez" (or "… on behalf of …"), sits under the sentence "By pressing this you are signing
  this document. It counts the same as signing on paper, and you will get a copy." The request
  still carries `intent_confirmed: true`, the service still refuses a signature without it, and
  `signer.signed` records exactly what it always did. What changed is which act that flag stands
  for, which is a judgement about what a court reads as intent rather than anything a test can
  settle: `docs/COMPLIANCE-CHECKLIST.md` C13 is open for counsel, and §2.14 there maps each
  non-negotiable act to where it now lives.
- **Consent may stand for a sitting** (`CONSENT_SPAN_SECONDS`, default `0`, at most `3600`). With
  it on, an acceptance by the same `(host_id, host_user_id)` of the same disclosure version and
  locale stands for that person's other documents for that long, and the second document shows "You
  agreed to sign electronically at 09:12" instead of the checkbox. **Every envelope still records
  its own acceptance**: `consent.accepted` on its own stream, `signers.consent_text_id` and
  `consented_at` set exactly as with the span off, and no signature accepted without them. What is
  weakened is that the disclosure was not displayed again; what contains it is that the event says
  so — `relied_on_envelope_id`, `relied_on_accepted_at`, and `relied_on_root_accepted_at`, the
  moment the notice was last actually shown, carried forward unchanged through a chain so a queue
  cannot renew the window a document at a time. The certificate prints "Consented 09:14 (given for
  an earlier document in the same sitting; disclosure displayed 09:12)", and
  `consent_relied_on_matches_trail` (section 4) re-reads the other envelope's trail years later. A
  kiosk session never has it, in either direction — the same rule that keeps a saved signature off
  a shared tablet — and verification re-derives that too rather than trusting the SQL that enforced
  it. Off by default; switching it on is a compliance decision
  (`docs/COMPLIANCE-CHECKLIST.md` C12, `docs/RUNBOOK.md` §7).

### (j) Following a standing acceptance by hand

Nothing here needs the service. Two queries against two streams, both hash-chained:

```sh
# 1. This envelope's own acceptance, and what it says it stood on.
psql -c "SELECT sequence, occurred_at, actor_user_id, data
         FROM audit_events
         WHERE stream_id = '<envelope id>' AND event_type = 'consent.accepted'"
# data: {"signer_id": "…", "consent_text_id": "8f1c…", "consent_version": "2026-09",
#        "locale": "en-US", "body_sha256": "4d90…",
#        "relied_on_envelope_id": "b1d0f6e2-…",                    the earlier document
#        "relied_on_accepted_at": "2026-09-22T09:12:04.481073Z",   its acceptance
#        "relied_on_root_accepted_at": "2026-09-22T09:12:04.481073Z"}  the notice displayed

# 2. The same acceptance, in that envelope's own trail.
psql -c "SELECT sequence, occurred_at, actor_user_id, data
         FROM audit_events
         WHERE stream_id = 'b1d0f6e2-…' AND event_type = 'consent.accepted'"
```

The second row has to exist, name the same `consent_text_id`, carry the same `actor_user_id`, and
sit at `relied_on_accepted_at` (within the same 60-second row/event tolerance every other
comparison uses). Its own root — its `relied_on_root_accepted_at`, or its `occurred_at` when it was
the document that displayed the notice — is what the first row must have carried forward, and the
gap from that root to the first row's `occurred_at` cannot exceed one hour. Then take the earlier
acceptance's own `data.signer_id` and look for a kiosk context on any of that signer's sessions
(`SELECT kiosk_staff_user_id FROM signing_sessions WHERE signer_id = '<that signer id>'`): one that
is not null, and the acceptance was never one that could stand — the question is whether the person
can be assumed to still be sitting there, so it is any session of theirs, not merely the one the
acceptance came from. Those are the six things `consent_relied_on_matches_trail` checks, in the
order it checks them.

**What an opposing expert should ask, and the honest answer.** "Was the disclosure in front of this
person when they agreed to sign *this* document?" With the span off, yes, and the trail of this one
envelope says so. With it on, no — it was in front of them at `relied_on_root_accepted_at`, on the
document named, minutes earlier at the same desk, and they agreed again here by pressing Continue
with the standing line on screen. The record never claims otherwise: that is why the times are on
the event, on the certificate and re-checkable from a second trail rather than smoothed into one
"Consented" timestamp.

---

## 8. Things a careful reader will ask

**"The signer's own copy — is it the same document?"** Yes, byte for byte. `GET /v1/signing/copy`
returns the sealed blob and nothing else; while the seal is pending it returns `202 {"status":
"sealing"}` rather than an unsealed approximation.

**"Could an administrator edit the audit trail?"** Not through the application: its database role
has `SELECT, INSERT` only on `audit_events`, and a trigger refuses `UPDATE`, `DELETE` and
`TRUNCATE` even for the owner role that runs migrations. Someone with superuser access to Postgres
could disable the trigger — and would then have to recompute every subsequent `event_hash` and
`prev_event_hash`, and the head hash printed inside the sealed PDF, which they cannot change
without breaking the seal. That is the point of printing it there.

**"What if the seal key is compromised?"** Every document sealed with it becomes suspect from the
revocation time onwards. Documents whose timestamp predates the revocation still validate, because
validation is point-in-time against the timestamp — which is why the timestamp is not optional.
See the rotation and incident sections of `docs/RUNBOOK.md`.

**"Can a signature be repudiated because it was typed rather than drawn?"** Not on those grounds.
The developer guide is explicit that a drawn signature adds no legal weight and excludes people;
the audit trail carries the weight. What the trail records is how each field was filled (`drawn`,
`typed`, `click`, `checkbox`, `text`) and the digest of the input, and that wording comes from the
template and the server, never from the client.

**"Was the document really shown to them?"** The server refuses consent and signing until the UI
has reported that every page was displayed, and it checks that claim against the page count of the
bytes *that session was actually served* — not against a number the client also supplied. The host
page must also cap the iframe height (see the README): a frame as tall as its content makes "every
page is on screen" true at load, and the signature would then be evidence that somebody had a
document open rather than that they read it.
