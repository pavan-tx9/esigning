# The audit chain, and how to re-verify one by hand

This file is the normative description of how an audit event is hashed. If you are holding a
database dump and a dispute years from now, everything you need to re-check the chain yourself is
here: the field list, the canonical encoding rules, and a worked example with the exact bytes and
the exact digest they produce.

`tests/audit/test_readme_vector.py` recomputes the worked example below from the live code and
fails if this document has drifted from it, so the example is not decoration.

## The chain

One chain per stream: `envelope` (the usual one), `template`, and `system`.

* `sequence` starts at 1 and has no gaps. Writers take
  `pg_advisory_xact_lock` on a hash of `(stream_type, stream_id)`, read the head, then insert,
  all inside the caller's transaction -- so two concurrent writers cannot produce the same
  sequence number or skip one.
* `prev_event_hash` of the first event is 32 zero bytes
  (`0000000000000000000000000000000000000000000000000000000000000000`). Every later event's
  `prev_event_hash` is the previous event's `event_hash`.
* `event_hash = SHA-256(canonical_json(the event without event_hash))`.
* `occurred_at` comes from the server's `Clock`, never from the client, and never moves backwards
  within a stream. An append whose timestamp is earlier than the head of its stream is refused
  rather than written, because the trail is append-only and the problem could never be corrected.

## The hashed fields

Exactly these seventeen, which is the `audit_events` column list minus `event_hash` itself. Every
stored column is covered, so a change to any one of them breaks the hash.

| Field | Source | Canonical form |
|---|---|---|
| `actor_capacity` | server | one of `self`, `guardian`, `proxy`, `witness`, `interpreter`, `clinician`, or `null` |
| `actor_role` | server | one of `patient`, `clinician`, `staff`, `host`, `system`, or `null` |
| `actor_user_id` | host, via the API key | opaque id string (no whitespace), or `null` |
| `auth_method` | server | lowercase token, e.g. `portal_otp`, `api_key`, or `null` |
| `data` | server, validated per event type | JSON object, keys sorted, same rules recursively |
| `document_sha256` | server | 64 lowercase hex characters, or `null` |
| `event_type` | server | the `EventType` value, e.g. `signer.signed` |
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

`event_hash` is not in the list: it is the output.

## Canonical JSON

1. Objects are written with their keys sorted by UTF-8 code point, recursively.
2. No insignificant whitespace: `{"a":1,"b":2}`, never `{"a": 1, "b": 2}`.
3. The output is UTF-8. Non-ASCII characters are written literally, not `\uXXXX`-escaped.
4. `bytes` are lowercase hex. A SHA-256 digest is 64 hex characters.
5. `UUID`s are their lowercase canonical string.
6. Timestamps are RFC 3339 in UTC with exactly six fractional digits and a `Z` suffix:
   `2026-03-17T14:31:02.481073Z`. A naive timestamp is an error, not an assumption.
7. Absent values are `null`. A field is never simply left out.
8. Floats are rejected. No evidence field is a float, and their text form is not portable.

## What may appear in `data`

Ids, enums, hashes, versions, counts, error codes and server-recorded timestamps. Nothing else.
Names, dates of birth, addresses, free text and prefill values have no field to live in: every
event type has a closed model in `events.py`, unknown keys are rejected, and every string field is
a constrained pattern. `OpaqueId` forbids whitespace, which is what stops a display name being
passed where a host user id belongs.

A rejected append says which field and which rule, never what the value was:

```
audit data rejected for signer.declined: note (extra_forbidden)
```

## Worked example

An `signer.signed` event, the seventh on its stream. These are the stored column values:

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
| `data` | the object below |

The canonical JSON is 1045 bytes, on one line (wrapped here only for the page; there is no
whitespace in the real thing):

```json
{"actor_capacity":"self","actor_role":"patient","actor_user_id":"host-user-1187","auth_method":"portal_otp","data":{"capacity":"self","capture_count":1,"captures":[{"field_id":"patient_sig","kind":"drawn"}],"consent_version":"2026-09","presented_sha256":"3b1f8c2d4e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e","reauth_used":false,"revision_no":2,"revision_sha256":"9a8b7c6d5e4f30211203f4e5d6c7b8a9f0e1d2c3b4a59687786950413223145f","role_key":"patient","signer_id":"7c3f1d2e-5a64-4b8f-9c10-2e4a6b8d0f31"},"document_sha256":"9a8b7c6d5e4f30211203f4e5d6c7b8a9f0e1d2c3b4a59687786950413223145f","event_type":"signer.signed","id":"0f2c9a44-1d3b-4e57-8a66-b1c2d3e4f5a6","ip":"198.51.100.24","occurred_at":"2026-03-17T14:31:02.481073Z","on_behalf_of":null,"prev_event_hash":"5d41402abc4b2a76b9719d911017c592a1b2c3d4e5f60718293a4b5c6d7e8f90","sequence":7,"session_id":"b4d5e6f7-8a9b-4c0d-9e1f-2a3b4c5d6e7f","stream_id":"1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9","stream_type":"envelope","user_agent":"Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X)"}
```

SHA-256 of those bytes:

```
466970085c4ed03fbf61e06ff44d19b8c8baa59920baed85a8b583a3cbbcce47
```

which is what `audit_events.event_hash` holds for this row, and what the eighth event's
`prev_event_hash` must be.

## Re-verifying a chain from a dump, without this codebase

For each row of a stream, in `sequence` order:

1. Build a JSON object from the seventeen columns above, applying the rules in "Canonical JSON".
   Postgres renders `bytea` as `\x…` and timestamps in the session time zone: convert the first to
   plain lowercase hex and the second to UTC with six fractional digits.
2. SHA-256 it. It must equal the row's `event_hash`.
3. The row's `prev_event_hash` must equal the previous row's `event_hash`, or 32 zero bytes for
   `sequence = 1`.
4. `sequence` must be the previous one plus one, and `occurred_at` must not be earlier than the
   previous row's.

A worked one-liner against a live database, for the whole envelope stream:

```sh
cd backend && uv run python -c "
from uuid import UUID
from sqlalchemy.orm import Session
from esign.audit import build_audit_log
from esign.clock import SystemClock
from esign.config import Settings
from esign.db import app_engine
s = Settings()
with Session(app_engine(s)) as db:
    print(build_audit_log(s, SystemClock()).verify(db, 'envelope', UUID('<envelope id>')))
"
```

`verify` reports every problem it finds rather than stopping at the first: `sequence gap after 4`,
`wrong prev_event_hash at 7`, `hash mismatch at 7`, `non-monotonic occurred_at at 9`,
`data keys do not match signer.signed at 7`, `unknown event_type at 11`.
