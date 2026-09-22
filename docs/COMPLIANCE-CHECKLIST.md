# Compliance checklist

Every requirement in `docs/ehr-esignature-developer-guide.pdf` — the Definition of Done, every do
and every don't — mapped to the code that implements it and the test that proves it.

**How to read this.** A ✅ means there is code *and* a test that would fail if the behaviour were
removed. A ⚠️ means the behaviour is implemented but something about the claim is weaker than the
guide's wording, and the entry says exactly what. A 🔵 means the item is not an engineering
decision at all: it needs counsel, compliance or a purchasing decision, and no amount of code will
close it. Every ⚠️ and 🔵 is collected again in sections 6 and 7 so nobody has to hunt.

Test paths are relative to `backend/` unless they start with `frontend/`. `make check` runs all of
them: 1,957 backend tests, 136 frontend tests and 23 demo-host tests at the time of writing, plus the two Playwright suites (14 specs against the mocks, 12 against the real stack through the demo host) that `make check` does not run.

This document describes the code as it is, not as the spec intends it to be. Where the two differ,
the entry says so.

---

## 1. Definition of done

| # | Item | Status | Where it lives | What proves it |
|---|---|---|---|---|
| 1 | Consent disclosure is shown, explicitly accepted, and its version is stored for every signer | ✅ | `identity/consent_texts.py`; `envelopes/service.py::accept_consent`; `frontend/src/flow/steps/ConsentStep.tsx` | `tests/envelopes/test_signing_flow.py::test_consent_requires_viewing_first`, `::test_consent_stores_the_text_it_was_given`, `::test_consent_to_a_stale_version_is_refused`; `tests/identity/test_consent.py::test_the_shipped_disclosure_covers_what_esign_requires` |
| 2 | Clinician signatures require re-authentication at the moment of signing | ✅ | `envelopes/service.py::_require_fresh_reauth` (`REAUTH_MAX_AGE_SECONDS`, default 120s); `create` forces `requires_reauth` for a clinician capacity whatever the template says; `documents/definitions.py` refuses to publish a clinician-capable role without it | `tests/documents/test_definitions.py::test_a_clinician_role_that_does_not_reauthenticate_is_refused`; `tests/e2e/test_happy_paths.py::test_three_signers_in_sequence_with_clinician_reauthentication`; `tests/e2e/test_isolation_and_tampering.py::test_reauthentication_cannot_be_attested_after_the_signature` |
| 3 | Guardians, witnesses and proxies are recorded in their own capacity | ✅ | `contracts.Capacity`; `signers.capacity` / `on_behalf_of`; `Actor.capacity` in the trail; the caption on the mark and the "Capacity" row on the certificate | `tests/envelopes/test_create.py::test_a_guardian_must_say_who_they_act_for`, `::test_a_guardian_acts_for_this_envelopes_patient`; `tests/documents/test_marks.py::test_on_behalf_of_appears_in_the_caption`; `tests/documents/test_certificate.py::test_every_signer_is_described_in_full` |
| 4 | The final PDF is built and flattened on the server; the client never supplies document bytes or hashes | ✅ | `documents/service.py::prepare` (flatten), `::apply_signer_marks`; `api/schemas.py` forbids unknown keys on every body | `tests/documents/test_prepare.py::test_a_widget_appearance_is_flattened_into_the_page`; `tests/documents/test_marks.py::test_the_signed_revision_has_nothing_interactive`; `tests/e2e/test_isolation_and_tampering.py::test_a_signer_cannot_fill_someone_elses_field_or_supply_the_date` |
| 5 | The sealed PDF validates in Adobe Acrobat, and a one-byte change makes validation fail | ⚠️ | `sealing/sealer.py` | The one-byte half is proved exhaustively: `tests/sealing/test_validate.py::test_every_single_byte_flip_in_the_first_kilobyte_is_caught`, `::test_flipping_a_byte_of_document_content_breaks_the_digest`, `::test_an_incremental_update_appended_after_the_seal_is_caught`. **Acrobat cannot be automated here.** It is a launch-checklist step in `docs/RUNBOOK.md` §1.8, and the green tick itself depends on a purchasing decision (see §7) |
| 6 | The signing key lives in KMS or an HSM, and a rotation procedure is written down | ✅ | `sealing/kms.py` — one `kms:Sign` call, no key material read, ever; `check_production_settings` refuses anything but `aws_kms` in production. Rotation: `docs/RUNBOOK.md` §2 | `tests/sealing/test_kms.py::test_seals_with_a_key_held_in_kms`, `::test_signing_happens_exactly_once_per_seal`, `::test_an_unreachable_kms_is_seal_unavailable`; `tests/api/test_http_hygiene.py::test_production_refuses_a_kms_backend_with_no_key_or_certificate` |
| 7 | The application's database role cannot update or delete audit events, and the hash chain verifies end to end | ✅ | `migrations/0002_roles.sql` (grants), `0001_schema.sql` (triggers), `0600` (truncate guards); `audit/log.py::verify` | `tests/foundation/test_roles.py::test_app_role_cannot_mutate_audit_events`, `::test_owner_update_of_an_audit_event_hits_the_trigger`, `::test_owner_truncate_of_audit_events_hits_the_trigger`; `tests/audit/test_verify.py::test_tampering_with_any_column_breaks_the_hash`; `tests/e2e/test_isolation_and_tampering.py::test_a_removed_audit_row_is_caught` |
| 8 | Sealed documents sit in write-once storage and are excluded from cleanup and deletion jobs | ✅ | `storage/s3.py` — Object Lock, conditional put, no `delete_object` anywhere; `BlobService` has no delete method | `tests/storage/test_s3_backend.py::test_an_object_is_written_under_a_compliance_lock_by_default`, `::test_object_lock_is_really_enforced_by_the_bucket`, `::test_the_backend_never_calls_delete`; `tests/storage/test_no_delete_path.py` (six tests that inspect the package for any destructive call) |
| 9 | The signer receives a copy immediately | ✅ | `GET /v1/signing/copy`; `envelopes/service.py::signer_copy`, `::may_download_copy` — the session a signer signed from stays alive for this and nothing else | `tests/envelopes/test_views_and_downloads.py::test_the_copy_is_only_ever_the_sealed_document`; `tests/envelopes/test_sign.py::test_signing_leaves_this_session_alive_for_the_copy_only`; `frontend/src/App.test.tsx` "review, consent, sign by typing, confirm, and the sealed copy" |
| 10 | No PHI appears in URLs, emails, text messages, logs or error tracking | ✅ | `logging.py` (allowlist); `audit/events.py` (closed models); `api/errors.py` (fixed sentences, never echoing input); ids are UUIDv4; no email or SMS code exists in the repository | `tests/e2e/test_webhooks_and_logs.py::test_no_log_line_in_a_full_run_contains_a_name_or_a_prefill_value`; `tests/foundation/test_logging.py::test_nothing_that_could_carry_phi_is_on_the_allowlist`; `tests/audit/test_no_phi.py::test_the_signer_display_name_has_nowhere_to_go`; `frontend/src/lib/api.test.ts` "never puts the token in the URL" |
| 11 | KMS and timestamp outages leave documents pending, never falsely complete, and sealing retries on recovery | ✅ | `envelopes/service.py::seal_pending` + `_on_seal_failure` (separately committed); `worker/__init__.py`; backoff 1m/5m/15m/1h/hourly | `tests/e2e/test_idempotency_and_outages.py::test_a_kms_outage_leaves_the_envelope_pending_and_two_workers_seal_it_once`, `::test_a_timestamp_authority_outage_leaves_the_envelope_pending_until_the_worker_retries`; `tests/envelopes/test_views_and_downloads.py::test_storage_being_down_leaves_the_envelope_pending_like_a_kms_outage` |
| 12 | Counsel has approved the consent wording, the certificate of completion and the document type list | 🔵 | The artefacts exist and are ready for review: `identity/consent/en-US.2026-09.txt` and `en-US.2026-10.txt`, `documents/certificate.py`, `APPROVED_DOCUMENT_TYPES` | **Not done.** No approval has been recorded. See §7 |
| 13 | An internal note explains how signatures work and how to verify one | ✅ | `docs/HOW-SIGNATURES-WORK.md`, plus `backend/src/esign/audit/README.md` for the normative hash definition | `tests/audit/test_readme_vector.py::test_the_worked_canonical_json_in_the_readme_is_byte_for_byte_correct` — the worked example is recomputed from live code, so the note cannot drift |

---

## 2. Do's and don'ts

### 2.1 Scope and templates

| Rule | Status | Where | Proof |
|---|---|---|---|
| DO ship v1 for authenticated signers only, with a fixed set of templates | ✅ | Every entry point needs an `esk_` key or an `est_` token; templates are imported ahead of time | `tests/api/test_http_hygiene.py::test_errors_use_one_envelope_and_never_echo_input`; `tests/identity/test_hosts.py::test_every_bad_key_is_the_same_unauthorized` |
| DON'T start with email-link signing or a visual template builder | ✅ | Neither exists. `POST /v1/envelopes/bulk`, `…/email-links` and `…/documents` are explicit `422 out_of_scope` routes, so a caller gets a clear refusal rather than a 404 that looks like a bug | `tests/api/test_http_hygiene.py::test_out_of_scope_requests_are_refused_with_a_clear_code` |
| DO define fields in code, or as AcroForm fields in PDFs we author | ✅ | `templates/*.json` beside `*.pdf`, generated reproducibly by `templates/generate.py` | `tests/documents/test_sample_templates.py::test_regenerating_reproduces_the_committed_files_byte_for_byte` |
| DON'T accept arbitrary uploaded PDFs | ✅ | `inspect_template_pdf` refuses encrypted, already-signed, scripted, XFA and attachment-bearing files, and enforces size and page limits. Nothing accepts a PDF at signing time | `tests/documents/test_inspection.py::test_forbidden_features_are_refused`, `::test_an_encrypted_template_is_refused`, `::test_a_too_large_template_is_refused` |
| DO version every template; a published version is immutable | ✅ | `template_versions.status`, guarded by a database trigger, not only by application code | `tests/foundation/test_template_immutability.py` (including `::test_a_published_version_cannot_be_deleted`); `tests/api/test_templates_api.py` |
| DON'T edit a template in place once anyone has signed against it | ✅ | An envelope holds `template_version_id`; publishing is one-way; the certificate prints the key and version it was created against | `tests/envelopes/test_create.py`; `tests/documents/test_certificate.py::test_the_certificate_carries_every_field_spec_6_requires` |

### 2.2 Consent and intent

| Rule | Status | Where | Proof |
|---|---|---|---|
| DO show the disclosure and require an explicit agree action before the first signature; store the version | ✅ | State machine refuses `SIGN` before `consented`; `consent.accepted` records id, version, locale and body hash | `tests/envelopes/test_signing_flow.py::test_consent_requires_viewing_first`; `tests/e2e/test_isolation_and_tampering.py::test_signing_before_viewing_or_consenting_is_a_conflict` |
| DON'T pre-tick the box, bury consent, or infer it | ✅ | `frontend/src/flow/steps/ConsentStep.tsx` renders an unchecked checkbox and a separate agree action; the server requires `accepted: true` and a matching `consent_version` | `frontend/src/App.test.tsx` "review, consent, sign by typing, confirm, and the sealed copy"; `tests/envelopes/test_signing_flow.py::test_consent_to_a_stale_version_is_refused` |
| DO require a deliberate act for every signature on every document | ✅ | A signature is adopted once per session and then **applied per field by an explicit action**; the final step is an intent confirmation, and `sign` requires `intent_confirmed: true` | `frontend/src/flow/draft.test.ts` "choosing a different signature un-applies the old one from every field", "never sends a date, an unapplied signature, or an empty optional answer" |
| DON'T silently re-apply a saved signature | ✅ | The draft lives in memory for one session only. A signature the signer chose to *save* (Addendum 1 B) is offered back as one of three equal choices, never pre-applied: using it is still one explicit action per field, the server records `kind = adopted` and which row, and a kiosk session is never offered one | `frontend/src/flow/draft.test.ts`; `frontend/src/App.test.tsx` "a kiosk session ends on hand-back with every trace of the patient gone"; `frontend/e2e/signing-flow.spec.ts` "a saved signature is offered first, placed per field, and sent as its id"; `tests/adopted_signatures/test_offered.py`; `tests/e2e/test_addendum_stories.py::test_a_kiosk_session_is_never_offered_the_patients_saved_signature` |
| DO let the signer review the full document before signing becomes available, and offer a paper alternative | ✅ | `record_viewed` checks `pages_viewed` against the page count of **the bytes that session was served**, not a number the client also supplied; decline reasons include `prefers_paper`, presented as an equally visible action | `tests/envelopes/test_signing_flow.py::test_a_second_session_cannot_claim_a_view_it_was_not_served`; `frontend/src/lib/pages-seen.test.ts` "counts a page only once it is drawn, on screen, and has stayed there"; `frontend/src/App.test.tsx` "choosing paper declines with that reason and tells the host" |
| DON'T make signing reachable before presentation, or make e-signing the only option | ✅ | As above, plus the decline path is reachable from every step before done | `frontend/src/flow/machine.test.ts` "decline can be opened from any step before done, and closed again" |
| DO give the signer their copy straight away, by download and in the portal | ✅ | `GET /v1/signing/copy` for the signer; the host files the sealed PDF from the webhook | `tests/envelopes/test_views_and_downloads.py::test_the_copy_is_only_ever_the_sealed_document`; `demo-host` files it and shows it in the chart |
| DON'T keep the signed copy visible only to staff | ✅ | Both audiences are first-class, and `document.downloaded` records which one took it (`audience: signer \| host`) | `tests/envelopes/test_views_and_downloads.py` |

### 2.3 Identity and attribution

| Rule | Status | Where | Proof |
|---|---|---|---|
| DO bind each signature to a user ID and session | ✅ | `signers.host_user_id` → `Actor.user_id`; `RequestContext.session_id` on every event; tokens are bound to one signer and one envelope | `tests/identity/test_sessions.py::test_a_session_binds_a_token_to_one_signer`; `tests/envelopes/test_signing_flow.py::test_a_session_for_another_envelopes_signer_is_not_found` |
| DO re-authenticate clinicians at the moment of signing | ✅ | See DoD #2 | as DoD #2 |
| DON'T rely on a long-lived session for clinician attestations | ✅ | `SESSION_TTL_SECONDS` 30 min; the re-auth window is 120 s and is checked at `sign`, not at session creation; `auth_time` older than 12 h is refused outright | `tests/identity/test_reauth.py::test_an_attestation_older_than_the_window_is_refused_at_the_door`, `::test_an_attestation_that_predates_the_session_is_refused`; `tests/identity/test_sessions.py::test_auth_time_older_than_the_window_is_refused` |
| DON'T tolerate shared logins near signing | ⚠️ | The service cannot see the host's login model. What it does enforce: one token per signer, a new session revokes the previous one, `host_user_id` must be opaque and is recorded on every event, and re-authentication is an attestation the host makes per session | `tests/identity/test_sessions.py::test_a_session_binds_a_token_to_one_signer`. **The host's own account hygiene is outside this system.** Raise it in the integration review |
| DO model guardians, witnesses, interpreters and proxies explicitly | ✅ | `Capacity` is a closed literal; roles carry `allowed_capacities`; a role may be `required: false` for an optional witness or interpreter | `tests/envelopes/test_create.py::test_only_a_guardian_or_proxy_acts_on_behalf_of_someone`; `tests/envelopes/test_ordering.py::test_sequential_order_gates_session_creation` |
| DON'T let staff sign for a patient by typing the patient's name, or record a guardian's signature as the patient's | ✅ | A guardian is a signer in their own right with `capacity: guardian` and `on_behalf_of` equal to the envelope's `patient_ref`; the caption under the mark says "on behalf of", and so does the certificate | `tests/envelopes/test_create.py::test_a_guardian_acts_for_this_envelopes_patient`; `tests/documents/test_marks.py::test_the_caption_says_who_in_what_capacity_when_and_which_signer`; `tests/envelopes/test_no_phi.py::test_a_guardians_stream_names_the_patient_only_by_reference` |
| DO record which staff member started a tablet session and how identity was checked | ✅ | `KioskContext{staff_user_id, identity_check}`, recorded on `session.created` and printed on the certificate | `tests/identity/test_sessions.py::test_a_kiosk_session_records_the_staff_member_and_the_check`; `tests/envelopes/test_sealing.py::test_the_certificate_carries_the_kiosk_details` |
| DON'T attribute a kiosk signature to the logged-in staff member | ✅ | The `Actor` on `signer.signed` is derived from the signer's capacity, never from the kiosk context; the staff id lives in a separate field | `tests/api/test_sessions_api.py::test_a_kiosk_session_records_the_staff_member_and_the_check`; `tests/documents/test_certificate.py::test_every_signer_is_described_in_full` |

### 2.4 Document integrity and sealing

| Rule | Status | Where | Proof |
|---|---|---|---|
| DO build the final PDF on the server, flatten it, then seal with PAdES (B-LT, RFC 3161) using pyHanko | ✅ | `documents/`, then `sealing/sealer.py`. `SEAL_PROFILE` defaults to `PAdES-B-LT`; production refuses `B-T` | `tests/sealing/test_seal.py::test_seal_then_validate_is_ok_for_every_profile`, `::test_long_term_profiles_embed_validation_information`, `::test_b_t_is_an_explicit_choice_not_a_downgrade` |
| DON'T write your own cryptography, byte-range handling or signature container | ✅ | pyHanko does all of it. The only hashing we do is SHA-256 over whole byte strings for the audit chain and content addressing | `sealing/` imports pyHanko throughout; there is no byte-range arithmetic in this codebase outside tests |
| DO keep the signing key in a KMS or HSM and sign through the external-signer interface | ✅ | `KmsSigner(pyhanko.sign.Signer)` — its only operation is one `kms:Sign` over the CMS signed attributes | `tests/sealing/test_kms.py::test_signing_happens_exactly_once_per_seal` |
| DON'T put a private key in the repo, env vars, an image or an app server disk | ✅ | `.dev-pki/` is git-ignored and refuses to generate under `APP_ENV=prod`; no setting holds key material, only a KMS key **id**; production refuses `SEAL_KEY_BACKEND=local` | `tests/cli/test_cli.py::test_dev_pki_refuses_to_overwrite_and_refuses_production`; `tests/api/test_http_hygiene.py::test_production_refuses_to_start_half_configured` |
| DO hash the exact bytes shown to the signer and the final sealed bytes, and store both in the trail | ✅ | `document.presented.document_sha256` is the hash of the bytes in that HTTP response; `document.sealed.document_sha256` is the sealed file. `signer.signed` additionally records the presented, base and output revision hashes | `tests/envelopes/test_signing_flow.py::test_presenting_records_what_this_session_was_shown`; `tests/verification/test_report.py::test_a_pointer_that_disagrees_with_the_revisions_is_reported` |
| DON'T trust the client: no client PDF, client hash or client-side flattening | ✅ | The Signer API accepts signature *inputs* only; bodies forbid unknown keys; `date_signed` from a client is refused with a distinct code | `tests/e2e/test_isolation_and_tampering.py::test_a_signer_cannot_fill_someone_elses_field_or_supply_the_date`, `::test_a_value_capture_cannot_claim_a_signature_kind`; `tests/documents/test_marks.py::test_a_client_supplied_date_signed_is_refused` |
| DO add each signature as an incremental update so earlier signatures stay valid (multi-signer) | ⚠️ | **Deliberate deviation, and worth being able to defend.** There is exactly one cryptographic signature, applied after the last signer. Each signer's step produces a fully hashed, stored, audit-chained revision instead. The reason is that the certificate of completion must be *inside* the sealed bytes, and appending pages after a PDF signature invalidates it — so a per-signer-signature design cannot carry the certificate the guide also requires. The per-signer evidence is the chain plus the stored revisions, and the seal covers a certificate quoting the chain's head hash, which ties them together. See `docs/HOW-SIGNATURES-WORK.md` §1 | `tests/envelopes/test_ordering.py::test_each_signer_signs_on_top_of_the_previous_revision`; `tests/verification/test_report.py::test_a_swapped_signature_image_inside_the_seal_is_reported`; `tests/envelopes/test_evidence_guards.py::test_the_certificate_quotes_the_chain_it_verified` |
| DON'T re-render, optimise, compress or re-save a PDF after any signature has been applied | ✅ | `finalize` rebuilds the document when it appends the certificate — but that happens **before any cryptographic signature exists**, and `seal` refuses an input that already carries one. After the seal, nothing touches the bytes: they are stored content-addressed and write-once | `tests/sealing/test_seal.py::test_already_signed_documents_are_refused`, `::test_seal_does_not_mutate_its_input`; `tests/verification/test_report.py::test_a_finalized_document_whose_pages_are_not_the_signed_ones_is_reported` |
| DO plan certificate rotation from day one and embed long-term validation data | ✅ | `docs/RUNBOOK.md` §2; `PAdES-B-LT` embeds a DSS, and `validate` reads it under `hard-fail` rather than ignoring it | `tests/sealing/test_seal.py::test_long_term_profiles_embed_validation_information`; `tests/sealing/test_validate.py::test_a_seal_whose_certificate_was_revoked_before_it_signed_is_refused` |
| DON'T assume a self-signed certificate earns Adobe's green tick | 🔵 | Acknowledged in code (the dev PKI is explicitly never for production) and costed in `docs/RUNBOOK.md` §1.2 | Purchasing decision. See §7 |

### 2.5 Audit trail

| Rule | Status | Where | Proof |
|---|---|---|---|
| DO write an append-only log covering created, presented, viewed, consented, authenticated, signed, declined, voided, sealed and downloaded | ✅ | `contracts.EventType` has 23 types and covers all ten, plus `session.rejected`, `seal.failed`, `envelope.superseded` and `verification.performed` | `tests/audit/test_append.py::test_every_event_type_round_trips_through_the_database_and_still_verifies` |
| DON'T store audit events anywhere the application role can UPDATE or DELETE; grant INSERT and SELECT only | ✅ | `0002_roles.sql`, plus triggers that stop the owner role too | `tests/foundation/test_roles.py::test_app_role_has_no_update_delete_or_truncate_grant`, `::test_app_role_is_not_a_superuser_and_cannot_bypass_rls` |
| DO chain events: each row stores the previous row's hash. Use server time in UTC | ✅ | `audit/log.py`, `audit/canonical.py`; `Clock` everywhere; a clock that goes backwards on a stream is an `IntegrityFailure`, not a clamped value | `tests/audit/test_append.py::test_each_event_chains_to_the_one_before_it`, `::test_occurred_at_comes_from_the_clock_not_the_wall`, `::test_equal_timestamps_are_allowed_but_a_backwards_clock_is_refused`; `tests/audit/test_concurrency.py::test_concurrent_appends_to_one_stream_produce_a_gapless_chain` |
| DON'T use client timestamps, or plan to rebuild the trail from application logs | ✅ | No audit field is populated from client JSON except through validated, typed fields; logs are explicitly not a record (they carry no PHI and no bodies) | `tests/audit/test_no_phi.py::test_no_stored_audit_row_can_hold_free_text` |
| DO generate the certificate of completion from the log and append it before sealing | ✅ | `_certificate_summary` reads every dated fact from the trail, cross-checks the mutable rows, and refuses on a disagreement | `tests/envelopes/test_evidence_guards.py::test_the_certificate_quotes_the_chain_it_verified`, `::test_a_broken_audit_chain_refuses_to_seal`, `::test_a_certificate_never_invents_a_completion_time` |
| DON'T put more PHI in the certificate than is needed | ✅ | `CertificateSummary` cannot carry chart data: there is no field for it. The only personal data is the signers' display names, which a signature nobody can attribute would lack | `tests/documents/test_certificate.py::test_nothing_but_the_summary_reaches_the_page` |

### 2.6 Storage and retention

| Rule | Status | Where | Proof |
|---|---|---|---|
| DO store sealed PDFs encrypted in write-once storage such as S3 Object Lock, linked to the chart | ✅ | `storage/s3.py` (Object Lock + SSE + conditional put); the host links it via `host_document_ref` and the `envelope.sealed` webhook | `tests/storage/test_s3_backend.py::test_server_side_encryption_is_on`, `::test_the_put_is_conditional_so_an_existing_key_is_never_replaced` |
| DON'T overwrite or delete a signed document; a correction is a new document that voids and references the old one | ✅ | No delete path exists. A sealed envelope is corrected by a new envelope with `supersedes_envelope_id`, which records `envelope.superseded` on the old stream. A sealed envelope can never be voided | `tests/e2e/test_endings.py::test_a_sealed_envelope_is_corrected_by_superseding_it_exactly_once`; `tests/envelopes/test_ending.py::test_a_sealed_envelope_is_never_voided` |
| DO apply the medical record retention schedule; ask compliance for the figures | ⚠️/🔵 | The mechanism is complete: `RETENTION_YEARS_BY_DOCUMENT_TYPE` per type, a 10-year default floor, passed to Object Lock as an absolute date on every blob. **The figures themselves have not been set** — the default is in force | `tests/foundation/test_clock_ids_config.py::test_retention_can_be_set_per_document_type`; `tests/storage/test_service.py::test_the_default_retention_is_the_configured_floor_measured_from_the_clock`. The table is compliance's to supply; see §7 |
| DON'T let generic cleanup jobs, TTLs or account-deletion flows touch signed records | ✅ | The only `DELETE` grant anywhere is on `idempotency_keys`, and the only deletion the code performs is of expired keys in that table | `tests/foundation/test_roles.py::test_app_role_cannot_delete_from_the_evidence_bearing_tables`, `::test_app_role_may_still_delete_expired_idempotency_keys`; `tests/storage/test_no_delete_path.py::test_the_module_never_added_a_migration_that_allows_deletion`. Operational rules are in `docs/RUNBOOK.md` §4 |

### 2.7 Security and PHI

| Rule | Status | Where | Proof |
|---|---|---|---|
| DO authorise every document fetch | ✅ | Every host lookup is scoped to the authenticated host; every signer route is scoped by the token; another host's object is `not_found`, never `forbidden` | `tests/e2e/test_isolation_and_tampering.py::test_a_host_never_reaches_another_hosts_data`; `tests/identity/test_sessions.py::test_another_hosts_session_does_not_exist_for_reauth` |
| DO log access | ✅ | `AccessLog` middleware: method, route template, status, duration. Plus `document.downloaded` in the trail, which is the access record that matters | `tests/foundation/test_logging.py::test_a_real_log_line_carries_no_unlisted_value` |
| DO encrypt in transit and at rest | ⚠️ | At rest: S3 SSE (`AES256` or `aws:kms`) is in code and tested. In transit and database-at-rest are **deployment concerns**: TLS is terminated in front of the API (HSTS is set when `APP_ENV=prod`), and Postgres encryption is the platform's | `tests/storage/test_s3_backend.py::test_server_side_encryption_is_on`; `tests/api/test_http_hygiene.py::test_every_response_carries_the_security_headers`. Deployment items are in `docs/RUNBOOK.md` §1 |
| DON'T put PHI or guessable document IDs in URLs, emails, texts, logs or analytics | ✅ | All ids are UUIDv4; session tokens are 256-bit and never in a URL; the access log records the route template, not the path; there is no email, SMS or analytics code in the repository | `frontend/src/lib/api.test.ts` "never puts the token in the URL"; `tests/e2e/test_webhooks_and_logs.py::test_no_log_line_in_a_full_run_contains_a_name_or_a_prefill_value` |
| DO use single-use, short-lived tokens bound to one signer and one document for any signing link | ⚠️ | There is no signing *link*: the token is delivered by `postMessage` and never appears in a URL, which is stronger. It is bound to one signer and one envelope, expires in 30 minutes, is stored only as a hash, and creating a new session revokes the previous one. It is **not single-use** — the UI uses it for the whole flow and then for the copy download — so a token captured mid-flow is usable until it expires or the signer signs (which revokes every other session for them) | `tests/identity/test_sessions.py::test_a_session_binds_a_token_to_one_signer`, `::test_the_plaintext_token_never_reaches_the_database`, `::test_expired_revoked_and_unknown_are_indistinguishable`; `tests/envelopes/test_sign.py::test_signing_leaves_this_session_alive_for_the_copy_only` |
| DON'T email the document as an attachment | ✅ | Nothing in this service sends email | no email client is imported anywhere in `backend/`, `frontend/` or `demo-host/` |
| DO rate-limit and alert on the signing and re-authentication endpoints | ⚠️ | Rate limiting is implemented and tested, per host, per session and per IP, on session creation, re-auth, consent, signing, presentation, copy and verification. **Alerting is not in the code** — it is a deployment concern, with thresholds and queries in `docs/RUNBOOK.md` §3. Also note the limiter is per process (§6) | `tests/api/test_http_hygiene.py::test_session_creation_is_rate_limited_per_host_with_a_retry_hint`, `::test_guessing_tokens_is_rate_limited_per_ip`, `::test_running_a_verification_is_rate_limited_per_host`; `tests/identity/test_rate_limiter.py` |
| DON'T send documents to a third party without a BAA; a TSA receiving only a hash is fine | ✅ | The only outbound calls are: KMS (signed attributes, a few hundred bytes — no document bytes), the TSA (a hash), and the host's own webhook (ids, statuses, hashes). No PDF leaves the service except to the host and the signer | `tests/e2e/test_webhooks_and_logs.py::test_webhooks_are_signed_carry_no_phi_and_verify`; `sealing/kms.py` module docstring and `tests/sealing/test_kms.py` |

### 2.8 User experience

| Rule | Status | Where | Proof |
|---|---|---|---|
| DO make the flow work on phones and tablets, with keyboard and screen reader support | ⚠️ | Built for it: one column, 360px up, ARIA live regions and labels throughout, focus management per step, and specific screen-reader affordances on the PDF viewer. **There is no automated accessibility audit** (no axe or equivalent in the test suite), so the claim rests on the component tests and manual review | `frontend/src/App.test.tsx` "tells a screen reader what the zoom is, and when a press changed nothing", "stays on screen while the patient reads, rather than scrolling off the top"; see §6 |
| DO offer typed and click-to-sign as well as drawn | ✅ | All three are first-class capture kinds, server and client | `tests/documents/test_marks.py::test_click_to_sign_renders_the_signers_name_in_the_plain_face`, `::test_a_typed_signature_lands_inside_its_rect`; `frontend/src/flow/draft.test.ts` "typed and click signatures are first-class capture kinds" |
| DON'T force a drawn signature | ✅ | As above. The trail records *how* each field was filled, and the wording comes from the template and the server, never the client | `tests/envelopes/test_evidence_guards.py::test_the_trail_takes_a_capture_kind_from_the_template_not_the_client` |
| DO show clear state: what is being signed, how many fields remain, and a confirmation with the copy | ✅ | Six states, a per-page progress indicator, a remaining-fields count, a review screen and a final confirmation | `frontend/src/flow/draft.test.ts` "counts what is still needed"; `frontend/src/flow/machine.test.ts`; `frontend/src/App.test.tsx` |
| DON'T allow double submission; signing must be idempotent and a retry must not create a second signature | ✅ | `Idempotency-Key` is **required** on `sign` (422 without it); a replay returns the first response; the same key with a different body is a conflict; the UI disables double submission and reuses the key on retry | `tests/e2e/test_idempotency_and_outages.py::test_a_double_submitted_signature_returns_the_same_response_and_makes_one_revision`, `::test_two_racing_submissions_with_one_key_sign_once`; `frontend/src/App.test.tsx` "retries a lost sign reply with the same Idempotency-Key and signs exactly once" |

### 2.9 Testing and failure handling

| Rule | Status | Where | Proof |
|---|---|---|---|
| DO add an automated test that flips one byte in a sealed PDF and asserts verification fails | ✅ | `tests/sealing/test_validate.py` does it exhaustively for the first kilobyte, plus content, trailer and signature-container bytes, and appended data | `::test_every_single_byte_flip_in_the_first_kilobyte_is_caught`, `::test_bytes_appended_after_the_final_eof_are_caught`, `::test_pyhanko_itself_refuses_to_append_to_our_seal`; end to end: `tests/e2e/test_isolation_and_tampering.py::test_a_tampered_sealed_blob_is_caught` |
| DO open real outputs in Adobe Acrobat and check the signature panel | ⚠️ | Cannot be automated. Launch-checklist step, `docs/RUNBOOK.md` §1.8, and a step after any change to the sealing path | See §6 |
| DON'T verify only with the library that produced the signature | ⚠️ | Partly satisfied in code: validation uses an independently built validation context, refuses to trust certificates embedded in the document, re-reads `/Location` out of the sealer's own output, and `sealed_pages_match_final_revision` compares the sealed pages against the signed revision by resolving and digesting every page resource — none of which takes the sealer's word for anything. But it is still pyHanko reading pyHanko's output. **Acrobat is the independent reader**, and it is manual | `tests/verification/test_report.py::test_a_swapped_signature_image_inside_the_seal_is_reported`, `::test_a_seal_made_for_one_envelope_does_not_verify_against_another` |
| DO test the unhappy paths: decline, void, expiry, session timeout mid-signing, second signer after first, KMS or timestamp outage | ✅ | All six, end to end | `tests/e2e/test_endings.py` (decline, void, expiry, supersede); `tests/e2e/test_idempotency_and_outages.py` (KMS and TSA outages); `tests/envelopes/test_ordering.py` (second signer, and a parallel signer whose document moved); `frontend/src/App.test.tsx` "a session that lapses mid-flow is caught wherever it happens" |
| DON'T fail open; hold as pending and retry; never show a document as complete until it is sealed and stored | ✅ | See DoD #11. `GET /signing/copy` answers `202 {"status":"sealing"}` rather than an unsealed file; the host's `document` route answers `409 not_sealed`; a seal that does not validate is discarded | `tests/envelopes/test_views_and_downloads.py::test_the_copy_is_only_ever_the_sealed_document`; `tests/envelopes/test_evidence_guards.py::test_a_broken_chain_records_the_failure_and_backs_the_job_off` |

### 2.10 Process and licensing

| Rule | Status | Where |
|---|---|---|
| DO have counsel review the consent wording, the certificate of completion and the document type list | 🔵 | Not done. §7 |
| DON'T decide for yourself which document types may be signed electronically | ✅ | `APPROVED_DOCUMENT_TYPES` is configuration, and an unapproved type cannot produce an envelope however many templates exist (`document_type_not_approved`). The list itself needs compliance's sign-off (§7) |
| DO write an internal note on how our signatures work and how to verify one | ✅ | `docs/HOW-SIGNATURES-WORK.md` |
| DON'T leave verification knowledge in one engineer's head | ✅ | The note, the CLI (`esign verify`), the API route, the button in the demo host's chart view, and a hand-verification procedure that uses none of our code |
| DO read DocuSeal, Documenso and OpenSign for ideas | — | Informational |
| DON'T copy code from them (all three are AGPL) | ✅ | No code was copied, and none of the three is a dependency. The declared dependencies in `backend/pyproject.toml` and `frontend/package.json` are permissive or LGPL — the signing stack is pyHanko (MIT), pypdf (BSD), reportlab (BSD) and Pillow (MIT-CMU) — with no AGPL package among them. A transitive licence audit is worth running once before launch |

---

### 2.11 Addendum 1 (`docs/SPEC-ADDENDUM-1.md`)

Three features that each weaken one of the rules above in a stated way. What contains each one,
and what proves the containment holds:

| Feature | What it weakens | Status | Where | Proof |
|---|---|---|---|---|
| Paper archives: a scan of an ink-signed document gets the same storage, seal, trail and verification | Nothing about electronic signatures. The seal proves the scan is unchanged since filing and who attested, *not* that the ink is genuine, and the cover page and certificate say so | ✅ | `archives/service.py`; `documents/archive_cover.py`; `api/archive_routes.py`; `verification/__init__.py` (revision 1 is the `scan`) | `tests/archives/test_filing.py`, `test_hygiene.py`, `test_no_phi.py` (paper signers' names never reach audit data), `test_verification.py::test_a_swapped_scan_is_caught`; `tests/e2e/test_addendum_stories.py::test_a_paper_document_is_filed_sealed_and_verified_and_a_swapped_scan_is_caught` |
| Saved signatures: a signer keeps the signature they adopted for their next session | "Adopt once per session". Contained: only the signer creates one, inside their own live non-kiosk session, after a signature succeeded; applying it is still per field; the trail and certificate say a saved one was used; either side can revoke; never on a kiosk | ✅ | `identity/adopted.py`; `envelopes/service.py::_resolve_adopted`; `api/adopted.py`; `frontend/src/flow/steps/AdoptSignature.tsx` | `tests/adopted_signatures/` (offered, applying, saving, revoking, identity rules); `tests/e2e/test_addendum_stories.py::test_a_clinician_saves_a_signature_on_one_order_and_uses_it_on_the_next`, `::test_a_host_revoke_removes_the_saved_signature_from_the_next_session`; `frontend/e2e/demo/addendum.spec.ts` |
| Re-authentication span: one attestation covers a clinician's queue | DoD #2's per-document re-authentication. Contained: off by default, capped at 900 s and at `REAUTH_MAX_AGE_SECONDS`, each document still reviewed, consented and signed on its own, `signer.signed` records the attestation id, `reauth_scope` and age, the certificate prints them, verification checks the row | ⚠️ | `identity/service.py::fresh_reauth`; `envelopes/service.py::sign`; `documents/certificate.py`; `verification/__init__.py::_check_reauth_attestations` | `tests/reauth_span/` (resolution, evidence, the signing queue); `tests/e2e/test_addendum_stories.py::test_a_queue_is_confirmed_once_and_the_third_document_is_refused_after_the_span_lapses`. ⚠️ because turning it on is a compliance decision (§7): the demo does, production should not without agreement |

## 3. Audit event minimum fields (guide §6)

Every field the guide asks for, with the column that holds it. The full definition — canonical
encoding and a worked test vector — is in `docs/HOW-SIGNATURES-WORK.md` §3 and
`backend/src/esign/audit/README.md`.

| Guide field | Our column | Notes |
|---|---|---|
| `event_id`, `sequence` | `id`, `sequence` | Monotonic per stream, gapless, serialised by an advisory lock |
| `document_id`, `template_id`, `template_version` | `stream_id`; `envelope.created.data.template_key` / `template_version` / `template_version_id` | The stream *is* the document; the template identity is on the creation event, and verification checks the row still agrees with it |
| `event_type` | `event_type` | 23 types, covering all ten the guide names |
| `actor_user_id`, `actor_role`, `capacity`, `on_behalf_of` | `actor_user_id`, `actor_role`, `actor_capacity`, `on_behalf_of` | All four are top-level hashed columns |
| `auth_method` | `auth_method`, plus `session.created.data.auth_method` and `auth_time` | |
| `occurred_at` | `occurred_at` | Server `Clock`, UTC, six fractional digits, never from a client |
| `ip_address`, `user_agent` | `ip`, `user_agent` | Server-side, honouring `TRUSTED_PROXY_CIDRS`; the user agent is truncated to 512 characters *before* hashing |
| `document_sha256` | `document_sha256` | The presented bytes, or the sealed bytes on `document.sealed` |
| `consent_text_version` | `consent.accepted.data.consent_version` | With the text id, the locale and the body hash |
| `prev_event_hash`, `event_hash` | `prev_event_hash`, `event_hash` | `SHA-256` over the canonical JSON of the other seventeen columns |

`tests/audit/test_append.py::test_the_hashed_field_list_is_exactly_the_stored_columns_minus_the_hash`
proves nothing can be added to the table without entering the hash.

---

## 4. Stop and escalate (guide §5)

These are not engineering decisions. The service refuses each of them rather than approximating.

| Case | How it is handled |
|---|---|
| **Controlled-substance prescriptions** | Out of scope by design. Not an approved document type, and no template exists. A DEA-compliant EPCS flow needs a certified application and two-factor signing; we integrate a certified vendor and never build it |
| **Witness or notary requirements** | Witnesses *are* modelled (capacity `witness`, sequential ordering, the procedure-consent sample uses one). Whether a witness is legally sufficient for a given document type in a given state is 🔵 counsel's call, per document type and per state. Notarisation is out of scope |
| **Non-US signers** | Out of scope. eIDAS may require an advanced or qualified signature, which needs a trust service provider. Nothing here claims to produce one |
| **New document types** | 🔵 Compliance first, always. Enforced mechanically: `APPROVED_DOCUMENT_TYPES` gates envelope creation (`document_type_not_approved`), so adding a template is not enough |

---

## 5. What the code does beyond the guide

Not requirements, but worth knowing when someone asks how defensible the record is:

- **Verification is itself recorded.** `verification.performed` carries the outcome, so the trail
  shows who checked and what they found.
- **The certificate of completion is built from the trail, not the rows**, and a disagreement
  between the two stops the seal (`certificate_evidence_mismatch`) rather than being certified.
- **The seal is bound to its envelope** (`/Location = envelope:<id>`), and both the sealer and the
  verifier read it back.
- **The certificate's head hash is checked twice**: against the chain as it stands, and by looking
  for it in the text of the sealed pages.
- **Signing refuses a revision the signer has not seen** — not just "has not viewed *something*",
  but "the bytes you read are still the current revision" (409 `not_viewed`).
- **The raw ink is evidence too.** The drawn PNG and the typed text are hashed into `signer.signed`
  and stored append-only, so a swapped signature image is a finding, not a silent substitution.
- **Refusals are recorded.** `session.rejected` and `seal.failed` are written in their own committed
  transactions, because the failing request's transaction is rolled back and the refusal still
  matters.
- **Out-of-scope requests get a named refusal** rather than a 404 that looks like a bug.

---

## 6. Gaps, honestly

Everything marked ⚠️ above, in one place, with what would close it.

| # | Gap | Impact | To close |
|---|---|---|---|
| G1 | **No Adobe Acrobat validation in CI.** DoD #5 and the "don't verify only with the library that produced the signature" rule both want an independent reader. Our validator is careful and independent *in construction*, but it is still pyHanko | Medium. A pyHanko-specific bug could produce a file that we accept and Acrobat rejects — the worst possible failure, because it surfaces in front of a patient's lawyer | Manual step in the launch checklist and after any change to `sealing/`. A CI job could at least add a second independent implementation; there is no headless Acrobat |
| G2 | **The rate limiter is per process.** `SlidingWindowRateLimiter` holds counters in memory and does not share them between replicas, so N API replicas allow N times the documented limit | Low–medium. It exists to slow guessing, not to meter traffic, and a 256-bit token is not guessable at any of these rates | A shared limiter (Redis), or an edge rate limiter in front of the service. Noted in `docs/RUNBOOK.md` §7 |
| G3 | **No alerting ships with the service.** The guide says "rate-limit **and alert** on the signing and re-authentication endpoints" | Medium. A seal backlog that nobody watches is a silent outage: signatures are taken and nothing completes | Wire the queries and thresholds in `docs/RUNBOOK.md` §3 into your monitoring. The signals exist (structured logs, `seal_jobs`, `seal.failed` events, `/healthz`) |
| G4 | **No automated accessibility audit.** ARIA and focus management are present and covered by component tests, but nothing runs axe or equivalent | Medium. A patient on a tablet in a clinic is exactly the user who suffers, and this is a flow people cannot skip | Add `@axe-core/playwright` to the existing Playwright run, and one manual screen-reader pass per release |
| G5 | **Session tokens are not single-use.** Short-lived (30 min), bound to one signer and one envelope, never in a URL, hashed at rest, revoked by a new session and by signing — but usable for the whole flow | Low. The guide's rule is aimed at emailed signing links, which do not exist here | Nothing, unless the threat model changes. It is documented rather than quietly ticked |
| G6 | **Retention figures are not set.** The mechanism is complete; `RETENTION_YEARS_BY_DOCUMENT_TYPE` is empty and the 10-year default floor applies to everything | High, and it is a **compliance** gap rather than a code one. Minors' records often need "until majority plus N years", which is longer than 10 and not expressible as a fixed number of years from signing | Compliance supplies the table; set the configuration. If a duration cannot be expressed as years-from-signing, that needs a design conversation before launch, not after |
| G7 | **Encryption in transit and database-at-rest are deployment concerns**, not code | Low, provided the runbook is followed | `docs/RUNBOOK.md` §1. Verify at deployment, not by reading this repository |
| G8 | **Shared logins at the host** are outside what this service can see | Medium, and it is the EHR's to answer | Raise in the integration review with each host. The service records `host_user_id` on every event, so a shared account is at least *visible* in the trail afterwards |
| G9 | **`esign` has no subcommand for rotating a webhook secret or disabling a host.** `rotate_webhook_secret` and `disable_host` exist in `esign.identity` and are tested, but reaching them in an incident means a Python one-liner | Low, but it is friction at exactly the wrong moment | Add `esign hosts rotate-webhook-secret` and `esign hosts disable`. The one-liners are in `docs/RUNBOOK.md` §6.7 in the meantime |
| G10 | **`backend/src/esign/sealing/README.md` is out of date** in its last "Known limits" bullet: it says `SealValidation.ok` "is computed from four booleans and ignores `problems`". That stopped being true when `ok` gained `and not self.problems` (SPEC §13, second round), and `sealer.py`'s own comment says so | Low, but it is a documentation defect in exactly the file a reviewer reads to decide whether the validator fails closed — and it understates the code | One-line correction to that bullet. Flagged rather than changed here because that file is the sealing module's, not this documentation set's |

None of these is a correctness bug in the evidence path. G6 is the one that should block launch.

---

## 7. For counsel and compliance, not for code

No engineering work will close any of these. Each needs a named owner and a recorded decision
before launch.

| # | Item | Owner | Why it cannot be code |
|---|---|---|---|
| C1 | **Approve the ESIGN disclosure wording.** `identity/consent/en-US.2026-09.txt` and `en-US.2026-10.txt`. Consent texts are immutable and versioned, so an approved version stays exactly as approved, and a new one is a new version | Counsel | It is the legal text that makes consent effective |
| C2 | **Approve the certificate of completion.** What it says, what it prints about each signer, and the "how to verify" paragraph. It travels with the document wherever the document goes | Counsel | It is the page a court reads |
| C3 | **Approve `APPROVED_DOCUMENT_TYPES`.** Today: `patient_consent`, `hipaa_acknowledgement`, `procedure_consent`, `clinical_order`. The list also decides which document types may be filed as paper archives | Compliance | The guide is explicit that engineers do not decide which document types may be signed electronically |
| C4 | **Supply the retention schedule** per document type, including the rule for minors (G6) | Compliance | Varies by state and by document type |
| C5 | **Rule on witnessing and notarisation** per document type and per state. The service models a witness; whether that is sufficient is a legal question | Counsel | State law |
| C6 | **Decide the certificate authority**, including whether to buy an AATL-member certificate so Acrobat shows a green tick rather than "validity unknown" to an outside reader. Options and costs are in `docs/RUNBOOK.md` §1.2 | Team lead + procurement | A purchasing decision the guide explicitly says to escalate |
| C7 | **Confirm no BAA is needed with the timestamp authority.** A TSA receives a hash and nothing else; the guide says this is fine, but the vendor should still be on the record | Compliance | Vendor management |
| C8 | **Confirm the identity-proofing story for kiosk sessions.** The service records which staff member started the session and how identity was checked (`photo_id`, `dob_and_name`, `known_to_staff`, `wristband`). Whether those methods are acceptable for a given document type is a policy question | Compliance | Clinic policy |
| C10 | **Decide whether a re-authentication span is acceptable, and for how long** (`REAUTH_SPAN_SECONDS`, §2.11). The service ships with it off: one re-authentication per document, as the guide asks. Turning it on lets a clinician sign a queue on one confirmation, with every signature recording which confirmation and how old; whether that trade is acceptable, and the window, is a policy decision. Both windows should be set together | Compliance | The guide's per-document rule is explicit, and this is a documented deviation from it |
| C9 | **Accept the one-seal-at-the-end design** (§2.4). It is a deliberate, documented deviation from the guide's "incremental update per signature" wording, taken so the certificate of completion can be inside the sealed bytes. Counsel should be comfortable with the explanation before the first dispute, not during it | Counsel + engineering | A judgement about what is defensible |

---

## 8. Re-checking this document

It is prose about code, so it can drift. When it matters:

```sh
make check                                    # the gate: every test cited here
cd backend && uv run pytest tests/e2e -q      # the end-to-end evidence tests
cd backend && uv run esign verify <id>        # a real document, end to end
```

The single most valuable recurring check is the weekly sample verification in `docs/RUNBOOK.md` §7:
five sealed envelopes, `esign verify` each. It exercises the seal, the blob store, the chain and
the certificate together, and it is how a slow corruption gets found before somebody in a
deposition finds it.
