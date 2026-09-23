# Runbook

Operating the e-signing service in production. Read `docs/HOW-SIGNATURES-WORK.md` first if you do
not already know what the evidence is; several procedures here exist to avoid damaging it.

The rule behind every page of this document: **nothing in this system deletes evidence, and no
procedure here should be the first thing that does.** There is no delete path in the code. If a
runbook step seems to need one, it is the wrong step.

## Contents

1. [Production setup](#1-production-setup)
2. [Certificate rotation and expiry](#2-certificate-rotation-and-expiry)
3. [Seal-job backlog and outages](#3-seal-job-backlog-and-outages)
4. [Retention](#4-retention)
5. [Backup and restore without breaking the chain](#5-backup-and-restore-without-breaking-the-chain)
6. [Incident checklists](#6-incident-checklists)
7. [Routine operations](#7-routine-operations)

---

## 1. Production setup

Four things have to exist before the service can seal anything: a signing key with a certificate, a
timestamp authority, a write-once bucket, and a database with two roles. Then the process has to be
told where the trusted proxies are, or every IP it records will be wrong.

`APP_ENV=prod` refuses to start unless most of this is in place. The check lives in
`esign.runtime.check_production_settings` and runs inside `build_runtime`, so the API, `esign
worker`, `esign verify` and every other command are gated identically — the worker is the process
that actually seals, and gating only the API would leave it sealing real documents with a dev key.

It refuses `APP_ENV=prod` with any of:

- `SEAL_PROFILE=PAdES-B-T` (production is `PAdES-B-LT` or `-B-LTA`)
- `SEAL_KEY_BACKEND` other than `aws_kms`, or `aws_kms` with no `SEAL_KMS_KEY_ID`, or a
  `SEAL_CERT_PATH` that is not a file
- `BLOB_BACKEND` other than `s3`
- a `TRUST_ROOTS_PATH` that does not exist
- an empty `TSA_URL`
- a `DATABASE_URL` or `DATABASE_OWNER_URL` still carrying the development passwords
- `DB_ECHO=true` (SQLAlchemy's echo logs bound parameters, which carry PHI)

And, in *any* environment: `BLOB_BACKEND=s3` with no `BLOB_S3_BUCKET`, `APP_ENV=dev` together with
`aws_kms` or `s3` (a deployment that forgot `APP_ENV`), and a malformed `TRUSTED_PROXY_CIDRS`.

### 1.1 The signing key

The key lives in AWS KMS and never leaves it. The service calls exactly one KMS operation,
`kms:Sign`, over the CMS signed attributes — a few hundred bytes. **No document bytes and no PHI
are ever sent to KMS.**

Create an asymmetric key for signing. Supported specs, and nothing else is accepted rather than
approximated:

| KMS key spec | Signing algorithm used |
|---|---|
| `RSA_2048`, `RSA_3072`, `RSA_4096` | `RSASSA_PKCS1_V1_5_SHA_256` |
| `ECC_NIST_P256` | `ECDSA_SHA_256` |

```sh
aws kms create-key \
  --key-usage SIGN_VERIFY \
  --key-spec RSA_3072 \
  --description "esign document seal (production)" \
  --tags TagKey=service,TagValue=esign TagKey=purpose,TagValue=document-seal
aws kms create-alias --alias-name alias/esign-seal-2026 --target-key-id <key id>
```

Alias each key by the year you started using it. Rotation is a *new key*, not AWS's automatic
material rotation — automatic rotation would change the key under a certificate that names the old
public key, and every seal would stop validating. **Disable automatic key rotation on this key.**

The service's IAM role needs only:

```json
{"Effect": "Allow", "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"],
 "Resource": "arn:aws:kms:<region>:<account>:key/<key id>"}
```

`kms:Decrypt` and `kms:ScheduleKeyDeletion` are not needed and should not be granted. Set a key
policy that denies `kms:ScheduleKeyDeletion` to everyone except a break-glass role: deleting this
key destroys nothing already sealed, but it makes future rotation and investigation harder, and
there is no reason for it to be an easy action.

### 1.2 The certificate

KMS holds the key; the certificate that describes it is a file. You need three:

| Setting | File |
|---|---|
| `SEAL_CERT_PATH` | the seal certificate itself. Exactly one certificate, PEM. The service refuses a bundle here |
| `SEAL_CHAIN_PATH` | the intermediates, PEM, in order. Not the root |
| `TRUST_ROOTS_PATH` | the root(s) `validate` is allowed to trust. **This file is the entire trust decision.** A certificate embedded in a PDF never counts |

Get a CSR for the KMS key — KMS does not produce one, so build it from the public key and sign it
with `kms:Sign`:

```sh
aws kms get-public-key --key-id alias/esign-seal-2026 --output text --query PublicKey \
  | base64 --decode > seal-2026.pub.der
```

Then have your CA (or a tool like `aws-kms-sign-csr`) produce a CSR whose signature comes from
`kms:Sign`, with:

- **Key usage**: `digitalSignature` and `nonRepudiation` (content commitment). Not `keyEncipherment`.
- **Extended key usage**: document signing. For an organisational seal, `id-kp-documentSigning`
  (`1.3.6.1.5.5.7.3.36`) if your CA supports it; `emailProtection` is the older convention some CAs
  still require for Adobe compatibility. Ask the CA which they issue.
- **Subject**: the legal entity, not a person and not a hostname. This string appears in Acrobat's
  signature panel and on nothing else, so make it the name a court would recognise.
- **Validity**: 2–3 years is typical. Longer is not better; see rotation below.

#### Choosing a CA: three options

| Option | What Acrobat shows | Cost and effort | When it is right |
|---|---|---|---|
| **Your own internal CA** | "Signature is valid, but the signer's identity is unknown" until the recipient adds your root | Free; you run the CA | Documents that stay inside the organisation, where you can distribute the root by policy |
| **A public code/document-signing CA** (DigiCert, Sectigo, GlobalSign, Entrust) | Depends on whether that CA is in the Adobe Approved Trust List | A few hundred to a couple of thousand dollars a year; identity vetting takes days to weeks | The usual answer |
| **An AATL member certificate** | "Signed and all signatures are valid" with a green tick, on any stock Acrobat install | The most expensive tier; the CA will usually require the key to be in an HSM or a KMS they will attest to, and will ask for evidence of that | Documents that leave the organisation and will be opened by patients, lawyers or other institutions who have never heard of you |

**The AATL question is a purchasing decision, not an engineering one.** Raise it with the team lead
and with compliance before launch. The developer guide is explicit that a self-signed certificate
is tamper-evident but shows as *validity unknown*, and "validity unknown" is what a patient's
solicitor will screenshot. Nothing in the code changes between these options: it is the same
`SEAL_CERT_PATH`, `SEAL_CHAIN_PATH` and `TRUST_ROOTS_PATH`.

Whichever you choose, confirm with the CA that they will issue against a key held in AWS KMS
(most will; some require an HSM they can attest to, which means CloudHSM rather than KMS). That
question decides the key backend, so ask it first.

`TRUST_ROOTS_PATH` should contain the root your seal certificate chains to, and nothing else you do
not intend to trust. It is the only input to the `trusted` verdict. If the file is missing or empty,
every document validates as `trust_roots_unavailable` — fail closed, never "trust whatever is in the
file".

### 1.3 The timestamp authority

`TSA_URL` names an RFC 3161 authority over HTTP. **It is required in production**: with no TSA the
service refuses to seal (`tsa_not_configured`) and the envelope stays pending. The in-process dummy
authority is reachable only from a non-production environment running on the local dev key, or from
`APP_ENV=test`.

The timestamp is not optional decoration. Retention is ten years and a signing certificate is not:
validation is done at the moment the TSA attested, read from the document, so a seal keeps
validating after its certificate expires. Without a trusted timestamp there is no such moment.

Choose an authority whose own certificate chains to something you will still trust in a decade —
in practice, the same CA that issues your seal certificate, or a dedicated TSA service (DigiCert,
Sectigo, GlobalSign and FreeTSA all run one). Points to check:

- **It must be in `TRUST_ROOTS_PATH`'s reach.** A timestamp whose TSA chain does not validate is
  `timestamp_invalid`, which fails the seal.
- **A BAA is not required.** A timestamp authority receives a hash and nothing else. This is worth
  writing down because "no third party without a BAA" is otherwise an absolute rule, and the
  developer guide calls out this exact exception.
- **Availability matters more than latency.** A TSA outage is not a data-loss event — envelopes sit
  in `completed_pending_seal` and retry — but it does mean nothing completes. Check whether the
  vendor publishes an SLA and whether they support a second endpoint.

Set `TSA_TIMEOUT_SECONDS` a little above the authority's p99 (the default is 10). A timeout raises
`SealUnavailable` and backs the job off; it never produces an untimestamped seal.

### 1.4 The S3 bucket

**Object Lock can only be enabled when a bucket is created.** You cannot add it later. Getting this
wrong means creating a second bucket and copying, which is exactly the kind of evidence-handling
exercise this section exists to avoid.

```sh
aws s3api create-bucket --bucket esign-evidence-prod --region <region> \
  --object-lock-enabled-for-bucket   # not retroactive; only at creation

aws s3api put-bucket-versioning --bucket esign-evidence-prod \
  --versioning-configuration Status=Enabled            # required by Object Lock

aws s3api put-bucket-encryption --bucket esign-evidence-prod \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms",
     "KMSMasterKeyID":"<storage kms key arn>"},"BucketKeyEnabled":true}]}'

aws s3api put-public-access-block --bucket esign-evidence-prod \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

Use a **separate** KMS key for storage encryption from the one that signs. They have different
lifecycles: the storage key must survive as long as the retention schedule, and the signing key
gets rotated every couple of years.

Keep `BLOB_S3_SSE` consistent with the bucket default. The service sends
`ServerSideEncryption` on every put — `AES256`, or `aws:kms` with `BLOB_S3_SSE_KMS_KEY_ID` — and the
per-request header wins over the bucket default, so a bucket configured for `aws:kms` and a service
configured for `AES256` will quietly store objects under S3-managed keys.

Do **not** set a default bucket retention period. The service passes an explicit
`ObjectLockRetainUntilDate` on every object, computed per document type from
`RETENTION_YEARS_BY_DOCUMENT_TYPE`, so a bucket default would be both redundant and a second source
of truth that can silently disagree.

`BLOB_S3_OBJECT_LOCK_MODE` defaults to `COMPLIANCE`: nobody, including the root account, can shorten
or bypass the retention until the date. `GOVERNANCE` leaves an escape hatch for holders of
`s3:BypassGovernanceRetention`. Choosing `GOVERNANCE` is a compliance decision that should be
written down with a reason, not a convenience.

Lifecycle rules: **none that expire or transition current object versions.** If you want cost
relief, a transition to `GLACIER_IR` after a year is defensible for `sealed_pdf` objects, provided
retrieval is tested — but remember `esign verify` reads the bytes back, so a deep-archive class
turns verification into a multi-hour job. Start with Standard-IA after 90 days and measure.

The service's IAM role needs exactly the operations it calls:

```json
{"Effect": "Allow",
 "Action": ["s3:PutObject", "s3:GetObject", "s3:PutObjectRetention", "s3:GetObjectRetention"],
 "Resource": "arn:aws:s3:::esign-evidence-prod/esign/*"}
```

No `s3:DeleteObject`. No `s3:DeleteObjectVersion`. No `s3:BypassGovernanceRetention`. There is no
code path that calls them, and the absence of the grant is the second line of defence.

Every put also carries `IfNoneMatch: *` (so an existing key is never replaced — S3 answers 412 and
the service confirms the existing content is identical), a `ChecksumSHA256` S3 verifies for itself,
and the server-side encryption you configured.

If you want a real bucket to poke at locally, `docker compose --profile minio up -d` brings up MinIO
on :9100; point `BLOB_S3_ENDPOINT_URL` at it.

### 1.5 The database

Two roles. Create them out of band, with real credentials, **before** running migrations; migration
`0002_roles.sql` creates them with development passwords only if they do not already exist, and
leaves them alone if they do.

```sql
CREATE ROLE esign_owner LOGIN PASSWORD '<from your secret manager>';
CREATE ROLE esign_app   LOGIN PASSWORD '<a different one>';
CREATE DATABASE esign OWNER esign_owner;
```

| Role | Used by | Privileges |
|---|---|---|
| `esign_owner` | `esign migrate` only | owns every object; runs DDL |
| `esign_app` | every running process | `SELECT, INSERT` on `audit_events`, `blobs`, `document_revisions`, `consent_texts`, `reauth_attestations`, `signature_captures`; `SELECT, INSERT, UPDATE` on `adopted_signatures`, where the only permitted `UPDATE` is the one revocation (below), and on the ordinary working tables; `DELETE` on `idempotency_keys` alone; no DDL, no `TRUNCATE` |

The grants are the first line of defence. Database triggers are the second: `BEFORE UPDATE OR
DELETE` and `BEFORE TRUNCATE` on every append-only table, which stop even the owner role. Both
are tested (`tests/foundation/test_roles.py`, `tests/audit/test_roles.py`,
`tests/storage/test_roles.py`).

`adopted_signatures` (the saved signatures of Addendum 1 B) is the one table with a narrower rule
rather than a flat refusal, and its trigger states it: a row may be updated exactly once, to set
`revoked_at` *and* `revoke_reason` together; a revoked row is immutable; no column other than those
two may ever change; `DELETE` and `TRUNCATE` are refused outright. That is deliberate — a
`signature_captures` row may point at a saved signature, so removing one would orphan evidence
inside a sealed document. Both layers are tested directly — the grants in
`tests/foundation/test_roles.py`, the trigger case by case in
`tests/adopted_signatures/test_write_once.py` (a revocation with no reason, a revocation that also
rewrites the signature, a second revocation or an un-revocation, and the owner's `DELETE`). If you
are auditing the database rules rather than the service, try a `DELETE` on a throwaway row
yourself and expect both layers to refuse it:

```
esign_app=>   DELETE FROM adopted_signatures WHERE id = '…';
ERROR:  permission denied for table adopted_signatures
esign_owner=> DELETE FROM adopted_signatures WHERE id = '…';
ERROR:  DELETE on adopted_signatures is forbidden: rows are revoked, never removed
```

Then:

```sh
DATABASE_OWNER_URL=... uv --directory backend run esign migrate --dry-run   # what would run
DATABASE_OWNER_URL=... uv --directory backend run esign migrate
DATABASE_OWNER_URL=... uv --directory backend run esign migrate --status
```

Migrations take a Postgres advisory lock, run each file in its own transaction with the row that
records it, and store a checksum of every applied file. Editing a migration that has already run is
**refused**, not silently re-applied.

Seed the disclosure and register each EHR:

```sh
uv --directory backend run esign consent add --default
uv --directory backend run esign hosts create \
  --name "Riverside Clinic" \
  --origin https://ehr.riverside.example \
  --webhook-url https://ehr.riverside.example/webhooks/esign
```

The API key and webhook secret are printed **once** and stored only as hashes. Put them into the
host's secret manager at that moment; there is no recovery, only `esign hosts rotate-key`.

Webhook URLs must be `https` except for loopback addresses.

### 1.6 Trusted proxies

`TRUSTED_PROXY_CIDRS` is the list of peer addresses whose `X-Forwarded-For` the service believes.
Everything else uses the socket's peer address.

This is evidence configuration, not plumbing. The IP recorded in `signer.signed` is printed on the
certificate of completion and is part of the attribution story. Get it wrong in one direction and
every signature is attributed to your load balancer's address; get it wrong in the other and a
client can assert any address it likes.

```sh
TRUSTED_PROXY_CIDRS=10.0.0.0/8,172.31.0.0/16     # your ALB/NLB subnets. Never 0.0.0.0/0
```

The value is parsed at startup and a malformed entry refuses to start, because a typo would
silently change every recorded address rather than fail.

`esign serve` deliberately does **not** let uvicorn rewrite the peer address (`proxy_headers=False`):
the check has to be made against this list, by the application, or it is looking at the wrong thing.

### 1.7 Processes

| Process | Command | Notes |
|---|---|---|
| API | `esign serve --host 0.0.0.0 --port 8000` | any number of replicas. Always through `esign serve`, never uvicorn directly — it is the one place uvicorn's own log config is dropped, so nothing writes outside the allowlisted structured logger |
| Worker | `esign worker` | any number. Jobs are claimed with `FOR UPDATE SKIP LOCKED`; the envelope row lock means two workers holding the same job still seal once. **At least one must always be running** |

Both go through `build_runtime`, so both enforce the production settings check.

Terminate TLS in front of the API. `Strict-Transport-Security` is set automatically when
`APP_ENV=prod`.

Health check: `GET /healthz` returns 200 `{"status": "ok"}`, or 503 `{"status": "degraded"}` when
the database does not answer. It touches nothing else, so it is safe to poll.

Logs are JSON whenever `APP_ENV` is not `dev`, and every field goes through an allowlist: an
unlisted key is dropped before rendering and the drop is itself reported, so a mistake is visible
rather than silent. Request and response bodies are never logged; the access line carries the
*route template* (`/v1/envelopes/{envelope_id}`), never the real path or query string.

### 1.8 Launch checklist

- [ ] `esign verify` run against a document sealed by the production stack: `RESULT: verified`
- [ ] That document opened in **Adobe Acrobat**: one certification signature, "no changes
      permitted", timestamp trusted. Screenshot it and keep it
- [ ] `document.sealed` records the profile you configured (`PAdES-B-LT` or better) and the
      certificate fingerprint you expect
- [ ] A one-byte change to a copy of that file makes both `esign verify` and Acrobat fail
- [ ] The application role cannot `UPDATE` or `DELETE` an audit event (try it)
- [ ] An object in the bucket shows a retain-until date years out, and `aws s3api delete-object`
      on it is refused
- [ ] `TRUSTED_PROXY_CIDRS` is right: a test signature records the client's address, not the
      balancer's
- [ ] A webhook arrives at the host, its HMAC verifies, and the host filed the sealed PDF
- [ ] Counsel has approved the consent wording, the certificate of completion and
      `APPROVED_DOCUMENT_TYPES` (see `docs/COMPLIANCE-CHECKLIST.md`)
- [ ] `REAUTH_SPAN_SECONDS` is `0`, or compliance has recorded a decision to turn it on and
      `REAUTH_MAX_AGE_SECONDS` was set with it (§7, "The re-authentication span")
- [ ] `CONSENT_SPAN_SECONDS` is `0`, or compliance has recorded a decision to turn it on and the
      window is the length of a sitting, not of a shift (§7, "The consent span")
- [ ] If paper archives will be filed: the records rule for the scanned **originals** is written
      down and matches the `original_disposition` values staff will send (§4, C11)

---

## 2. Certificate rotation and expiry

### What rotation is, and is not

Rotating means: **a new KMS key, a new certificate for it, and a configuration change.** Every
document sealed with the old key keeps validating, because validation is point-in-time against the
embedded RFC 3161 timestamp and the old root stays in `TRUST_ROOTS_PATH`.

Rotating does **not** mean re-sealing anything. There is no re-seal path and there should not be:
a second seal over the same document would be a new document with a different hash, and the old
one's audit trail says what it says.

### When

| Trigger | Lead time |
|---|---|
| Certificate expiry | start 90 days out; complete 30 days before |
| Key compromise | immediately — see [6.2](#62-the-signing-key-is-compromised) |
| CA changes (moving to AATL, changing vendor) | treat as an expiry rotation |
| Algorithm deprecation | as advised |

Put the expiry date of `SEAL_CERT_PATH` in the on-call calendar the day you install it. Nothing in
the service watches it. A certificate that expires while in use does not corrupt anything — the
seal fails to validate at signing time and `_confirm_seal` refuses, so envelopes pile up in
`completed_pending_seal` — but it is an avoidable outage.

```sh
openssl x509 -in /etc/esign/seal.pem -noout -subject -enddate -fingerprint -sha256
```

### Procedure

1. **New key.** `aws kms create-key --key-usage SIGN_VERIFY --key-spec RSA_3072`, alias
   `alias/esign-seal-<year>`. Do not touch the old key.
2. **New certificate** from the CA, against the new key's public key (section 1.2). Same subject,
   same key usage.
3. **Stage the files.** Put `seal-<year>.pem` and `chain-<year>.pem` next to the current ones.
4. **Extend the trust roots, do not replace them.** If the new certificate chains to a different
   root, append it:
   ```sh
   cat trust-roots.pem new-root.pem > trust-roots.new.pem
   openssl crl2pkcs7 -nocrl -certfile trust-roots.new.pem | openssl pkcs7 -print_certs -noout
   mv trust-roots.new.pem trust-roots.pem
   ```
   **Removing the old root is what breaks history.** Every document sealed under it becomes
   `untrusted_chain` on the next verification. The old root stays in this file until the last
   document sealed under it is past its retention — which for a ten-year schedule means at least
   ten years after the last seal.
5. **Verify before cutting over.** In a staging environment pointed at the new key, seal a document
   and run `esign verify` and Acrobat against it.
6. **Cut over.** Change `SEAL_KMS_KEY_ID`, `SEAL_CERT_PATH` and `SEAL_CHAIN_PATH`; restart the
   workers first, then the API. Sealing is idempotent at the job level: an envelope mid-attempt
   during the restart simply retries.
7. **Confirm.** Seal one real envelope and check `document.sealed.signer_cert_sha256` is the new
   fingerprint:
   ```sh
   psql -At -c "SELECT data->>'signer_cert_sha256', data->>'seal_profile', occurred_at
                FROM audit_events WHERE event_type = 'document.sealed'
                ORDER BY occurred_at DESC LIMIT 5"
   ```
8. **Re-verify a sample of old documents.** Pick a handful sealed under the previous key and run
   `esign verify` on each. They must still pass. If they do not, the trust roots were replaced
   rather than extended — go back to step 4.
9. **Keep the old key, disabled, not deleted.** `aws kms disable-key --key-id <old>`. Disabling
   prevents new signatures; deleting destroys your ability to answer questions about the old ones.
10. **Write the date, the fingerprints and the reason** in the change record.

### Revocation data and long-term validity

At `PAdES-B-LT` the seal embeds the revocation information needed to validate it, in the document's
own security store, at the moment it is sealed. Validation reads that store under `hard-fail`:
revocation must be decidable from what the document carries, or the result is `revocation_unknown`
and the document fails.

Consequences worth understanding:

- **Sealing needs the CA's CRL or OCSP responder reachable.** If it is not, sealing fails with
  `SealUnavailable` and the envelope stays pending. That is deliberate: the alternative is a file
  claiming to be `B-LT` with an empty store.
- **What the seal cannot see is a revocation published after it was written.** That is an
  operational control, not a cryptographic one: if a certificate is revoked, you know which
  documents were sealed under it from `document.sealed.signer_cert_sha256`, and section 6.2 tells
  you what to do about them.
- `PAdES-B-LTA` additionally embeds an archive timestamp, which extends validity past the point
  where the *signature* algorithms weaken. Consider it if documents must stand for more than ten
  years. It costs one extra TSA round trip per seal.

---

## 3. Seal-job backlog and outages

### How it behaves

When the last signer signs, the envelope becomes `completed_pending_seal` and a `seal_jobs` row is
written **in the same transaction**. One sealing attempt is then made inline, after that commit and
in a transaction of its own. If it fails, the worker retries.

Every failure — retryable or not — does the same three things: the envelope stays
`completed_pending_seal`, `seal.failed` is recorded with an error code (in a separate, committed
transaction, because the failed attempt's own transaction is rolled back), and the job backs off.

```
attempt 1 fails → 1m → 2 fails → 5m → 3 fails → 15m → 4 fails → 1h → hourly thereafter
```

Nothing anywhere reports the document as complete in the meantime. The signer's `GET /signing/copy`
answers `202 {"status": "sealing"}`; the host's `GET /v1/envelopes/{id}/document` answers `409
not_sealed`; the `envelope.completed` webhook has fired but `envelope.sealed` has not.

**An envelope waiting for its seal cannot be voided.** Every signer has signed; the honest states
are "sealed" or "still trying". There is no operator action that turns a fully signed document into
a cancelled one, and adding one would be a serious mistake.

### Watching for a backlog

```sql
-- pending work, oldest first
SELECT e.id, e.completed_at, j.attempts, j.last_error_code, j.next_attempt_at, j.locked_at
FROM envelopes e JOIN seal_jobs j ON j.envelope_id = e.id
WHERE e.status = 'completed_pending_seal' AND j.completed_at IS NULL
ORDER BY e.completed_at;

-- failures in the last hour, by reason
SELECT data->>'error_code' AS code, count(*)
FROM audit_events
WHERE event_type = 'seal.failed' AND occurred_at > now() - interval '1 hour'
GROUP BY 1 ORDER BY 2 DESC;
```

Alert on:

| Condition | Severity | Means |
|---|---|---|
| any envelope `completed_pending_seal` for more than 15 minutes | page | signatures are being taken and nothing is completing |
| `seal.failed` rate above zero for 10 minutes | page | a dependency is down |
| `attempts >= 5` on any job | page | it is now retrying hourly; someone must look |
| `error_code` = `integrity_failure`, `audit_chain_broken`, `certificate_evidence_mismatch`, `seal_validation_failed` | page immediately | **no retry will fix this.** Section 6.3 |
| no `worker.tick` log line for 5 minutes | page | the worker is dead |
| `webhook.failed` with `attempts >= 6` | ticket | a host endpoint is down |

### The error codes, and what to do

| `seal.failed.error_code` | Cause | Action |
|---|---|---|
| `seal_unavailable` | KMS unreachable, throttled, key disabled, permissions denied; or the TSA did not answer | Check KMS and the TSA. It retries by itself |
| `seal_key_unavailable` | `SEAL_CERT_PATH` missing or unreadable, no `SEAL_KMS_KEY_ID`, an unsupported key algorithm | Fix the configuration and restart. It retries |
| `tsa_not_configured` | `TSA_URL` empty in production, or a non-local key backend outside `APP_ENV=test` | Set `TSA_URL`. **Check `APP_ENV` is `prod`** — this code also means a deployment forgot it |
| `seal_profile_not_achieved` | The output did not have the structure the configured profile promises (missing DSS, missing timestamp) | Usually revocation data was unreachable. Check the CA's CRL/OCSP endpoints |
| `seal_validation_failed` | The sealer produced a document that its own validator rejects | **Not a transient.** Section 6.3 |
| `storage_unavailable` / `blob_store_unavailable` | S3 unreachable or refusing | Check the bucket, credentials and Object Lock configuration |
| `blob_corrupt` / `blob_missing` | A stored revision no longer matches its hash, or is gone | **Data loss.** Section 6.4 |
| `audit_chain_broken` | The envelope's audit chain does not verify, checked before anything is certified | **Section 6.5.** Nothing will be sealed around a false claim |
| `certificate_evidence_mismatch` | A mutable row disagrees with the append-only trail | Section 6.6 |
| `internal_error` | A bug | Get the traceback from the logs; the envelope is safe where it is |

### Draining a backlog after a fix

Nothing special. Once the dependency is back, workers pick jobs up on their own schedule — but a
long outage leaves jobs spread across hourly backoffs. To bring them forward:

```sql
-- pull every waiting job to now; the workers claim them within a tick
UPDATE seal_jobs SET next_attempt_at = now(), locked_at = NULL
WHERE completed_at IS NULL AND next_attempt_at > now();
```

That is the one routine write to `seal_jobs` an operator should ever make. It is safe: it changes
scheduling, not evidence, and the envelope row lock still means each envelope seals once. Watch the
backlog query drain. Scale workers horizontally if it is large — they coordinate by
`FOR UPDATE SKIP LOCKED`.

A single job can also be nudged with `esign worker --once`, which runs one tick and prints what it
did.

### A worker that died mid-attempt

The claim is a timestamp (`seal_jobs.locked_at`), not a held lock. A claim older than
`SEAL_JOB_LOCK_TIMEOUT_SECONDS` (default 600) is taken over by the next worker automatically. If
you know a host is gone and do not want to wait, clear its claims:

```sql
UPDATE seal_jobs SET locked_at = NULL WHERE completed_at IS NULL AND locked_at < now() - interval '10 minutes';
```

---

## 4. Retention

### How it is applied

Every blob is written with an explicit `retain_until`, computed as
`Settings.retain_until(document_type, now)`:

```
RETENTION_YEARS_BY_DOCUMENT_TYPE.get(document_type, DEFAULT_RETENTION_YEARS)  # default 10
```

measured in 365-day years, from the moment the blob is written. It is passed to the backend as the
S3 `ObjectLockRetainUntilDate`, which in `COMPLIANCE` mode nobody can shorten. A blob written
without an explicit date gets the configured floor, never "no retention".

This covers everything: the sealed PDF, every revision, the presented document, the template PDFs
and the raw signature images. Not just the final artefact.

**Retention is a floor, not a schedule.** The service never deletes anything when the date passes —
there is no delete path in the code, no `delete_object` call in the S3 backend, and no delete
method on `BlobService`. What the date does is stop *anyone else* deleting it before then.

### Setting the schedule

The figures are a compliance question, not an engineering one. They vary by state and by document
type, and are longer for minors — often "until the patient reaches majority plus N years", which is
not expressible as a fixed number of years from signing. Ask compliance for the table and configure
the longest applicable figure:

```sh
RETENTION_YEARS_BY_DOCUMENT_TYPE='{"procedure_consent": 25, "patient_consent": 10, "hipaa_acknowledgement": 7}'
DEFAULT_RETENTION_YEARS=10
```

Raising a figure applies to **new** blobs. For existing ones, the service pushes the retain-until
date further out when the same content is written again, but it never pulls one in. To extend
retention on already-stored objects you must do it deliberately in S3:

```sh
aws s3api put-object-retention --bucket esign-evidence-prod --key <key> \
  --retention '{"Mode":"COMPLIANCE","RetainUntilDate":"2051-01-01T00:00:00Z"}'
```

The `blobs` table keeps the date agreed at first write, because it is append-only. The backend holds
the effective one, and the backend is what actually resists deletion. Note that divergence when
auditing.

### Scans of paper-signed documents

A paper archive (`POST /v1/archives`) is retained exactly like anything else: the scan is a blob of
kind `scan_pdf`, written with `retain_until` from the schedule for its **document type**, and the
sealed output, the cover page and the certificate are inside the same regime. Nothing extra to
configure — but two things to decide, and neither is ours:

- **The document types that may be filed this way** are the same `APPROVED_DOCUMENT_TYPES` list,
  and a scan of anything else is refused (`document_type_not_approved`). Adding a type for paper
  filing is the procedure in §7, with the same compliance approval.
- **What happens to the paper original** is a records-management question this service only
  *records*. The host states one of `retained`, `returned_to_signer` or `destroyed_per_policy`, it
  is printed on the cover page and the certificate, and it is in `archive.attested` — but the
  service has no opinion on whether destroying an original after scanning is lawful for that
  document type in your state, and it cannot enforce one. Get that rule in writing before staff
  start sending `destroyed_per_policy` (`docs/COMPLIANCE-CHECKLIST.md` C11). Where the original is
  gone, the scan plus the attestation is the whole record.

### What must never touch this data

Write these into whatever governs your cleanup tooling, and check them when any of it changes:

- No S3 lifecycle expiration or noncurrent-version expiration on the evidence bucket or prefix.
- No account-deletion or right-to-erasure flow that reaches these objects or these tables. A
  signed consent is a medical record, not user-generated content.
- No database `DELETE` job against `audit_events`, `blobs`, `document_revisions`, `consent_texts`,
  `reauth_attestations`, `signature_captures` or `adopted_signatures`. The grants and triggers will
  refuse, which is the design, but the job should not exist to be refused. A saved signature is
  removed by *revoking* it, never by deleting the row (§6.9).
- The only routine deletion anywhere in this system is `idempotency_keys` older than
  `IDEMPOTENCY_TTL_HOURS`, which the worker does on its own tick. That table holds request digests
  and response ids, no evidence.

### Legal hold

Object Lock supports a legal hold independent of the retention date: it blocks deletion
indefinitely until it is removed, even after the retain-until has passed.

```sh
aws s3api put-object-legal-hold --bucket esign-evidence-prod --key <key> \
  --legal-hold Status=ON
```

Apply it to every blob for the envelopes concerned — which you find by:

```sql
SELECT DISTINCT encode(r.sha256, 'hex'), b.storage_key
FROM document_revisions r JOIN blobs b ON b.sha256 = r.sha256
WHERE r.envelope_id = '<envelope id>';
```

Record who applied it and why. Removing it is a decision for counsel, not for on-call.

---

## 5. Backup and restore without breaking the chain

### What can break

The database and the blob store are two halves of one record, and they reference each other:

- `blobs.sha256` and `blobs.storage_key` point at objects; `document_revisions` and `envelopes`
  point at `blobs`.
- The audit chain hashes **every column of every event**. A restore that alters a single value —
  `occurred_at` rendered in a different time zone, a `bytea` re-encoded, an `inet` normalised —
  breaks `event_hash` for that row and, by chaining, every row after it.

So: **restore the database in Postgres's own format, never through a text-and-reimport pipeline.**

| Do | Do not |
|---|---|
| `pg_dump -Fc` (custom format) or physical backup / PITR | `pg_dump` to SQL text, edited or filtered before loading |
| Restore into the same major version, or a newer one via `pg_upgrade` | Restore through a tool that "normalises" types or time zones |
| Restore the **whole** database | Restore a subset of tables |
| Verify after restoring (below) | Assume it worked because the restore reported success |

### Backup

```sh
# database: nightly full, continuous WAL archiving for point-in-time recovery
pg_dump -Fc -h <host> -U esign_owner esign > esign-$(date -u +%Y%m%dT%H%M%SZ).dump

# blobs: already durable and immutable in S3. Replicate for a regional failure
aws s3api put-bucket-replication --bucket esign-evidence-prod --replication-configuration file://replication.json
```

Points worth knowing:

- **The blob store needs no incremental backup.** It is content-addressed and write-once: objects
  are only ever added. Cross-region replication is for availability, not for versioning, and the
  destination bucket must also have Object Lock enabled.
- **Back up `TRUST_ROOTS_PATH`, `SEAL_CERT_PATH` and `SEAL_CHAIN_PATH`**, including every
  superseded certificate, in a place that will outlive the servers. They are not secrets, and
  without them no old document can be shown to be trusted.
- **The KMS key is not in any backup**, by design. Its durability is AWS's problem; your problem is
  not deleting it. See section 2, step 9.
- Back up the *configuration*, especially `RETENTION_YEARS_BY_DOCUMENT_TYPE`, `APPROVED_DOCUMENT_TYPES`
  and `TRUSTED_PROXY_CIDRS`. They are part of the story of how a given document was produced.

### Restore

1. Restore the database into a **new, empty** database owned by `esign_owner`.
   ```sh
   createdb -O esign_owner esign_restored
   pg_restore -d esign_restored --no-owner --role=esign_owner esign-….dump
   ```
2. Make sure the blob store is reachable and holds the objects the restored rows reference. If you
   are restoring to a different bucket, `BLOB_S3_PREFIX` and the keys must match: keys are derived
   from the content hash, so they are stable, but the prefix is configuration.
3. **Verify before anyone trusts it.** Point a non-serving process at the restored database and run
   verification over a sample — and over every envelope sealed in the period the restore covers:
   ```sh
   for id in $(psql -At -d esign_restored -c \
       "SELECT id FROM envelopes WHERE status = 'sealed' ORDER BY sealed_at DESC LIMIT 200"); do
     DATABASE_URL=postgresql+psycopg://esign_app:…@…/esign_restored \
       uv --directory backend run esign verify "$id" >/dev/null || echo "FAILED $id"
   done
   ```
   Any failure means the restore damaged evidence. Stop and investigate before serving traffic.
4. Check the roles came back. `pg_restore` does not create roles:
   ```sql
   \dp audit_events   -- esign_app must have arwd? No: only 'ar' (SELECT, INSERT)
   ```
   Re-run `esign migrate` if `0002_roles.sql` needs to re-apply the grants. It is idempotent.
5. Sanity-check the chain heads against an independent record — the head hash printed inside any
   sealed PDF you hold outside the database is exactly such a record, which is why it is printed
   there.

### Point-in-time recovery and the append-only rule

PITR to a moment in the past is safe for the *chain* — it truncates the tail, and a shorter valid
chain is still valid. What it is not safe for is **the outside world's memory of events you have
now unwritten**: webhooks already delivered, sealed PDFs already downloaded and filed in a chart,
verification reports already run.

After any PITR:

1. Find envelopes whose blobs exist but whose rows do not, by comparing the bucket listing to
   `blobs.storage_key`. Those are documents that were sealed and are now unrecorded.
2. For each, the sealed PDF is still self-describing: it carries its certificate of completion, its
   audit head hash and its envelope id in `/Location`. Treat it as evidence and reconcile with the
   host's chart.
3. Do **not** attempt to re-insert audit events to "repair" the chain. A reconstructed chain is a
   fabricated one. Record the discrepancy in the incident report instead.

### Migrating to a new environment

Same rules, plus: copy blobs with `aws s3 sync` (which preserves content; it cannot preserve Object
Lock retention, so re-apply retention on the destination), and keep the old bucket until the new one
has been verified against a sample.

---

## 6. Incident checklists

Common to all of them, and worth doing before anything else:

- **Snapshot first.** `pg_dump -Fc` and a record of the relevant object keys. There is no undo in
  this system and no delete path; do not let an investigation become the first one.
- **Do not modify evidence tables.** Not to "fix" a row, not to "clean up" a duplicate.
- **The audit trail is your best witness.** It is append-only and hash-chained. `GET
  /v1/envelopes/{id}/audit` and `esign verify --json` are the first two commands of any
  investigation.

### 6.1 Sealing has stopped

1. Is a worker alive? Look for `worker.tick` / `worker.started` log lines.
2. `SELECT count(*) FROM envelopes WHERE status = 'completed_pending_seal'` — how big is it?
3. The `seal.failed` breakdown query in section 3. One code or several?
4. Follow the error-code table in section 3.
5. Once fixed, bring the backlog forward and watch it drain.
6. **Tell the hosts.** Signatures were taken; documents are not complete. The EHR's users may be
   waiting.

### 6.2 The signing key is compromised

The most serious incident here, and the one where the timestamp earns its keep.

1. **Stop signing.** `aws kms disable-key --key-id <key>`. Sealing now fails with `seal_unavailable`
   and envelopes queue safely. Do **not** schedule deletion.
2. **Establish the compromise window** — the earliest time the key could have been misused.
3. **Revoke the certificate** with the CA, with a revocation time at the start of that window, not
   "now". This is the decision that determines which documents survive: validation is point-in-time,
   so a seal whose timestamp predates the revocation still validates, and one after it becomes
   `certificate_revoked`.
4. **List the affected documents:**
   ```sql
   SELECT stream_id AS envelope_id, occurred_at, data->>'seal_profile'
   FROM audit_events
   WHERE event_type = 'document.sealed'
     AND data->>'signer_cert_sha256' = '<compromised cert fingerprint>'
   ORDER BY occurred_at;
   ```
   Split them at the revocation time. Those before it are fine and should be re-verified to prove
   it. Those after it are suspect.
5. **Rotate** (section 2), on an emergency timetable. New key, new certificate, new configuration.
6. **For documents in the suspect window:** they cannot be re-sealed, and should not be. Each one
   still has its complete audit trail, its stored revisions and its hashes — which is evidence about
   the signing that the compromised key does not touch. Work with counsel on whether they need to be
   re-executed. Apply a legal hold on their blobs in the meantime.
7. Keep the compromised key **disabled, not deleted**, and its certificate in the trust roots, so
   the old documents remain analysable.

### 6.3 `seal_validation_failed` or `seal_profile_not_achieved`

The sealer produced something its own validator rejects, or a document that does not have the
structure the configured profile promises. This is never a transient.

1. The output was discarded; nothing was stored. The envelope is pending and safe.
2. Get the `seal.validation_failed` log line — it carries the four flags and the problem strings
   without any PHI.
3. `revocation_unknown` or `seal_profile_not_achieved` usually means the CA's CRL or OCSP endpoint
   is unreachable, so the DSS could not be assembled. Check from the worker's network.
4. `untrusted_chain` means `TRUST_ROOTS_PATH` does not contain the root your new certificate chains
   to — check a rotation that replaced rather than extended it.
5. `timestamp_invalid` means the TSA's own chain does not validate against the trust roots, or it
   stamped a time beyond our clock. Check both clocks.
6. Anything else: escalate to engineering with the problem strings. Do not work around it, and
   above all do not lower `SEAL_PROFILE` to make it pass.

### 6.4 `blob_corrupt` or `blob_missing`

Stored evidence does not match its recorded hash, or is gone. Treat as data loss.

1. Snapshot. Do not re-put the blob — a fresh `put` of different bytes under the same digest is
   refused, and a `put` of the *right* bytes would paper over the fact that they were lost.
2. Which blob, and what kind? `SELECT kind, size_bytes, storage_key, created_at FROM blobs WHERE
   sha256 = '\x…'`.
3. If the object is missing from S3 but Object Lock was on, it was not deleted normally — check
   CloudTrail for `DeleteObject`, `PutBucketLifecycleConfiguration` and
   `PutObjectLockConfiguration`, and check whether the bucket or prefix is right for this
   environment.
4. Check replication and versioning: an earlier version may still be there
   (`aws s3api list-object-versions --prefix <key>`).
5. Restore the bytes from a replica or backup if they exist. They are content-addressed, so a
   restored object is either the right bytes (it hashes correctly) or it is not; there is no
   ambiguity.
6. If the bytes are genuinely gone: the document is damaged and cannot be reconstructed. Everything
   else about it survives — the trail, the hashes, the certificate of completion inside any copy the
   host downloaded. Involve counsel. Record what was lost.

### 6.5 `audit_chain_broken`, or a verification that reports a chain problem

The chain does not verify. Getting here usually requires database access the application does not
have — with one exception, which is worth ruling out first because it is the only benign one.

0. **Is every sub-problem `data keys do not match <event type> at N`, with no `hash mismatch`, no
   `sequence gap` and no `wrong prev_event_hash`?** Then nothing was edited. An event's key set is
   compared against the model the *running build* declares, so every event of that type written
   before a release that added a field to it reports this, for ever, with its hash still correct.
   Addendum 1 did this to `signer.signed`: a document signed before migration `0700` now reports

   ```
   FAILED  audit_chain  data keys do not match signer.signed at 7
   FAILED  reauth_attestations_match_trail  <signer id>: signer.signed does not say which
                                            attestation covered the signature
   ```

   while every revision hash, the seal, `envelope_row_matches_trail` and `certificate_head_hash`
   pass. Confirm it is that and not something else: the events named are older than the release
   (`SELECT occurred_at FROM audit_events WHERE stream_id = '<envelope id>' AND sequence = N`), the
   same line appears on every envelope of that vintage and on none signed since, and §2(e) of
   `docs/HOW-SIGNATURES-WORK.md` — which hashes the stored columns and knows nothing about our
   models — reports `problems: none`. Record the finding against those envelopes and move on; do
   not rebuild anything. If any of that does not hold, continue below.
1. Snapshot immediately, including WAL if you have it.
2. Run the standalone re-check in `docs/HOW-SIGNATURES-WORK.md` §2(e). It names the first bad row
   and the kind of problem.
3. `sequence gap` means a row was deleted; `hash mismatch` means a column was edited; `wrong
   prev_event_hash` means the chain was re-linked.
4. Who could have done it? Only a superuser, or the owner role with the trigger disabled. Check
   Postgres logs for `ALTER TABLE … DISABLE TRIGGER`, and review who holds those credentials.
5. **Anything sealed before the damage is still provable.** The certificate of completion inside
   each sealed PDF carries the event count and head hash as they were at sealing time, and the seal
   makes that quotation unforgeable. Compare the surviving rows against it.
6. Do **not** rebuild the chain. Report it.

### 6.6 `certificate_evidence_mismatch`

A mutable row disagrees with the append-only trail, caught before sealing.

1. The `seal.certificate_evidence_mismatch` log line names the field (`signers.capacity`,
   `envelopes.created_at`, …) and the envelope and signer ids.
2. Compare the row with the event that recorded the same fact:
   ```sql
   SELECT status, role_key, capacity, on_behalf_of, consent_text_id, viewed_at, consented_at, signed_at
   FROM signers WHERE id = '<signer id>';

   SELECT sequence, event_type, occurred_at, data
   FROM audit_events WHERE stream_id = '<envelope id>' ORDER BY sequence;
   ```
3. The trail is the record. The row is the copy. **Do not edit the trail to match the row.**
4. If the row was changed by an operator, this is an access-control incident: find out how.
5. If neither explains it, it is a bug — escalate with both outputs. The envelope stays pending and
   loud, which is the correct state.

Historical note: one earlier version of `accept_consent` could produce this permanently, by moving
`consent_text_id` while keeping the first `consented_at`. That is fixed (`only_if_unset` covers both
columns). If you see it on an envelope created before that fix, say so in the report.

### 6.7 A host's API key or webhook secret has leaked

1. `esign hosts rotate-key <host id>` — the old key stops working immediately. The new one is
   printed once.
2. Get the new key to the host through their secret channel, and confirm they have deployed it.
3. For a leaked **webhook secret**, mint a new one. There is no CLI subcommand for this today
   (see the gaps in `docs/COMPLIANCE-CHECKLIST.md`); use:
   ```sh
   uv --directory backend run python -c "
   from esign.runtime import build_runtime
   from esign.identity import rotate_webhook_secret
   from uuid import UUID
   rt = build_runtime()
   with rt.transaction() as db:
       print(rotate_webhook_secret(db, UUID('<host id>')).hex())
   "
   ```
   Deliveries queued but not yet sent will be signed with the new secret, so coordinate the cutover
   with the host or they will reject them.
4. What could the holder of a leaked key do? Create envelopes, open sessions for signers on *their
   own* envelopes, and read their own documents. They could not read another host's anything — every
   lookup is host-scoped and another host's object is `not_found`. Review that host's
   `envelope.created` and `session.created` events for the exposure window.
5. To stop a host entirely while you work:
   ```sh
   uv --directory backend run python -c "
   from esign.runtime import build_runtime
   from esign.identity import disable_host
   from uuid import UUID
   rt = build_runtime()
   with rt.transaction() as db:
       disable_host(db, UUID('<host id>'))
   "
   ```
   A disabled host cannot authenticate, and `/sign?host=…` serves `frame-ancestors 'none'`.

### 6.8 Suspected PHI in a log

1. Find it, quote nothing in the ticket, and note which field and which log line.
2. The logger drops any key that is not on the allowlist and reports the drop, so a genuine leak
   means either a value inside an allowlisted field or a logger that was bypassed. Check for
   `dropped_fields` around the time.
3. Purge according to your log retention policy. Log data is not evidence; it may be deleted.
4. Fix the call site, add a test to whichever `test_no_phi*` module covers that package, and check
   `DB_ECHO` is off.
5. The most likely bypass is a process that did not go through `esign serve` and so kept uvicorn's
   own non-propagating loggers. There is exactly one correct way to start the API.

### 6.9 A saved signature is compromised

Somebody else got at a clinician's account, or a saved signature was captured by the wrong person
and is now being offered in that person's sessions (Addendum 1 B). The saved signature itself is
not a credential — it cannot be used without an authenticated session for that user, and a
clinician's signature additionally needs a re-authentication — so this is usually the *second*
thing to deal with, after the account.

1. **Deal with the account first**, in the EHR. A saved signature is only reachable from a live
   session of that `host_user_id`; while the account is compromised, revoking the signature stops a
   convenience, not an attack. The host should also stop opening sessions for that user.
2. **Revoke the saved signature.** One call, through the host API, idempotent:
   ```sh
   curl -s -X POST "$API/v1/users/<host_user_id>/adopted-signature/revoke" \
     -H "Authorization: Bearer $ESIGN_API_KEY" -H 'Content-Type: application/json' \
     -d '{"reason": "suspected compromise"}'
   # {"revoked": true}     ("revoked": false = there was nothing live to revoke)
   ```
   `reason` is for your own logs and is deliberately not stored; the trail records `reason: host`.
   Send JSON or no body at all — `-d '{}'` with no `Content-Type` is form-encoded and is refused.
   The signer can do the same from their own session (`POST /v1/signing/adopted-signature/revoke`,
   recorded as `reason: user`). The next session is offered nothing and must adopt a fresh
   signature.
3. **Record what it was and what used it.** Nothing is deleted, so this is answerable afterwards:
   ```sql
   -- the row, live or revoked
   SELECT id, kind, created_at, created_by_session_id, created_in_envelope_id,
          revoked_at, revoke_reason
   FROM adopted_signatures
   WHERE host_id = '<host id>' AND host_user_id = '<host_user_id>'
   ORDER BY created_at DESC;

   -- every signature that applied it, and on which document
   SELECT s.envelope_id, c.signer_id, c.field_id, c.created_at
   FROM signature_captures c JOIN signers s ON s.id = c.signer_id
   WHERE c.adopted_signature_id = '<adopted signature id>'
   ORDER BY c.created_at;
   ```
   The trail says the same from the other side: `signature.adopted` on the envelope stream of the
   session that created it, `signature.adoption_revoked` on the `system` stream for that host, and
   `signer.signed.adopted_signature_id` on every signature that used it.
   ```sql
   SELECT occurred_at, event_type, actor_user_id, data
   FROM audit_events
   WHERE stream_type = 'system' AND stream_id = '<host id>'
     AND event_type = 'signature.adoption_revoked'
   ORDER BY sequence DESC LIMIT 20;
   ```
4. **Do not delete the row**, and do not ask the owner role to. The trigger refuses, which is the
   design: a sealed document's capture points at it, and verification follows that pointer to
   re-hash what was stamped. A deleted row would turn a verifiable signature into an unverifiable
   one — the compromise would have destroyed evidence rather than being contained.
5. **The documents already signed stand until somebody decides otherwise.** Each one still has its
   own session, consent, re-authentication (if the role required it) and audit chain; the question
   "was this person really the one signing?" is answered by that evidence, not by the saved image.
   Re-verify the affected envelopes (`esign verify`), list them for the host, and work with counsel
   on whether any need to be re-executed — the same conversation as §6.2, with a much smaller blast
   radius.
6. If the span is on (§7), note that a compromised session inside the window could sign several
   documents on one confirmation. `SELECT ... WHERE data->>'reauth_scope' = 'span'` (the query in
   §7) lists exactly which signatures those were.

---

## 7. Routine operations

### Adding a document type

A document type not on `APPROVED_DOCUMENT_TYPES` cannot produce an envelope, whatever templates
exist. That is deliberate: the developer guide says the list is compliance's decision, not
engineering's.

1. Compliance approves the type. Get it in writing; counsel may need to rule on witnessing or
   notarisation requirements for it, per state.
2. Add it to `APPROVED_DOCUMENT_TYPES` and deploy.
3. Import the template (below) and publish it.
4. Run one envelope end to end in staging, seal it, verify it, and read the certificate of
   completion.

### Adding or versioning a template

```sh
uv --directory backend run esign templates import --host <host id> --dir templates/
```

Imports every `*.json` with a matching `*.pdf` and publishes it (`--no-publish` leaves drafts). A
**published version is immutable**; a change is a new version. Existing envelopes keep the version
they were created against, which is what the certificate prints.

The service refuses a template PDF that is encrypted, already signed, scripted, XFA-bearing or
carrying attachments, and one whose definitions are inconsistent — including a role that allows the
`clinician` capacity without `requires_reauth`.

Retiring a version (`POST /v1/templates/{key}/versions/{n}/retire`) stops new envelopes using it and
touches nothing already signed.

### The re-authentication span

`REAUTH_SPAN_SECONDS` decides whether a clinician re-authenticates once per **document** (the
default, `0`) or once per **queue of documents** (any value up to 900). Turning it on is not a
tuning decision: it is the one documented deviation from the guide's per-document rule, and it
needs a recorded decision from compliance (`docs/COMPLIANCE-CHECKLIST.md` C10) before it is set.

**What changes when it is on.** An attestation made for one of a user's sessions also covers that
same user's other sessions **on the same host**, for that many seconds after its `auth_time`. Every
signature still needs its own envelope, session, review, consent and explicit sign action; what it
no longer needs is its own trip through the host's re-authentication screen.

**Set both windows together.**

```sh
REAUTH_MAX_AGE_SECONDS=300     # how fresh an attestation must be to cover any signature
REAUTH_SPAN_SECONDS=300        # how long it may also cover the user's other sessions
```

An attestation older than `REAUTH_MAX_AGE_SECONDS` covers nothing, span or no span, so the
effective queue window is the **smaller** of the two. Raising the span alone changes nothing you
would notice: with the shipped `REAUTH_MAX_AGE_SECONDS=120`, `REAUTH_SPAN_SECONDS=300` still gives
a two-minute queue. Both are validated at startup (`0 ≤ span ≤ 900`), and `make demo` sets both to
300 for exactly this reason.

Pick the window from how long a real queue takes, not from what is convenient: long enough that a
clinician signing five orders is not re-prompted mid-queue, short enough that an unattended
workstation is not a signing machine. Five minutes is a defensible starting point; anything
approaching the 900-second cap should be argued for in writing.

**Auditing it afterwards.** Every signature says which attestation covered it and whether it was
borrowed, so "how often is the span actually used, and how stale were those confirmations?" is one
query:

```sql
SELECT date_trunc('day', occurred_at) AS day,
       data->>'reauth_scope'          AS scope,
       count(*),
       max((data->>'reauth_age_seconds')::int) AS oldest_seconds
FROM audit_events
WHERE event_type = 'signer.signed' AND data->>'reauth_used' = 'true'
GROUP BY 1, 2 ORDER BY 1 DESC, 2;
```

A `span` row whose `oldest_seconds` is near the window is the case a reviewer will ask about; a
sudden rise in `span` against `session` means the host changed how it drives the queue. A row with
a **null** scope is a signature recorded before migration `0700`, when `signer.signed` did not yet
name its attestation — verification reports those as a finding
(`reauth_attestations_match_trail`) rather than a pass, so they should not appear for anything
signed after the upgrade. The certificate of completion prints the same fact per signature, in
words, so nothing here depends on the query being run.

**Turning it off** is setting it back to `0` and restarting: nothing is migrated, nothing already
signed changes, and every past signature keeps its recorded scope. Do that first and investigate
afterwards if the span is ever implicated in an incident.

### The consent span

`CONSENT_SPAN_SECONDS` is the same shape of decision for the other thing a queue asks for twice.
At `0` (the default) the ESIGN disclosure is displayed before every agreement, on every envelope.
Above zero, an acceptance by the same `(host_id, host_user_id)`, of the same disclosure version and
locale, stands for that person's other documents on the same host for that many seconds: they see
"You agreed to sign electronically at 09:12" instead of the checkbox. Like the re-authentication
span it needs a recorded decision from compliance (`docs/COMPLIANCE-CHECKLIST.md` C12) before it is
set, and it is validated at startup (`0 ≤ span ≤ 3600`).

**What does not change.** Every envelope still records its own `consent.accepted`, still sets the
signer's `consent_text_id` and `consented_at`, and no signature is accepted without them. What the
span changes is whether the notice was put in front of the signer again — and the record says which
it was: the event names the acceptance relied on and when it was given, the certificate prints
"(given for an earlier document in the same sitting; disclosure displayed 08:58)", and
`esign verify` re-reads that earlier envelope's own hash-chained trail rather than trusting the
pointer. A kiosk session never has standing consent, in either direction, and verification
re-derives that too rather than assuming the rule held when the row was written.

Pick the window from how long a sitting lasts — a patient at one desk, a clinician's queue of
orders — not from how long somebody is logged in. `make demo` uses 900 seconds. The window is
measured from the moment the notice was **displayed**, not from the last agreement: document
three stands on document two, which stood on document one, and every event carries that first
display time forward, so a queue cannot renew the window one document at a time. A signature
resting on a disclosure displayed longer ago than the `3600`-second cap describes something this
service could not have produced, and verification says so whatever the configuration was at the
time.

**Auditing it afterwards**, the same way the span above is audited:

```sql
SELECT date_trunc('day', occurred_at) AS day,
       (data->>'relied_on_envelope_id' IS NOT NULL) AS stood_on_an_earlier_one,
       max(occurred_at - (data->>'relied_on_root_accepted_at')::timestamptz)
         AS longest_since_the_notice_was_shown,
       count(*)
FROM audit_events
WHERE event_type = 'consent.accepted'
GROUP BY 1, 2 ORDER BY 1 DESC, 2;
```

**Turning it off** is setting it back to `0` and restarting. Nothing already recorded changes: the
acceptances that stood on an earlier one keep saying so.

### Rolling out a new consent disclosure

Consent texts are immutable and versioned. Adding one does not invalidate anything already accepted.

```sh
uv --directory backend run esign consent add \
  --version 2027-01 --locale en-US --file disclosure-2027-01.txt \
  --effective-at 2027-01-01T00:00:00+00:00
```

- Counsel approves the wording before it is added.
- `--effective-at` in the future means it becomes current at that moment; sessions in flight
  continue on the old version until the client posts consent, at which point a stale version is
  refused with `consent_version_stale` and the UI shows the new text. That refusal is correct: it
  stops consent being recorded against text the signer was not shown.
- The same version with different words is a conflict. Bump the version.
- Check the text does not promise something that is false on a kiosk — the bundled `en-US.2026-10`
  replaced `2026-09` for exactly this reason, because the older one promised a download "from this
  screen" and a kiosk hands the tablet back and wipes state.

### Scaling

- **API**: stateless. Add replicas.
- **Worker**: add replicas; they coordinate through the database. One is enough for a small clinic;
  size by how long the backlog query stays non-empty.
- **Database**: the hot path is one row lock per envelope plus one advisory lock per audit stream.
  Contention is per envelope, so it scales with distinct documents, not total load.
- **Caveat: rate limits are per process.** `SlidingWindowRateLimiter` keeps its counters in memory
  and does not share them between replicas, so N API replicas allow N times the documented limit.
  They exist to slow down guessing rather than to meter traffic, so this is tolerable — but if you
  run many replicas, put a limiter in front of the service as well.

### Upgrading

1. `esign migrate --dry-run` against a copy of production, then `esign migrate`. Files are applied
   in filename order, each in its own transaction, under an advisory lock, with a stored checksum.
2. Workers first, then the API. A worker restarted mid-attempt loses nothing: the claim goes stale
   and another worker takes it over.
3. After any upgrade, seal one document and verify it — including in Acrobat if the sealing path
   changed at all.
4. **If the release adds a field to an audit event's `data`** — Addendum 1 did, to `signer.signed`
   — then every event of that type written before it will report `data keys do not match <type>`
   from then on, and those envelopes verify `FAILED` although nothing was touched (§6.5 step 0).
   Before upgrading, run `esign verify --json` over a sample and keep the reports: a verification
   recorded as `ok` on the old build, plus the `verification.performed` events already in each
   trail, is what dates the finding to the release rather than to an incident. Tell whoever runs
   the weekly sample verification (below) which envelopes are affected, so it is not re-triaged
   every week.

### Weekly

- Backlog query returns nothing.
- `seal.failed` count for the week is zero, or every entry is explained.
- Webhook deliveries with `attempts >= 6` and no `delivered_at` — a host endpoint is down.
- Sample five sealed envelopes and `esign verify` them. This is cheap and it is how a slow
  corruption gets found before someone in a deposition finds it. Sample from *recent* envelopes;
  one signed before a release that changed an event's data shape fails on that alone (§6.5 step 0)
  and tells you nothing about this week.

### Quarterly

- `openssl x509 -enddate` on the seal certificate. More than 90 days left?
- Trust roots file still contains every root ever used.
- A restore rehearsal, verified per section 5.
- Object Lock still on, no lifecycle rule touching the evidence prefix, retention dates as expected.
- Re-read `docs/COMPLIANCE-CHECKLIST.md` against the code as it now is.
