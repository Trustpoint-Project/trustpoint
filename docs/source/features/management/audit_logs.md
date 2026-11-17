# Audit Log

The audit log records important state changes in Trustpoint. It is intended for traceability and operational review, not for storing secrets or full request payloads.

Access: **Management > Audit Log**

## Traceability credentials

Under **Management > Traceability Credentials**, configure a signing identity with
an assignment method first, then its name and settings:

- **Issue from Management CA**: select an existing active management CA or RA.
  Local CAs issue directly; EST and CMP RAs use their saved enrollment settings.
- **PKCS#12 file**: upload a certificate and private key in one container.
- **Separate files**: upload the certificate, private key, and optional issuer chain.
- **Generate CSR**: generate a managed key, download the CSR, then upload the
  issued certificate and select an issuing CA trust store. The trust store must
  contain the CA certificates needed to build the certificate path.

CA issuance uses the selected management CA’s signing key curve (P-256 or P-384).
Standalone CSR generation asks for the signing key curve.
Imports take their curve from the first certificate; replacements must use the
same curve. The selected method also controls **Request new credential**. Imported private
keys require **Allow imported private keys** in Security Settings and use the
configured crypto backend's import protection. Certificates must be currently
valid, match the configured curve, have `CA=false` and digital-signature-only key
usage. Extended Key Usage may be absent. When present, it must include
`anyExtendedKeyUsage` (`2.5.29.37.0`); a certificate restricted to unrelated
purposes such as TLS authentication or code signing cannot sign traceability
records. This applies to imported certificates and issuance profiles alike.
A dedicated traceability-signing EKU OID is not currently defined by Trustpoint.

Only one traceability identity and one signing generation can be active.
Requesting a replacement always requires a fresh key and certificate. The current
generation continues signing until the replacement validates and activates;
failed issuance or a pending CSR leaves it unchanged. A pending CSR can be
cancelled before requesting another. **Retire credential** stops signing with the
current generation, cancels any pending CSR, and retains history. A later request
can activate a fresh generation of the same identity.

## Hash chain and signed checkpoints

Every audit event is part of an append-only SHA-256 hash chain. Each entry
contains its monotonically increasing `sequence`, the `previous_hash` of the
preceding entry, and its own `entry_hash`. The first entry references a
64-character zero hash. The hash covers the sequence, previous hash, timestamp,
operation, target type, target identifier and display label, actor username,
and details.

Signing is configured on **Management > Audit Log > Signing settings**, not in
the Traceability Credential details. The credential is a reusable signing
identity; the enablement state and intervals are global audit policy. Select an
active and usable Traceability Credential, then enable checkpoint signing.
The default policy is one checkpoint after 100 new events. A maximum interval
is optional and disabled by default. The event threshold and the time interval
are independent: whichever is reached first triggers a checkpoint. Values must be
at least one event and one minute. Enabling signing creates a baseline
checkpoint immediately; if no events exist yet, it signs an empty genesis
checkpoint to prove that the configured key works.

A checkpoint covers a contiguous sequence range and records the range, entry
count, head hash, previous checkpoint hash, signing timestamp, exact signed
JSON payload, signature, and the concrete signing generation. The signature is
created with the existing Traceability Credential service. Checkpoints are
created after the business transaction commits, so a signing failure never
fails or rolls back the audited operation. Failed attempts are recorded on the
signing configuration, retried after a short backoff, and can also be retried
by `python manage.py sign_audit_checkpoint` or the scheduled Django-Q2 task.
The scheduled task runs at the configured maximum interval, with its next run
reset to the latest checkpoint's signing time plus that interval. Without a
time interval, retries run every five minutes. Background worker availability
and scheduler latency can delay execution. The audit event is still written and
chained when checkpoint signing fails.

Every successful checkpoint also writes an **Audit Checkpoint Signed** event
to the audit log, containing the checkpoint number, covered sequence range,
event count, head hash, signing generation, algorithm, and certificate
fingerprint. These internal signing events are excluded from the event count
that triggers the next checkpoint, so signing cannot trigger itself in a loop.
Crypto audit events produced by checkpoint signing are also excluded from this
trigger count. All these events remain in the hash chain and are covered by later
checkpoints; ordinary crypto operations still count toward the next checkpoint.

Key rotation is transparent. The configuration references the logical
Traceability Credential; each checkpoint stores the concrete generation that
signed it. Rotating the credential changes the generation used for future
checkpoints, while all historical checkpoints continue to verify against their
original certificates. Retiring the configured credential stops signing
safely; select another active credential to resume. Historical generations are
never deleted.

## Verifying integrity

Use **Verify integrity** on the Audit Log page or run:

```bash
python manage.py verify_audit_log
python manage.py verify_audit_log --json
```

Verification reads all events in sequence order and checks:

- sequence 1 exists and sequence numbers are contiguous;
- every `previous_hash` matches the preceding `entry_hash`;
- every recorded hash matches the current event contents;
- checkpoint ranges are contiguous and their counts and head hashes match;
- every checkpoint links to its predecessor;
- every checkpoint payload matches its database columns;
- every checkpoint signature verifies against its historical signing generation
  and certificate fingerprint.

Events newer than the latest checkpoint are normal while they remain below the
configured event interval. They become an `UNSIGNED_EVENTS` warning only when
the event threshold or the maximum time interval is due, which indicates that
checkpoint signing has failed or has not run. Disabled or unusable signing
configuration, and a chain with no signed checkpoints, are also warnings: the
hash chain can be intact without being cryptographically anchored. The page
shows an amber warning in these cases instead of claiming that all signatures
are valid. A successful command exits with status 0; any fatal chain or
signature finding exits with status 1. The web page requires **View audit log**
and refuses logs above 10,000 events; use the management command for larger
logs. Changing signing settings requires **Manage security configuration**.

## Security limitations

The hash chain and signatures detect modification, deletion, reordering, and
signature invalidity under normal application and database access. They do not
make the database a write-once store. Consider all of the following:

- Events, hashes, checkpoints, signatures, and credential references are kept
  in the same database. An attacker with write access, and especially access to
  the signing key or crypto backend, can rewrite history and create new valid
  signatures. Use a hardware-backed or remote signing key to raise the bar.
- Deleting the newest events is only detectable up to the newest retained
  checkpoint. Deleting events and the checkpoints after a chosen point leaves a
  shorter but internally consistent chain.
- To obtain real tamper evidence, retain signed checkpoints, their payloads,
  signatures, and signing-certificate SHA-256 fingerprints outside Trustpoint,
  for example in write-once storage, another system, or an external
  timestamping/transparency service. Verify those retained fingerprints
  independently. In-app verification assumes the stored generation certificate
  and its fingerprint are trustworthy.
- Existing audit events are hashed when the feature is first installed. This
  establishes a baseline but does not prove that old rows were not modified
  before the upgrade.
- The chain proves what Trustpoint recorded, not that every business operation
  called the audit API. A code path that omits auditing leaves no trace.
- Timestamps come from the application server clock. Signatures prove the
  recorded time, not real-world time, unless an external timestamp is used.
- Model-level delete protection can be bypassed with raw SQL or bulk query
  operations. Verification detects most changes unless the attacker also
  rewrites the chain and can sign.
- Restoring an older database backup or snapshot truncates the current tail.
  Only externally retained checkpoints can reveal that rollback.

## Evidence exports

Apply the audit log filters, then choose **Evidence export**. Full exports
require **View audit log**. Filtered exports also require **Manage Traceability
Credentials**, because they use the configured audit signing key. The signing
credential is taken from the audit signing configuration rather than selected
per export. The download is a JSON evidence
package named `trustpoint-audit-evidence.json` with format
`trustpoint:audit-evidence:v1`. It contains the matching events, the full
retained checkpoint history, and the signing certificates needed for offline
verification. Exports are limited to 10,000 events and 10,000 checkpoints;
narrow the filters or retain smaller exports for larger logs.

The package has three top-level fields:

- `format`: `trustpoint:audit-evidence:v1`.
- `evidence`: scope, filters, range, events, chain head, checkpoints, and certificates.
- `snapshot_signature`: `null` for a full export, or a JWS for a filtered one.

Checkpoint metadata is not duplicated. Each checkpoint contains only the signed
`payload` object and its `signature`; checkpoint number, sequence range, head
hash, previous checkpoint hash, signing time, credential, generation, and
certificate fingerprint are read from the signed payload. Signing certificates
are deduplicated in `evidence.certificates` by SHA-256 fingerprint, and each
payload references its certificate through the signer fingerprint. A filtered
export also lists the certificate that signed its snapshot, even when no
checkpoint uses that generation yet.

### Full versus filtered exports

A **full export** has no audit log filters. It is a complete chain from sequence
1 through the latest signed checkpoint captured at the start of the export and
contains every retained checkpoint up to that boundary. The package's range and
chain head identify this boundary. Newer events, including the latest checkpoint's
own signing event, are left for a later export. No additional snapshot signature
is created: the checkpoint signatures and the hash chain already protect the
exported events. If no checkpoint exists, all events are exported and the package
fails offline verification. If a retained checkpoint
is newer than the event head, the export is refused instead of silently
producing a shorter package; run integrity verification and investigate before
exporting.

A **filtered export** is a subset. It is signed automatically with the
configured audit signing credential; there is no separate credential picker.
Filtered exports require audit signing to be enabled and usable. The snapshot
signature proves the exact filtered package came from Trustpoint, but it cannot
prove that no matching source events were omitted. Checkpoint coverage is only
verified when the checkpoint head event is also part of the selection;
otherwise the verifier reports `CHECKPOINT_COVERAGE_NOT_EXPORTED`.

The snapshot signature is an [RFC 7515 flattened JWS](https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.2)
using `protected`, `payload`, and `signature`. The protected header contains
`alg` (`ES256`/`ES384`), `cty` (`application/json`), and `x5c` with the signing
generation certificate as standard Base64 DER. The payload is the canonical
JSON encoding of the `evidence` object. Editing the evidence invalidates the
snapshot signature.

### Offline verification

Verify on another machine with Python and `cryptography` installed:

```bash
python -I trustpoint/util/audit_log_export.py trustpoint-audit-evidence.json \
    --trusted-certificate generation-1.pem \
    --trusted-certificate generation-2.pem
```

Repeat `--trusted-certificate` for every signing generation present in the
package. Obtain the certificates independently from a trusted administrator and
check their SHA-256 fingerprints against the Traceability Credential generation
history. Do not establish trust using only certificates embedded in an untrusted
package. Retired generations remain necessary because each checkpoint records
the exact generation that signed it.

The verifier checks event hashes and links, checkpoint coverage for full
exports, checkpoint payloads and signatures, and the filtered snapshot
signature. It does not build certificate paths to arbitrary CA trust stores.
The command exits non-zero for integrity, coverage, signature, trust, or
unsigned-tail findings. Only unproven filtered coverage is a warning.
Previously generated JWS-only exports are not supported by the evidence
verifier; download a new evidence package.

A full package with no checkpoints fails verification with
`NO_SIGNED_CHECKPOINTS`. No export can prove that source events
were not intentionally never written to the audit log, and a filtered export
cannot prove source completeness.

## What is recorded

Each audit log entry contains:

| Field | Description |
|---|---|
| Sequence | Monotonic position in the hash chain. |
| Timestamp | Time when the event was recorded. |
| Operation | Type of change or security-relevant action. |
| Target Type | Object type affected by the action. |
| Target | Human-readable object label captured at the time of the action. |
| Actor | Username captured at the time of the action, or `System` for automated actions. |
| Details | Optional structured metadata. |
| Previous Hash | Hash of the preceding event, or the zero hash for the first event. |
| Entry Hash | SHA-256 hash of this event's canonical contents. |

The target label is preserved even if the original object is later deleted.

## Operations

Trustpoint records audit events for changes such as:

- credential issuance, renewal, revocation, and deletion
- device, domain, CA, signer, and user changes
- security configuration changes
- audit signing configuration changes and signed audit checkpoints
- TLS certificate changes
- signing operations
- crypto backend operations such as key generation, signing, verification, and key destruction

## Writing audit events

Each business operation has one audit owner: the view, API handler, or service
that coordinates the complete operation. `AuditLog.save()` assigns the chain
sequence and hashes on insert, so both `AuditLog.create_entry()` and direct
model creation produce chained rows. Do not use bulk inserts or update stored
hash fields. Replace an existing audit call when
adopting a helper for the same event. Model saves and signals do not independently
write security-change events.

For registered security-sensitive objects, use
`management.security_change_audit.security_change(target=instance, actor=user)`
around the complete update, including related-object changes. The scope reads the
original database state, waits for all saves to finish, and writes one entry with
the final persisted differences. Unchanged submissions produce no entry. Changes
and their audit entry share a transaction; an audit write failure rolls back the
change. Use `action='deleted'` for deletion to retain the original object identity.

For creation, call `audit_security_change(target=instance, actor=user, before=None,
action='created')` after saving, within the same transaction. Import forms that
persist during validation require a transaction around validation as well.
Backend setup uses `provider_configuration_changes(actor=user_or_none)` to capture
one event per changed configuration object, including initialization and removal;
nested setup scopes share the outer audit owner.

The helpers select object-specific operations, preserve the actor, and redact
sensitive configuration references. Domain certificate-profile assignments and
truststore certificate membership are included in their parent object's event.
Do not additionally audit each through-model save for those operations.
Distinct business events, such as credential issuance and crypto signing, retain
their dedicated operation types and owners.

`MODEL_CREATED`, `MODEL_UPDATED`, and `MODEL_DELETED` remain available as legacy
filter choices for historical rows. New production writers use specific types.
Existing audit history is preserved by the operation-choice migration.
