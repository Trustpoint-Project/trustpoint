# Issuing CA Rollover

Issuing CA rollover replaces the credential used by a locally managed Issuing CA without immediately replacing the active CA. The existing CA remains active until the rollover is explicitly started, transitioned, and completed.

Rollover is available from the Issuing CA configuration page:

**PKI > Issuing CAs > Issuing CA configuration > CA Rollover Management**

Rollover applies only to locally managed Issuing CAs. Remote Issuing CAs and RA configurations cannot be rolled over because Trustpoint does not own their signing credential.

## Rollover methods

A rollover can acquire the replacement credential using one of these methods:

### Import from file

- Import a PKCS#12 file containing the private key, CA certificate, and optional chain.
- Import separate private-key, CA-certificate, and optional chain files.

The same Issuing CA import validation is used for rollover. The private key must match the certificate, the certificate must be a CA certificate, and the required CA extensions and key usages must be valid.

### Generate a keypair and request a certificate

Trustpoint generates the replacement keypair through the configured crypto backend. The active backend and its capability policy remain the source of truth; rollover does not select or reconfigure a backend.

The certificate can be requested using:

- EST
- CMP

The existing Issuing CA EST and CMP request workflows are reused. Upstream endpoint, port, path, and authentication settings are entered in the rollover request form and are not silently copied from an earlier request.

## Lifecycle

The rollover states follow this sequence:

```text
PLANNED
    |
    v
PREPARATION
    |
    v
TRANSITION
    |
    v
COMPLETED
```

Generated EST/CMP requests have an additional certificate-acquisition step:

```text
Create managed key and provisional CA request
    |
    v
AWAITING_NEW_CA
    |
    |  EST or CMP returns the replacement CA certificate
    v
PLANNED
    |
    v
PREPARATION
    |
    v
TRANSITION
    |
    v
COMPLETED
```

### Planned

The replacement CA credential exists and has passed the import or certificate-request validation. The active CA has not changed. The operator can start the rollover.

### Awaiting New CA

The generated replacement key and provisional CA request configuration exist, but the replacement CA certificate has not yet been received. The rollover cannot start until EST or CMP returns a valid certificate.

After receipt, Trustpoint validates that:

- the certificate is a CA certificate;
- Basic Constraints permit CA usage;
- `keyCertSign` and `cRLSign` are enabled;
- the certificate public key matches the backend-managed replacement key.

A different Subject DN from the current CA is allowed.

### Preparation

Starting a planned rollover moves it to Preparation. The replacement CA is prepared while the old CA remains active. If a transition time was supplied, Trustpoint schedules an automatic transition check.

### Transition

The rollover moves from Preparation to Transition either through the configured schedule or through the manual transition action. The replacement CA is intended to issue new certificates while the old CA remains available for trust and cleanup purposes.

### Completed

Completing the rollover reassigns associated domains to the replacement CA and deactivates the old CA. The active Issuing CA credential is not replaced before this lifecycle step.

### Cancelled

An active rollover can be cancelled before completion. A cancelled rollover does not activate the replacement CA.

## Truststores and devices

Each CA has its own server-side chain truststore. Creating or importing the replacement CA creates or associates its CA-chain truststore as part of credential setup.

The current rollover state machine does not automatically distribute both the old and new CA truststores to requesting devices. Device truststore distribution or device-specific trust updates must be handled by the relevant device provisioning workflow.

## Concurrency and safety

Only one active rollover is allowed for an Issuing CA. A second rollover cannot be started while another rollover is planned, awaiting a certificate, in preparation, or in transition.

The rollover service uses transactional checks and database constraints to prevent concurrent active rollovers. The active CA remains unchanged until the normal activation lifecycle completes.

Private keys are handled through Trustpoint's crypto backend abstraction. Backend-managed keys are not exported during rollover.
