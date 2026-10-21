# asyncua OPC UA GDS Push test target (experimental)

Python-based integration test target modeled after `opcua-asyncio/examples/server-with-encryption.py`, for Trustpoint's GDS Push client.

**Experimental development server.** Automated integration tests cover discovery,
TrustList installation, certificate rotation, and credential renewal. Certificate
activation requires restart; full OPC UA SecurityAdmin permissions and CRL
signature/path verification remain outside this target's implementation. Run it
only on an isolated loopback development network.

## Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python server.py
```

Uses `./state/pki/` for persistent OPC UA PKI files, with the conventional `own`, `trusted`, `issuers`, and `rejected` layout. On first start, a self-signed application certificate and RSA private key are generated. They are not regenerated on subsequent starts. Set `GDS_ENDPOINT`, `GDS_APPLICATION_URI`, and `GDS_HOSTNAME` before the first boot if needed. Trustpoint's GDS Push service currently constructs `opc.tcp://<IP>:<port>` without a path, so set `GDS_ENDPOINT=opc.tcp://127.0.0.1:4840` to match it.


## PKI folder structure

The server creates these directories automatically on startup:

```text
state/
  pki/
    own/
      certs/server.der             # active server application certificate
      private/server.pem           # matching private key (keep private)
      backup/                      # last active certificate and key
    trusted/
      certs/                      # directly trusted client / CA certificates
      crl/                        # CRLs checked for revoked peer certificates
      admin-client.der            # explicitly authorized GDS Push admin identity
    issuers/
      certs/                      # chain-building intermediates; not trust anchors
      crl/                        # issuer CRLs checked for revocation
    rejected/
      certs/                      # reserved for rejected peer certs (not yet populated)
    trustlist-staged.bin          # last applied binary TrustList payload
```

A certificate in `issuers/certs/` must **not** become a trusted root solely by its presence.
The server loads `trusted/certs/` using asyncua's `TrustStore`; it does not yet
perform CRL signature/path verification or automatic rejected-certificate storage.
Revocation checks use asyncua's TrustStore implementation. The
GDS Push TrustList updates replace the selected certificate/CRL folders and reload
validation when `ApplyChanges` is called. Issuer certificates remain separate from
the trusted certificates.

If upgrading from the original prototype, copy its existing `state/server.der`
and `state/server-key.pem` to the new `pki/own/` paths **before starting**.
Copy the old `state/admin-client.der` to `pki/trusted/admin-client.der`.
Do not delete or regenerate the original private key during migration.

## Mutual trust bootstrap

1. Start once, then copy `state/pki/own/certs/server.der` to Trustpoint's GDS Push server truststore as the server certificate (first entry / order zero).
2. Export the *actual GDS Push client certificate* used by Trustpoint's domain credential in DER encoding. Copy it to `state/pki/trusted/admin-client.der` (explicit SecurityAdmin allowlist).
3. Put that same approved client certificate in `state/pki/trusted/certs/` (in supported DER/PEM form; inspect your `asyncua` version's TrustStore conventions). If issuing CA trust is used, separately validate how chain validation works.
4. Restart the test server. Create the Trustpoint OPC UA GDS Push device, attach the matching domain credentials and server truststore, and test a secure connection.

**Do not turn off certificate validation to overcome bootstrap problems.** Use an isolated admin identity and verify the server's SecurityAdmin role mapping before using methods.

## Optional administrator username/password

Trustpoint's GDS Push username and password fields are optional. Leave both blank
for the certificate-based administrator access described above.

The test server also accepts an optional administrator account configured through
environment variables before startup:

```bash
export GDS_ADMIN_USERNAME='admin'
read -r -s -p 'GDS admin password: ' GDS_ADMIN_PASSWORD; echo
export GDS_ADMIN_PASSWORD
python server.py
```

Set both variables as a pair. To select certificate-only authentication, explicitly
set both variables to empty strings (overriding the script's development defaults).
Enter the same credentials in the Trustpoint device's OPC User and OPC Password
fields. The certificate administrator allowlist remains available. Invalid supplied
credentials are rejected, even when the client has an allowlisted admin certificate.
Set both variables explicitly when running automated tests.

Both authentication methods still require a trusted client certificate and an
encrypted connection. For username/password access, place the approved Trustpoint
client certificate in `state/pki/trusted/certs/`; it need not also be registered as
`admin-client.der`. Trustpoint must still trust the server certificate. Restart the
server after changing its credentials or trust configuration.

## Supported/partial operations

Only `DefaultApplicationGroup` is exposed. asyncua's unimplemented default HTTPS
and user-token certificate groups are removed at startup so clients do not attempt
their unbound TrustList methods (`BadNothingToDo`). This status is not an indication
that the certificates are already installed. Repeated uploads to the application
TrustList are accepted.

- `CreateSigningRequest`: creates a server-owned RSA-2048 CSR; can stage a new key.
- `UpdateCertificate`: validates the public-key match, stages the issued certificate.
- `ApplyChanges`: persists the staged cert/key in `pki/own/`; restart required to load the new certificate into the running server.
- TrustList `Open`, `Write`, `CloseAndUpdate`: receives and validates binary `TrustListDataType`.
  `ApplyChanges` replaces the selected certificate/CRL folders and reloads the live
  validator. A copy of the applied payload is retained at `pki/trustlist-staged.bin`.
  Invalid payloads are rejected before replacing existing files.

The server remains a development target. It does not implement the full OPC UA
security and certificate-management specification. Replacement server certificates
require a restart; issuer certificates are not implicitly trusted, and CRL
signature/path verification is outside this target's validation capabilities.

## Automated end-to-end workflow

From the repository root, run:

```bash
RUN_GDS_INTEGRATION=1 uv run pytest \
  trustpoint/request/tests/integration/test_gds_push_workflow.py -m integration -v
```

The tests create a disposable CA, domain, device, and credentials in the Django
test database. Each scenario starts the actual `server.py` in a subprocess on an
unused loopback port with its own temporary PKI directory. No manually running
OPC UA server or existing device configuration is needed.

Both password-based and certificate-only administrator access are exercised:

- Discovery and encrypted authenticated connection through `GdsPushService`.
- TrustList upload, certificate/CRL installation, and validator reload.
- Server-owned CSR, signing through Trustpoint's real issuance pipeline, and key/certificate persistence.
- Server restart and verification that the new certificate is presented and accepted.
- Invocation of the periodic server-renewal and domain-renewal tasks without waiting for their intervals.
- Issuance of a fresh client identity and revocation of its predecessor.
- A subsequent TrustList upload propagating the new CRL, followed by live rejection of the revoked identity.

Certificate-only access uses an exact certificate allowlist. Its scenario explicitly
updates `admin-client.der` and restarts the target after domain renewal, modelling
the required out-of-band administrator registration. Password-based access needs
no allowlist replacement while the issuing CA remains trusted.

Without `RUN_GDS_INTEGRATION=1`, these tests are skipped by the ordinary pytest run.
Set `GDS_TEST_ARTIFACT_DIR` to retain subprocess logs after a run. Pytest's
`--junitxml` and `--log-file` options can also capture test results and Trustpoint
logs. Temporary private keys are not copied into the report directory.
