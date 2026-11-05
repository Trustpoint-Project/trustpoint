# SCEP API Documentation

Simple Certificate Enrollment Protocol (SCEP) is a PKI enrollment protocol specified in [RFC 8894](https://www.rfc-editor.org/rfc/rfc8894). Trustpoint exposes SCEP endpoints for initial certificate enrollment and certificate renewal in industrial and other device environments.

## Overview

Trustpoint's SCEP server supports:

- Discovery of server capabilities (`GetCACaps`).
- Retrieval of the SCEP server certificate and CA chain (`GetCACert`).
- Initial enrollment using `PKCSReq` (`messageType = 19`) and a device-specific `challengePassword`.
- Certificate-based renewal using `RenewalReq` (`messageType = 17`).
- Transaction retry handling that returns the previously issued certificate for the same request.
- RSA-based enrollment and supported elliptic-curve client keys, subject to the implementation's cryptographic constraints.

**Client compatibility:** Some `sscep` versions send a certificate-authenticated
`PKCSReq` instead of `RenewalReq` when renewing with `-K` and `-O`. The current
handler routes a `PKCSReq` whose signer is not self-signed through renewal
authentication. That path checks the registered signer credential, its status,
domain, and requested identity. Test the intended client version against the
deployed Trustpoint release; message type alone does not establish authorization.

## Base URL

SCEP endpoints are available under:

```text
http://<trustpoint-host>/.well-known/scep/
```

SCEP uses CMS message protection, but **HTTPS is recommended in production**, particularly for discovery and integrity of server/CA certificate distribution. Confirm the applicable proxy and TLS configuration before deploying.

## URL Structure

### Domain endpoint

```text
GET  /.well-known/scep/<domain>/?operation=GetCACaps
GET  /.well-known/scep/<domain>/?operation=GetCACert
POST /.well-known/scep/<domain>/?operation=PKIOperation
```

For POST, `operation=PKIOperation` is optional; omitting it defaults to `PKIOperation` in the current Django view.

### Domain and certificate profile

```text
POST /.well-known/scep/<domain>/<cert_profile>/?operation=PKIOperation
```

A certificate profile in the URL is required for initial enrollment. During certificate-authenticated renewal, Trustpoint resolves the profile associated with the previously issued credential. Discovery requests may use the domain URL without a profile.

**Example:**

```text
http://127.0.0.1/.well-known/scep/arburg/bacnet_sc/
```

### Path and query parameters

| Parameter | Location | Description | Example |
|---|---|---|---|
| `domain` | Path | Trustpoint domain identifier; required | `arburg` |
| `cert_profile` | Path | Certificate profile allowed for the domain; required for initial enrollment | `tls_server`, `bacnet_sc` |
| `operation` | Query | SCEP operation, or implicit `PKIOperation` on POST | `GetCACaps`, `GetCACert`, `PKIOperation` |

## Supported Operations

| Operation | HTTP method | Function | Status |
|---|---|---|---|
| `GetCACaps` | GET | Returns advertised capabilities as newline-separated text | Supported |
| `GetCACert` | GET | Returns SCEP server certificate and certificate chain | Supported |
| `PKIOperation` | POST | Processes initial enrollment and renewal requests | Supported |
| `GetNextCACert` | GET | Retrieves next CA certificates | Not implemented (`501`) |
| `GetCert` | GET | Fetches an issued certificate by identifier | Not implemented (`501`) |
| `GetCRL` | GET | Retrieves a CRL | Not implemented (`501`) |
| `CertPoll` | GET | Polling operation | Not implemented (`501`) |

`GET ...?operation=PKIOperation` returns `405 Method Not Allowed`; use POST.

## Discovery

### GetCACaps

```bash
curl -s 'http://127.0.0.1/.well-known/scep/arburg/?operation=GetCACaps'
```

The current server advertises:

```text
AES
POSTPKIOperation
Renewal
SCEPStandard
SHA-256
```

Response content type: `text/plain`.

### GetCACert

```bash
curl -s 'http://127.0.0.1/.well-known/scep/arburg/?operation=GetCACert' \
  -o ca-certs.p7b
```

The current implementation returns a DER-encoded certificates-only CMS structure with content type `application/x-x509-ca-ra-cert`.

Extract the certificates:

```bash
openssl pkcs7 -inform DER -in ca-certs.p7b -print_certs -out ca-certs.pem
```

**Security:** Do not trust CA certificates solely because they were downloaded from the endpoint. Establish their authenticity using a trusted fingerprint or other out-of-band mechanism.

## PKIOperation Request Format

### HTTP method and headers

```text
POST /.well-known/scep/arburg/tls_server/?operation=PKIOperation
Content-Type: application/x-pki-message
```

Body: binary DER-encoded CMS `SignedData` containing SCEP signed attributes and an encrypted PKCS#10 certificate request (`pkcsPKIEnvelope`). Do not send the CSR PEM directly to this endpoint.

The server rejects oversized requests (currently more than 128 KiB).

### Supported SCEP message types

| Message type | Value | Purpose |
|---|---:|---|
| `PKCSReq` | `19` | Initial enrollment using a self-signed signer and a challenge |
| `RenewalReq` | `17` | Certificate-based renewal using an existing Trustpoint-issued certificate |
| `CertRep` | `3` | Server response to enrollment/renewal |

The server does not currently implement `CertPoll`, `GetCert`, or `GetCRL` through the PKIOperation handler.

## Response Format

### Successful or rejected PKIOperation

```http
HTTP/1.1 200 OK
Content-Type: application/x-pki-message
```

A valid protocol-level request receives a CMS-encoded SCEP `CertRep`, with `pkiStatus` describing the outcome. **HTTP 200 does not necessarily mean certificate issuance succeeded.**

| `pkiStatus` | Meaning |
|---|---|
| `0` | `SUCCESS` |
| `2` | `FAILURE` |
| `3` | `PENDING` (defined by SCEP, not currently issued by this implementation) |

On success, Trustpoint returns the issued certificate inside the encrypted response. CA certificates can be obtained separately using `GetCACert`.

### HTTP errors

| HTTP status | Example reason |
|---|---|
| `400` | Unknown operation, malformed SCEP message, or invalid POST operation |
| `404` | Domain unavailable or no usable SCEP serving credential |
| `405` | `PKIOperation` sent with GET |
| `413` | Request exceeds the configured size limit |
| `500` | Unexpected server failure |
| `501` | Recognized but unsupported discovery operation |

## Authentication and Authorization

### Initial enrollment: challengePassword

Initial enrollment uses a per-device challenge generated by Trustpoint. The client embeds the challenge as the PKCS#9 `challengePassword` attribute in its CSR. The SCEP message is signed by a **self-signed certificate** using the same key and subject as the CSR.

Trustpoint checks that:

1. The challenge maps to a device in the requested domain and matches its stored secret.
2. SCEP is enabled for the device.
3. The challenge has not expired or already been consumed.
4. The requested certificate profile is allowed for the domain.
5. The CSR, SCEP message protection, device authorization, and profile validation succeed.

An initial enrollment challenge is one-time authorization: it is consumed after successful issuance. For supported ECC response-encryption flows, the challenge may still be needed by the client for decrypting replies; retaining it does **not** authorize another enrollment.

### Certificate-based renewal

`RenewalReq` uses an existing issued certificate as the SCEP signer. Trustpoint validates that the certificate is known, associated with the device and domain, valid for renewal, and matches the requested identity. Renewal uses the certificate profile associated with the existing credential.

For `sscep 0.10.0`, `enroll -K <existing-key> -O <existing-cert>` may still send a `PKCSReq`. If your server includes the optional compatibility routing, it can recognize a non-self-signed, known Trustpoint-issued signer and apply the same renewal checks. Without that change, the request will be rejected with `The initial signer certificate must be self-signed.`

## Examples

### Example 1: Prepare the CA certificates

```bash
curl -s 'http://127.0.0.1/.well-known/scep/arburg/?operation=GetCACert' \
  -o ca-certs.p7b
openssl pkcs7 -inform DER -in ca-certs.p7b -print_certs \
  -out ca-certs.pem
```

### Example 2: Create a key and CSR for initial enrollment

Download the device-specific `scep.cnf` from the Trustpoint SCEP help page. It contains the device identity and the current `challengePassword`.

**Example structure** (placeholder only; do not use a real secret in documentation):

```ini
[req]
distinguished_name = dn
attributes = attrs
prompt = no

[dn]
CN = example-device

[attrs]
challengePassword = REPLACE_WITH_DEVICE_CHALLENGE
```

Generate the key and CSR:

```bash
openssl req -new -newkey rsa:2048 -noenc \
  -keyout key.pem -out req.pem -config scep.cnf -sha256
```

Verify that the CSR includes `challengePassword`:

```bash
openssl req -in req.pem -noout -text
openssl req -in req.pem -noout -verify
```

The attribute list must not show `Attributes: (none)`.

### Example 3: Enroll a TLS server certificate with sscep

```bash
sscep enroll \
  -u http://127.0.0.1/.well-known/scep/arburg/tls_server/ \
  -c ca-certs.pem -e ca-certs.pem \
  -k key.pem -r req.pem -l cert.pem \
  -S sha256 -E aes
```

After success, check the certificate identity and public key:

```bash
openssl x509 -in cert.pem -noout -subject -issuer -serial
openssl x509 -in cert.pem -noout -ext basicConstraints
openssl pkey -in key.pem -pubout -outform DER | openssl dgst -sha256
openssl x509 -in cert.pem -pubkey -noout | \
  openssl pkey -pubin -outform DER | openssl dgst -sha256
```

The public-key digests must match. If `sscep` reports a subject mismatch, compare the CSR subject with the issued certificate; a profile may add or modify subject attributes.

### Example 4: Enroll a BACnet/SC certificate

Use a CSR generated for the appropriate device and profile:

```bash
sscep enroll \
  -u http://127.0.0.1/.well-known/scep/arburg/bacnet_sc/ \
  -c ca-certs.pem -e ca-certs.pem \
  -k key.pem -r req.pem -l bacnet-cert.pem \
  -S sha256 -E aes
```

Certificate profiles may inject subject fields and SANs. Ensure the resulting subject is compatible with your SCEP client and the profile's intended identity policy.

### Example 5: Renew using an existing certificate (sscep)

Generate a new key and CSR. The requested identity must match the currently issued certificate, including any required SANs:

```bash
openssl req -new -newkey rsa:2048 -noenc \
  -keyout newkey.pem -out newreq.pem \
  -subj '/CN=example-device' -sha256
```

The example assumes a CN-only certificate. If the existing certificate has additional subject attributes or SANs, reproduce those in the CSR according to the configured profile.

```bash
sscep enroll \
  -u http://127.0.0.1/.well-known/scep/arburg/tls_server/ \
  -c ca-certs.pem -e ca-certs.pem \
  -k newkey.pem -r newreq.pem \
  -K key.pem -O cert.pem \
  -l cert-renewed.pem \
  -S sha256 -E aes
```

**Compatibility note:** In `sscep 0.10.0`, this is an `enroll` command, not `sscep renew`. Check your Trustpoint version for certificate-authenticated `PKCSReq` compatibility before relying on this flow.

## Error Handling

SCEP protocol failures are returned as `CertRep` messages with `pkiStatus = FAILURE` and a `failInfo` value.

| `failInfo` | Value | Meaning / common causes |
|---|---:|---|
| `badAlg` | `0` | Unsupported signature, hash, or key algorithm |
| `badMessageCheck` | `1` | CMS integrity/signature failure, decryption problem, or invalid initial signer |
| `badRequest` | `2` | Unsupported message type, invalid challenge, profile or enrollment policy rejection |
| `badTime` | `3` | Signer certificate time validity failure |
| `badCertId` | `4` | Unknown or invalid signer certificate identity |

Typical `sscep` output:

```text
sscep: valid response from server
sscep: pkistatus: FAILURE
sscep: reason: Integrity check failed
```

The client-side reason may be generic. Check the corresponding Trustpoint `SCEP_REJECTED` audit record (transaction ID, `fail_info`, `reason`) and server logs for the exact rejection cause. Do not log enrollment challenges or private keys.

## Transaction Retries

Trustpoint records successful SCEP transaction IDs with a digest of the original request and a reference to the issued certificate. Replaying the *same* request can return the already issued certificate. Reusing the same transaction ID for a different request is rejected.

A request with a new transaction ID is a new operation—not a retry of the previous transaction.

## Security Considerations

1. **Protect the enrollment challenge:** Downloaded `scep.cnf` files contain a credential capable of authorizing initial enrollment. Limit access, avoid shell history/logging, and remove unnecessary copies.
2. **Authenticate the CA:** Verify downloaded CA certificates and SCEP server identity against an independently trusted source.
3. **Protect private keys:** Keep device private keys local, encrypted or hardware-backed where possible. Never upload them to the SCEP endpoint.
4. **Enforce device/domain ownership:** Renewal requests must validate the existing signer certificate against Trustpoint's issued credential and domain records.
5. **Avoid accidental credential replacement:** Separate new issuance from renewal; do not identify the credential to replace solely by common name. Verify the intended renewal/replacement behavior in the shared credential lifecycle for your release.
6. **Use TLS where available:** CMS protects protocol messages, but HTTPS adds transport protections and helps reduce deployment risks.
7. **Observe supported algorithms and limits:** The current implementation advertises AES, SHA-256, and POST PKIOperation; request processing is bounded by limits including a 128 KiB body size.

## Integration with Trustpoint Workflows

SCEP uses Trustpoint's shared certificate profile validation and issuance pipeline. Authorization is checked before issuance. The current handler does not invoke the workflow enrollment orchestrator and has
no built-in SCEP approval/pending trigger. Do not configure a workflow expecting
it to gate SCEP issuance. Asynchronous SCEP polling is not implemented.

## Current Limitations

- `GetNextCACert`, `GetCert`, `GetCRL`, and `CertPoll` are not implemented.
- SCEP `PENDING` responses and certificate polling are not currently supported.
- Certificate-authenticated `PKCSReq` renewal is implemented, but interoperability must be checked with the intended client version.
- Certificate profiles that alter the subject can cause client-side subject mismatch errors.
- Correct separation of independently issued credentials and renewal replacement is a shared credential lifecycle concern and is not guaranteed by SCEP alone.

## Further Reading

- [RFC 8894 — Simple Certificate Enrolment Protocol](https://www.rfc-editor.org/rfc/rfc8894)
- [RFC 5652 — Cryptographic Message Syntax (CMS)](https://www.rfc-editor.org/rfc/rfc5652)
- [OpenSSL `req` documentation](https://docs.openssl.org/master/man1/openssl-req/)
- [Trustpoint repository](https://github.com/Trustpoint-Project/trustpoint)
