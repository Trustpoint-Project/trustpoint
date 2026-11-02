# CMP API Documentation

Certificate Management Protocol (CMP) is a standard PKI protocol defined in RFC 4210 and RFC 9480 for certificate lifecycle management.

## Overview

Trustpoint implements CMP endpoints that allow devices and clients to:

- Request initial certificates (Initialization Request - IR)
- Request additional certificates (Certificate Request - CR)
- Update valid certificates (Key Update Request - KUR / Key Update Response - KUP)
- Confirm certificate acceptance (Certificate Confirm - certConf)
- Revoke certificates (Revocation Request - RR)

## Base URL

All CMP endpoints are accessible under:

```
https://<trustpoint-host>/.well-known/cmp/
```

## URL Structure

RFC 9480 Section 3.3 and RFC 9483 Section 6.1 define the following URI shapes:

```
/.well-known/cmp
/.well-known/cmp/<operation>
/.well-known/cmp/p/<name>
/.well-known/cmp/p/<name>/<operation>
```

`<name>` is one path segment whose meaning is configured by the server. Trustpoint
can encode a domain and profile in that segment as `<domain>~<cert_profile>`.
For example, the standard form for a key update is:

```
POST /.well-known/cmp/p/production~tls_server/keyupdate
```

The HTTP operation label is `keyupdate`, while the request and response bodies are
`kur` and `kup`. Send `pollReq` and `certConf` to the same enrollment endpoint,
including its `/keyupdate` suffix. Operation labels are optional; when absent,
Trustpoint infers the operation from the CMP body.

Trustpoint accepts the routes below. Separate domain and profile path segments
are compatibility extensions beyond the standard URI shapes above.

### Basic Endpoints

```
POST /.well-known/cmp/
POST /.well-known/cmp/<operation>
```

### With Certificate Profile

```
POST /.well-known/cmp/p/~<cert_profile>
POST /.well-known/cmp/p/~<cert_profile>/<operation>
```

### With Domain

```
POST /.well-known/cmp/p/<domain>
POST /.well-known/cmp/p/<domain>/<operation>
POST /.well-known/cmp/p/<domain>/<cert_profile>
POST /.well-known/cmp/p/<domain>/<cert_profile>/<operation>
```

### With Domain and Profile (Tilde Syntax)

```
POST /.well-known/cmp/p/<domain>~<cert_profile>
POST /.well-known/cmp/p/<domain>~<cert_profile>/<operation>
```

## URL Parameters

### Path Parameters

| Parameter | Description | Required | Example |
|-----------|-------------|----------|---------|
| `domain` | The Trustpoint domain name | No | `production`, `iot_domain` |
| `cert_profile` | Certificate profile identifier | No | `device_cert`, `server_cert` |
| `operation` | HTTP operation label | No | `initialization`, `certification`, `keyupdate`, `revocation` |

**Special domain values:**
- `.` or `_` represents an empty domain segment (default domain)

### Operations

| Operation | Description | RFC Reference |
|-----------|-------------|---------------|
| `initialization` | Initialization Request / Response (`ir` / `ip`) | RFC 9483 Section 4.1.1 |
| `certification` | Certificate Request / Response (`cr` / `cp`) | RFC 9483 Section 4.1.2 |
| `keyupdate` | Key Update Request / Response (`kur` / `kup`) | RFC 9483 Section 4.1.3 |
| `revocation` | Revocation Request / Response (`rr` / `rp`) | RFC 9483 Section 4.2 |

`certConf` and `pollReq` are follow-up message bodies, not separate HTTP operation
labels. Use the endpoint of the original enrollment operation for both.

## Request Format

### HTTP Method

All CMP requests use the `POST` method.

### Headers

```yaml
Content-Type: application/pkixcmp
Content-Length: <message-length>
```

### Body

The request body must contain a DER-encoded CMP PKIMessage structure as defined in RFC 4210.

## Response Format

### Headers

```yaml
Content-Type: application/pkixcmp
```

### Body

The response body contains a DER-encoded CMP PKIMessage with the operation result.

### Status Codes

| Status Code | Description |
|-------------|-------------|
| `200 OK` | Request processed successfully |
| `400 Bad Request` | Invalid request format or parameters |
| `401 Unauthorized` | Authentication failed |
| `403 Forbidden` | Authorization failed |
| `404 Not Found` | Invalid operation or endpoint |
| `500 Internal Server Error` | Server error during processing |

## Authentication

Trustpoint supports multiple CMP authentication methods:

### 1. Shared Secret (Password-Based MAC)

Used for initial enrollment when no certificate exists.

**Protection:** Message Authentication Code (MAC) based on a shared secret

**Use case:** Initial device onboarding

### 2. Signature-Based

Used when the device already has a certificate (e.g., IDevID).

**Protection:** Digital signature using device's private key

**Use case:** Certificate renewal, re-key operations

### 3. IDevID-Based Authentication

Devices can authenticate using their Initial Device Identifier (IDevID) certificate.

**Protection:** Signature with IDevID private key

**Use case:** Zero-touch onboarding, secure initial enrollment

## Examples

Select **Permitted CMP HMAC algorithms** in Management → Settings → Advanced security settings
(`SecurityConfig.permitted_cmp_hmac_algorithms`). The selected algorithm OIDs determine which
shared-secret requests are accepted; an empty selection disables CMP shared-secret authentication.
The Lab and Brownfield presets select HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, and HMAC-SHA512.
Industrial, Hardened, and Critical select SHA256/384/512 and prevent enabling other algorithms.
Lab / Custom allows selecting all implemented HMACs, including SHA224, SHA3 variants, and MD5.

OpenSSL defaults to HMAC-SHA1. Select it to accept that default, or explicitly set
`-mac hmacWithSHA256` when HMAC-SHA256 is permitted by your policy.
The environment restriction `TP_SECURITY_PERMITTED_CMP_HMAC_ALGORITHMS` accepts comma-separated
names such as `HMAC_SHA384,HMAC_SHA512`; an empty value disables all shared-secret MACs.
Environment synchronization may only restrict the selected preset, except in Lab / Custom.
The previous `TP_SECURITY_ALLOW_CMP_HMAC_SHA1` restriction remains supported for compatibility.
The CMP MAC policy is separate from certificate signature hashes and the PBM one-way function.

### Example 1: Initial Certificate Request with Shared Secret

```bash
openssl cmp \
  -cmd ir \
  -server https://trustpoint.example.com/.well-known/cmp/p/production \
  -ref device-12345 \
  -secret pass:MySharedSecret \
  -mac hmacWithSHA256 \
  -subject "/CN=Device 12345" \
  -newkey device_key.pem \
  -certout device_cert.pem \
  -chainout chain.pem
```

### Example 2: Certificate Request with Profile

```bash
openssl cmp \
  -cmd ir \
  -server https://trustpoint.example.com/.well-known/cmp/p/~iot_device \
  -ref device-12345 \
  -secret pass:MySharedSecret \
  -mac hmacWithSHA256 \
  -subject "/CN=IoT Device 12345" \
  -newkey device_key.pem \
  -certout device_cert.pem
```

### Example 3: Key Update Request

Use the certificate being updated to sign the request. It must be active, issued by
the addressed CA, and associated with the authenticated device and domain. The
requested subject and SAN must preserve the existing identity; the selected
certificate profile must preserve that identity as well. The optional CRMF
`oldCertID` control must identify the signing certificate. PBM-protected key
updates are rejected.

The HTTP operation label is `keyupdate`; `kur` and `kup` are CMP body types.
The response uses `kup`, including `waiting` and authenticated request rejection
responses. Send subsequent polling and confirmation messages to the same endpoint,
using the original signing certificate. Both implicit and explicit confirmation
are supported. Successful updates leave the old certificate valid until its normal
expiry or an explicit revocation.

```bash
openssl cmp \
  -cmd kur \
  -server https://trustpoint.example.com/.well-known/cmp/p/production~tls_server/keyupdate \
  -cert current_cert.pem \
  -key current_key.pem \
  -newkey new_key.pem \
  -certout updated_cert.pem
```

### Example 4: Certificate Revocation

```bash
openssl cmp \
  -cmd rr \
  -server https://trustpoint.example.com/.well-known/cmp/p/production/revocation \
  -cert cert_to_revoke.pem \
  -key cert_key.pem
```

## Error Handling

CMP errors are returned within the CMP PKIMessage structure using PKIStatus values:

| PKIStatus | Description |
|-----------|-------------|
| `0` | Accepted - Request successful |
| `1` | Granted with modifications |
| `2` | Rejection - Request rejected |
| `3` | Waiting - Request pending |
| `4` | Revocation Warning |
| `5` | Revocation Notification |
| `6` | Key Update Warning |

Detailed error information is provided in the PKIStatusInfo structure within the response.

## Security Considerations

1. **HTTPS Required**: Always use HTTPS in production to protect credentials and certificates in transit
2. **Shared Secrets**: Store shared secrets securely and rotate them regularly
3. **Certificate Validation**: Verify the Trustpoint server certificate before sending requests
4. **Key Protection**: Protect private keys using hardware security modules (HSMs) or secure key storage
5. **Replay Protection**: CMP includes nonces and transaction IDs to prevent replay attacks

## Integration with Trustpoint Workflows

The registered CMP request triggers are `cmp.initialization`, `cmp.certification`,
`cmp.keyupdate`, and `cmp.certconf`. Enrollment and key update workflows can gate issuance and
use CMP transaction/polling handling while waiting for approval. Certificate
confirmation has its own trigger.

There is no registered CMP revocation-request trigger. A `certificate.revoked`
lifecycle event reports a revocation; it is not a pre-revocation approval gate.
See the [workflow guide](../workflows/index.md) for the available triggers and
their exact request/response behavior.

## Further Reading

- [RFC 4210 - Certificate Management Protocol (CMP)](https://www.rfc-editor.org/rfc/rfc4210)
- [RFC 9480 - Certificate Management Protocol (CMP) Updates](https://www.rfc-editor.org/rfc/rfc9480)
- [RFC 6712 - CMP Algorithms](https://www.rfc-editor.org/rfc/rfc6712)
