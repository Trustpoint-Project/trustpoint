# CMP API Documentation

Certificate Management Protocol (CMP) is a standard PKI protocol defined in RFC 4210 and RFC 9480 for certificate lifecycle management.

## Overview

Trustpoint implements CMP endpoints that allow devices and clients to:

- Request initial certificates (Initialization Request - IR)
- Request certificate updates (Key Update Request - KUR / Certificate Request - CR)
- Confirm certificate acceptance (Certificate Confirm - certConf)
- Revoke certificates (Revocation Request - RR)

## Base URL

All CMP endpoints are accessible under:

```
https://<trustpoint-host>/.well-known/cmp/
```

## URL Structure

Trustpoint supports flexible CMP URL structures according to RFC 9480 Section 3.3:

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
| `operation` | CMP operation type | No | `ir`, `cr`, `kur`, `rr` |

**Special domain values:**
- `.` or `_` represents an empty domain segment (default domain)

### Operations

| Operation | Description | RFC Reference |
|-----------|-------------|---------------|
| `ir` | Initialization Request - Request initial certificate | RFC 4210 Section 5.1.1 |
| `cr` | Certificate Request - Request certificate | RFC 4210 Section 5.1.2 |
| `kur` | Key Update Request - Update certificate with new key | RFC 4210 Section 5.1.8 |
| `rr` | Revocation Request - Revoke a certificate | RFC 4210 Section 5.1.11 |
| `certConf` | Certificate Confirmation - Confirm receipt of certificate | RFC 4210 Section 5.1.13 |

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

### Example 1: Initial Certificate Request with Shared Secret

```bash
openssl cmp \
  -cmd ir \
  -server https://trustpoint.example.com/.well-known/cmp/p/production \
  -ref device-12345 \
  -secret pass:MySharedSecret \
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
  -subject "/CN=IoT Device 12345" \
  -newkey device_key.pem \
  -certout device_cert.pem
```

### Example 3: Key Update Request

```bash
openssl cmp \
  -cmd kur \
  -server https://trustpoint.example.com/.well-known/cmp/p/production/kur \
  -cert current_cert.pem \
  -key current_key.pem \
  -newkey new_key.pem \
  -certout updated_cert.pem
```

### Example 4: Certificate Revocation

```bash
openssl cmp \
  -cmd rr \
  -server https://trustpoint.example.com/.well-known/cmp/p/production/rr \
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

CMP requests can trigger Trustpoint Workflow2 approval processes for:

- Certificate issuance
- Certificate renewal
- Certificate revocation

Workflows allow automated or manual approval based on configurable policies.

## Further Reading

- [RFC 4210 - Certificate Management Protocol (CMP)](https://www.rfc-editor.org/rfc/rfc4210)
- [RFC 9480 - Certificate Management Protocol (CMP) Updates](https://www.rfc-editor.org/rfc/rfc9480)
- [RFC 6712 - CMP Algorithms](https://www.rfc-editor.org/rfc/rfc6712)
