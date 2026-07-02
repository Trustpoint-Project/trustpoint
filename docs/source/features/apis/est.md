# EST API Documentation

Enrollment over Secure Transport (EST) is a standard PKI protocol defined in RFC 7030 for certificate enrollment and management over HTTPS.

## Overview

Trustpoint implements EST endpoints that allow devices and clients to:

- Retrieve CA certificates (`/cacerts`)
- Enroll for new certificates (`/simpleenroll`)
- Re-enroll existing certificates (`/simplereenroll`)
- Query CSR attributes (`/csrattrs`) - Not currently supported

## Base URL

All EST endpoints are accessible under:

```
https://<trustpoint-host>/.well-known/est/
```

## URL Structure

Trustpoint supports flexible EST URL structures with optional domain and certificate profile parameters:

### Basic Endpoints (Default Domain)

```
GET  /.well-known/est/cacerts
POST /.well-known/est/simpleenroll
POST /.well-known/est/simplereenroll
```

### With Certificate Profile Only

```
GET  /.well-known/est/~<cert_profile>/cacerts
POST /.well-known/est/~<cert_profile>/simpleenroll
POST /.well-known/est/~<cert_profile>/simplereenroll
```

### With Domain

```
GET  /.well-known/est/<domain>/cacerts
POST /.well-known/est/<domain>/simpleenroll
POST /.well-known/est/<domain>/simplereenroll
```

### With Domain and Certificate Profile

```
GET  /.well-known/est/<domain>/<cert_profile>/cacerts
POST /.well-known/est/<domain>/<cert_profile>/simpleenroll
POST /.well-known/est/<domain>/<cert_profile>/simplereenroll
```

## URL Parameters

### Path Parameters

| Parameter | Description | Required | Example |
|-----------|-------------|----------|---------|
| `domain` | The Trustpoint domain name | No | `production`, `iot_domain` |
| `cert_profile` | Certificate profile identifier (prefixed with `~` when domain is omitted) | No | `~device_cert`, `server_cert` |

## Endpoints

### 1. Get CA Certificates

Retrieves the CA certificate chain for the specified domain.

**Endpoint:** `GET /cacerts` or `GET /<domain>/cacerts`

**Authentication:** None required

**Request Headers:**
```http
Accept: application/pkcs7-mime
```

**Response:**

- **Status Code:** `200 OK`
- **Content-Type:** `application/pkcs7-mime`
- **Content-Transfer-Encoding:** `base64`
- **Body:** Base64-encoded PKCS#7 certificate chain

**Example Request:**
```bash
curl -X GET \
  https://trustpoint.example.com/.well-known/est/production/cacerts \
  -H "Accept: application/pkcs7-mime" \
  --output cacerts.p7
```

**Example Response:**
```
MIID...
(base64-encoded PKCS#7 data, wrapped at 64 characters per line)
...AAAA==
```

---

### 2. Simple Enrollment

Request a new certificate from Trustpoint.

**Endpoint:** `POST /simpleenroll` or `POST /<domain>/<cert_profile>/simpleenroll`

**Authentication:** Required (see [Authentication](#authentication))

**Request Headers:**
```http
Content-Type: application/pkcs10
Content-Transfer-Encoding: base64
Authorization: Basic <base64-credentials>
```

**Request Body:**

Base64-encoded PKCS#10 Certificate Signing Request (CSR)

**Response:**

- **Status Code:** `200 OK` (success)
- **Content-Type:** `application/pkcs7-mime`
- **Content-Transfer-Encoding:** `base64`
- **Body:** Base64-encoded PKCS#7 containing the issued certificate

**Example with OpenSSL:**

1. Generate a private key and CSR:
```bash
openssl req -new -newkey rsa:2048 -nodes \
  -keyout device.key \
  -out device.csr \
  -subj "/CN=Device12345"
```

2. Convert CSR to base64:
```bash
openssl req -in device.csr -outform DER | base64 > device.csr.b64
```

3. Send enrollment request:
```bash
curl -X POST \
  https://trustpoint.example.com/.well-known/est/production/simpleenroll \
  -H "Content-Type: application/pkcs10" \
  -H "Content-Transfer-Encoding: base64" \
  -u "username:password" \
  --data @device.csr.b64 \
  --output device_cert.p7
```

4. Extract certificate from PKCS#7:
```bash
openssl pkcs7 -in device_cert.p7 -inform DER -print_certs -out device_cert.pem
```

---

### 3. Simple Re-enrollment

Re-enroll an existing certificate (renewal with the same or new key).

**Endpoint:** `POST /simplereenroll` or `POST /<domain>/<cert_profile>/simplereenroll`

**Authentication:** Mutual TLS required (client certificate authentication)

**Request Headers:**
```http
Content-Type: application/pkcs10
Content-Transfer-Encoding: base64
```

**Request Body:**

Base64-encoded PKCS#10 Certificate Signing Request (CSR)

**Response:**

- **Status Code:** `200 OK` (success)
- **Content-Type:** `application/pkcs7-mime`
- **Content-Transfer-Encoding:** `base64`
- **Body:** Base64-encoded PKCS#7 containing the renewed certificate

**Example with curl and mTLS:**

```bash
curl -X POST \
  https://trustpoint.example.com/.well-known/est/production/simplereenroll \
  -H "Content-Type: application/pkcs10" \
  -H "Content-Transfer-Encoding: base64" \
  --cert current_cert.pem \
  --key current_key.pem \
  --data @new_device.csr.b64 \
  --output renewed_cert.p7
```

---

## Authentication

Trustpoint supports multiple EST authentication methods:

### 1. HTTP Basic Authentication (Username/Password)

Used for initial enrollment when no certificate exists.

**Header:**
```http
Authorization: Basic <base64-encoded-credentials>
```

Where `<base64-encoded-credentials>` is the base64 encoding of `username:password`.

**Example:**
```bash
# Username: device123, Password: secret
echo -n "device123:secret" | base64
# Result: ZGV2aWNlMTIzOnNlY3JldA==

curl -X POST \
  https://trustpoint.example.com/.well-known/est/simpleenroll \
  -H "Authorization: Basic ZGV2aWNlMTIzOnNlY3JldA==" \
  -H "Content-Type: application/pkcs10" \
  --data @device.csr.b64
```

**Use case:** Initial device onboarding

---

### 2. Mutual TLS (mTLS)

Used for re-enrollment when the device already has a certificate.

**Configuration:** The client must present its current certificate during the TLS handshake.

**Example with curl:**
```bash
curl -X POST \
  https://trustpoint.example.com/.well-known/est/simplereenroll \
  --cert client_cert.pem \
  --key client_key.pem \
  --cacert trustpoint_ca.pem \
  -H "Content-Type: application/pkcs10" \
  --data @new_csr.b64
```

**Use case:** Certificate renewal, re-key operations

---

### 3. IDevID-Based Authentication

Devices can authenticate using their Initial Device Identifier (IDevID) certificate for initial enrollment.

**Configuration:** The client presents its IDevID certificate during the TLS handshake for `/simpleenroll`.

**Use case:** Zero-touch onboarding, secure initial enrollment

---

## Response Status Codes

| Status Code | Description |
|-------------|-------------|
| `200 OK` | Request processed successfully |
| `400 Bad Request` | Invalid request format or missing required fields |
| `401 Unauthorized` | Authentication failed (invalid credentials or missing certificate) |
| `403 Forbidden` | Authorization failed (valid auth but insufficient permissions) |
| `404 Not Found` | Endpoint not found or domain does not exist |
| `500 Internal Server Error` | Server error during processing |

## Content Types

### Request Content Types

| Content-Type | Description | Used In |
|--------------|-------------|---------|
| `application/pkcs10` | PKCS#10 Certificate Signing Request | `/simpleenroll`, `/simplereenroll` |

### Response Content Types

| Content-Type | Description | Used In |
|--------------|-------------|---------|
| `application/pkcs7-mime` | PKCS#7 certificate or certificate chain | `/cacerts`, `/simpleenroll`, `/simplereenroll` |

## Complete Enrollment Example

Here's a complete example of enrolling a device using EST:

### Step 1: Retrieve CA Certificates

```bash
curl -X GET \
  https://trustpoint.example.com/.well-known/est/production/cacerts \
  -o cacerts.p7

# Convert to PEM for verification
openssl pkcs7 -in cacerts.p7 -inform DER -print_certs -out ca_chain.pem
```

### Step 2: Generate Key and CSR

```bash
# Generate private key
openssl genrsa -out device.key 2048

# Create CSR
openssl req -new -key device.key \
  -out device.csr \
  -subj "/CN=MyDevice/O=MyOrganization/C=US"

# Convert to base64
openssl req -in device.csr -outform DER | base64 > device.csr.b64
```

### Step 3: Enroll for Certificate

```bash
curl -X POST \
  https://trustpoint.example.com/.well-known/est/production/device_cert/simpleenroll \
  -H "Content-Type: application/pkcs10" \
  -H "Content-Transfer-Encoding: base64" \
  -u "device123:MyPassword" \
  --cacert ca_chain.pem \
  --data @device.csr.b64 \
  -o device_cert.p7

# Extract certificate
openssl pkcs7 -in device_cert.p7 -inform DER -print_certs -out device_cert.pem
```

### Step 4: Verify Certificate

```bash
# Verify certificate against CA
openssl verify -CAfile ca_chain.pem device_cert.pem
```

## Integration with Trustpoint Workflows

EST requests can trigger Trustpoint Workflow2 approval processes for:

- Certificate issuance (`/simpleenroll`)
- Certificate renewal (`/simplereenroll`)

Workflows allow automated or manual approval based on configurable policies.

## Security Considerations

1. **HTTPS Required**: EST protocol requires TLS/HTTPS. All communications must be encrypted.
2. **Certificate Validation**: Always verify the Trustpoint server certificate before sending requests.
3. **Credential Protection**: 
   - Use strong passwords for HTTP Basic Authentication
   - Protect private keys using hardware security modules (HSMs) or secure key storage
4. **Mutual TLS**: For production environments, configure mutual TLS for enhanced security.
5. **Certificate Expiry**: Monitor certificate expiration and use `/simplereenroll` before expiry.
6. **CSR Validation**: Ensure CSRs are properly formatted and contain accurate subject information.

## Error Handling

EST errors are returned as HTTP status codes with plain text error messages:

**Example Error Response:**
```http
HTTP/1.1 401 Unauthorized
Content-Type: text/plain

Authentication failed
```

Common error scenarios:

- **401 Unauthorized**: Invalid username/password or missing/invalid client certificate
- **403 Forbidden**: Valid authentication but insufficient permissions for the requested operation
- **404 Not Found**: Domain does not exist or invalid endpoint
- **500 Internal Server Error**: Server-side processing error (check server logs)

## Further Reading

- [RFC 7030 - Enrollment over Secure Transport (EST)](https://www.rfc-editor.org/rfc/rfc7030)
- [RFC 7030 - EST Errata](https://www.rfc-editor.org/errata_search.php?rfc=7030)
- [RFC 2986 - PKCS#10: Certification Request Syntax](https://www.rfc-editor.org/rfc/rfc2986)
- [RFC 5272 - Certificate Management over CMS (CMC)](https://www.rfc-editor.org/rfc/rfc5272)
