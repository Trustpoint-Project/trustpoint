# REST PKI API - Certificate Enrollment

Trustpoint provides a simplified REST API for certificate enrollment and re-enrollment operations. This is a JSON-based alternative to the standard EST and CMP protocols, designed for ease of integration.

> **Note**: This is the **Certificate Enrollment API** (`/rest/`). For general Trustpoint administration and management, see the [Trustpoint Management API](rest_api.md) (`/api/`).

## Overview

The REST PKI API allows devices and clients to:

- Enroll for new certificates (`/enroll`)
- Re-enroll existing certificates (`/reenroll`)

## Base URL

All REST PKI endpoints are accessible under:

```
https://<trustpoint-host>/rest/
```

## URL Structure

The REST API uses a simple URL structure with domain and optional certificate profile parameters:

### With Domain and Certificate Profile

```
POST /rest/<domain>/<cert_profile>/enroll
POST /rest/<domain>/<cert_profile>/reenroll
```

### With Domain Only (Default Profile)

```
POST /rest/<domain>/enroll
```

When the certificate profile is omitted, the default profile `domain_credential` is used.

## URL Parameters

### Path Parameters

| Parameter | Description | Required | Example |
|-----------|-------------|----------|---------|
| `domain` | The Trustpoint domain name | Yes | `production`, `iot_domain` |
| `cert_profile` | Certificate profile identifier | No (defaults to `domain_credential`) | `device_cert`, `server_cert` |

## Endpoints

### 1. Enroll (Initial Certificate Request)

Request a new certificate from Trustpoint.

**Endpoint:** `POST /<domain>/<cert_profile>/enroll`

**Authentication:** Required (see [Authentication](#authentication))

**Request Headers:**
```http
Content-Type: application/json
Authorization: Basic <base64-credentials>
```

**Request Body (JSON):**
```json
{
    "csr": "<PEM or Base64-DER encoded PKCS#10 CSR>"
}
```

**Response:**

- **Status Code:** `200 OK` (success)
- **Content-Type:** `application/json`

**Response Body (JSON):**
```json
{
    "certificate": "<PEM certificate>",
    "certificate_chain": [
        "<PEM CA certificate>",
        "<PEM root certificate>",
        "..."
    ]
}
```

**Example Request:**

```bash
curl -X POST \
  https://trustpoint.example.com/rest/production/device_cert/enroll \
  -H "Content-Type: application/json" \
  -u "username:password" \
  -d '{
    "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIICvDCCAaQCAQAwdzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx\n...\n-----END CERTIFICATE REQUEST-----"
  }'
```

**Example Response:**

```json
{
    "certificate": "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKJ...\n-----END CERTIFICATE-----",
    "certificate_chain": [
        "-----BEGIN CERTIFICATE-----\nMIIDBTCCAe2gAwIBAgIQN...\n-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE-----\nMIIDBjCCAe6gAwIBAgIBAD...\n-----END CERTIFICATE-----"
    ]
}
```

---

### 2. Re-enroll (Certificate Renewal)

Re-enroll an existing certificate (renewal with the same or new key).

**Endpoint:** `POST /<domain>/<cert_profile>/reenroll`

**Authentication:** Mutual TLS required (client certificate authentication)

**Request Headers:**
```http
Content-Type: application/json
```

**Request Body (JSON):**
```json
{
    "csr": "<PEM or Base64-DER encoded PKCS#10 CSR>"
}
```

**Response:**

- **Status Code:** `200 OK` (success)
- **Content-Type:** `application/json`

**Response Body (JSON):**
```json
{
    "certificate": "<PEM certificate>",
    "certificate_chain": [
        "<PEM CA certificate>",
        "<PEM root certificate>",
        "..."
    ]
}
```

**Example Request:**

```bash
curl -X POST \
  https://trustpoint.example.com/rest/production/device_cert/reenroll \
  -H "Content-Type: application/json" \
  --cert current_cert.pem \
  --key current_key.pem \
  -d '{
    "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIICvDCCAaQCAQAwdzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx\n...\n-----END CERTIFICATE REQUEST-----"
  }'
```

**Example Response:**

```json
{
    "certificate": "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKJ...\n-----END CERTIFICATE-----",
    "certificate_chain": [
        "-----BEGIN CERTIFICATE-----\nMIIDBTCCAe2gAwIBAgIQN...\n-----END CERTIFICATE-----"
    ]
}
```

---

## Authentication

The REST PKI API supports two authentication methods:

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
curl -X POST \
  https://trustpoint.example.com/rest/production/enroll \
  -H "Content-Type: application/json" \
  -u "device123:secret" \
  -d '{"csr": "..."}'
```

**Use case:** Initial device onboarding

---

### 2. Mutual TLS (mTLS)

Used for re-enrollment when the device already has a certificate.

**Configuration:** The client must present its current certificate during the TLS handshake.

**Example:**
```bash
curl -X POST \
  https://trustpoint.example.com/rest/production/reenroll \
  -H "Content-Type: application/json" \
  --cert client_cert.pem \
  --key client_key.pem \
  --cacert trustpoint_ca.pem \
  -d '{"csr": "..."}'
```

**Use case:** Certificate renewal, re-key operations

---

## CSR Format

The Certificate Signing Request (CSR) can be provided in two formats:

### 1. PEM Format (Recommended)

```json
{
    "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIICvDCCAaQCAQAwdzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx\nFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDzANBgNVBAoMBk15T3JnMRAwDgYDVQQL\nDAdNeVVuaXQxGDAWBgNVBAMMD015RGV2aWNlTmFtZTEwggEiMA0GCSqGSIb3DQEB\nAQUAA4IBDwAwggEKAoIBAQC...\n-----END CERTIFICATE REQUEST-----"
}
```

### 2. Base64-Encoded DER Format

```json
{
    "csr": "MIICvDCCAaQCAQAwdzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx..."
}
```

## Response Status Codes

| Status Code | Description |
|-------------|-------------|
| `200 OK` | Request processed successfully |
| `400 Bad Request` | Invalid request format, malformed JSON, or invalid CSR |
| `401 Unauthorized` | Authentication failed (invalid credentials or missing certificate) |
| `403 Forbidden` | Authorization failed (valid auth but insufficient permissions) |
| `404 Not Found` | Domain or certificate profile does not exist |
| `500 Internal Server Error` | Server error during processing |

## Error Response Format

When an error occurs, the API returns a JSON response with error details:

**Example Error Response:**
```json
{
    "error": "Authentication failed",
    "detail": "Invalid username or password"
}
```

Common error scenarios:

- **400 Bad Request**: Invalid JSON format, missing `csr` field, or malformed CSR
- **401 Unauthorized**: Invalid username/password or missing/invalid client certificate
- **403 Forbidden**: Valid authentication but insufficient permissions
- **404 Not Found**: Specified domain or certificate profile does not exist
- **500 Internal Server Error**: Server-side processing error (check server logs)
