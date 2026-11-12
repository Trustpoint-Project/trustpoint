# TLS Settings

Trustpoint uses TLS certificates to secure access to the web interface and related HTTPS endpoints.

Access: **Management > TLS**

## Overview

The TLS page lists all TLS server certificates known to Trustpoint. A certificate can be viewed, downloaded, deleted, or activated as the currently used TLS certificate.

## Actions

Available actions:

- **Details**: show certificate information.
- **Download**: download a single certificate.
- **Activate**: use the certificate for TLS.
- **Add new TLS Certificate**: import or create a TLS certificate.
- **Download selected**: export selected certificates as `tar.gz` or `zip`.
- **Delete selected**: remove selected certificates.

## Adding a TLS Certificate

A TLS server certificate can be provided in four ways:

- import an existing credential from a **PKCS#12** file
- import the private key and certificate from **separate files**
- generate a **CSR** for an external PKI and upload the issued certificate
- select a **Management CA** and let Trustpoint issue the certificate

When a management CA is selected, the TLS key type is bound to that CA's public
key type. Trustpoint then either signs the certificate locally (internal management
CA) or forwards the request to the external PKI configured for an EST/CMP management
CA acting as Registration Authority.

## Notes

Only one TLS certificate can be active at a time. Activating a new certificate replaces the currently used TLS certificate.

Self-signed certificates are useful for testing or closed environments. For production deployments, use a TLS certificate trusted by the clients that access Trustpoint.