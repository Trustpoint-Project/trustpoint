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

## Notes

Only one TLS certificate can be active at a time. Activating a new certificate replaces the currently used TLS certificate.

Self-signed certificates are useful for testing or closed environments. For production deployments, use a TLS certificate trusted by the clients that access Trustpoint.