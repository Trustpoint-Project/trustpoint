# Extensibility and Future Development

This document describes extension points, planned features, known limitations, and future architectural directions for Trustpoint.

## Planned Features

- Extended REST API: Comprehensive API for certificate, device, CA and lifecycle management, including authentication, versioning and OpenAPI documentation.
- HSM & TPM Integration: Support for PKCS#11, REST-based HSM/KMS integration, TPM-backed keys and device attestation.
- Cascading Trustpoint Instances: Centralized monitoring, certificate inventory, remote lifecycle operations, hierarchical management and policy distribution.
- Extended CA Rollover: Support for requesting rollover CA certificates, external and offline parent CAs, automated transitions and CA retirement.
- Enhanced User Authentication: Client certificate authentication (mTLS) using managed CAs, certificate-to-user mapping and role-based authorization.
- Extended Registration Authority (RA): Microsoft AD CS connector, external CA integration framework and certificate template mapping.
- Certificate Transparency & Audit Logging: Certificate transparency for private PKIs, cryptographically signed audit logs, verification capabilities and SIEM integration.
- Web UI Automation: Automated certificate deployment and renewal for Brownfield devices using reusable automation profiles and distributed Trustpoint Agents.
