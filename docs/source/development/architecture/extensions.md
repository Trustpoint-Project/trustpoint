# Roadmap

This document describes extension points, planned features, known limitations, and future architectural directions for Trustpoint.

## Planned Features

1. **Web UI Automation**
   - Expand automated certificate deployment, renewal and trust-store management for industrial devices without standard certificate management protocols.
   - Develop reusable, versioned automation profiles with device/firmware compatibility checks, credential handling and verification of successful deployment.

2. **Trustpoint Agents**
   - Extend agent-based certificate and private-key lifecycle operations on remote endpoints, machines and edge gateways.
   - Improve job execution, status reporting, recovery and operation across segmented or intermittently connected OT networks.

3. **Industrial Device Integration Profiles**
   - Define a common integration model for onboarding, enrollment, certificate installation, trust-list updates, renewal and revocation/replacement.
   - Provide tested reference integrations for selected industrial devices, covering Web UI, agent, OPC UA GDS Push and vendor-specific interfaces.

4. **OPC UA GDS Push and Native Protocols**
   - Expand compatibility testing for OPC UA GDS Push and improve interoperability with EST, CMP, SCEP and relevant vendor-specific protocols.
   - Validate complete device lifecycles, including initial enrollment, renewal, trust-list updates and error recovery, rather than issuance alone.

5. **Automation Reliability and Operations**
   - Improve scheduling, retries, timeouts, maintenance-window handling, job history and actionable diagnostics.
   - Add end-to-end validation and clear visibility into whether certificates were successfully installed and activated on the device.

6. **Extension Architecture**
   - Document and stabilize extension interfaces for device adapters, automation actions and external integrations, building on the existing architecture.
   - Support maintainable, independently testable integrations without device-specific changes throughout Trustpoint Core.

7. **Microsoft AD CS Integration**
   - Develop and validate a dedicated connector for Microsoft Active Directory Certificate Services as an upstream issuing CA.
   - Define certificate-template mapping, enrollment/renewal/revocation behavior, authentication, permissions and error handling for the supported AD CS interfaces.

8. **Additional Enterprise PKI Integrations**
   - Extend the RA connector framework for additional enterprise PKIs, including Keyfactor Command/EJBCA integration scenarios where technically appropriate.
   - Support mapping between Trustpoint certificate profiles, upstream CA policies and connector-specific capabilities.

9. **REST API and Automation Interfaces**
   - Close remaining API coverage gaps for devices, certificates, CAs, lifecycle jobs and agent orchestration.
   - Improve API consistency, access control, versioning, OpenAPI documentation and integration examples where needed.

10. **Distributed Trustpoint**
    - Develop a model for cascading instances deployed at OEM-product, machine and factory levels.
    - Explore centralized inventory, status monitoring, policy distribution and delegated operations while respecting OT network boundaries.

11. **Security and Operational Hardening**
    - Extend HSM/KMS and TPM-backed key-management scenarios, CA rollover, authentication and audit-integrity capabilities.
    - Improve deployment, updates, backup/recovery and monitoring for production environments.
