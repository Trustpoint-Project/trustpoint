<p align="center">
  <img src=".github-assets/trustpoint_banner.png" alt="Trustpoint Logo" width="600">
</p>

<h1 align="center">Trustpoint — Security Controls</h1>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/Owner-Trustpoint_Project-0A66C2?style=for-the-badge" alt="Owner"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Version-1.0-555?style=for-the-badge" alt="Version"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Effective-2026--06--26-success?style=for-the-badge" alt="Effective Date"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Review-Quarterly-orange?style=for-the-badge" alt="Review Cycle"/></a>
</p>

**📋 Document Owner:** Trustpoint Project Maintainers | **📄 Version:** 1.0 | **📅 Last Updated:** 2026-06-26
**🔄 Review Cycle:** Quarterly | **⏰ Next Review:** 2026-09-26

---

## **Purpose**

This document describes the technical and organizational security controls used to reduce cybersecurity risks for Trustpoint.

The controls are derived from the threats identified in `THREAT_MODEL.md` and the risks evaluated in `RISK_REGISTER.md`.


---

## **Control Management Process**

Trustpoint follows a structured security documentation chain:

```text
Threat Model → Risk Register → Controls → Evidence → Review
```

| Step             | Document                                                                                                                       | Purpose                                                                                                               |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| 1. Threat Model  | [`THREAT_MODEL.md`](./THREAT_MODEL.md)                                                                             | Identifies threats to Trustpoint                                  |
| 2. Risk Register | [`RISK_REGISTER.md`](./RISK_REGISTER.md)                                                                                   | Groups threats into cybersecurity risks
| 3. Controls      | [`CONTROLS.md`](./CONTROLS.md)    -  [![Critical][badge-you-are-here]]()                                                                                                 | Documents implemented and planned controls                               |
| 4. Evidence      | [`CRA_COMPLIANCE.md`](./CRA_COMPLIANCE.md) · [`SECURITY.md`](./SECURITY.md) · CI/CD artifacts · SBOM                           | Provides evidence for implemented controls, vulnerability handling, release processes, and security maintenance       |
| 5. Review        | [`THREAT_MODEL.md`](./THREAT_MODEL.md) · [`RISK_REGISTER.md`](./RISK_REGISTER.md) · [`CONTROLS.md`](./CONTROLS.md) · [`CRA_COMPLIANCE.md`](./CRA_COMPLIANCE.md) | Ensures that threats, risks, controls, and evidence remain current over time       

---

## **Control Status**

| Status         | Meaning                                                                 |
| -------------- | ----------------------------------------------------------------------- |
| ![Implemented][badge-implemented]    | Control is implemented and evidence is available or partially available |
| ![In Progress][badge-in-progress]    | Control is partially implemented or being improved                      |
| ![Planned][badge-planned]        | Control is identified but not yet implemented                           |
| ![NA][badge-na] | Control is not applicable to the current Trustpoint scope               |

---

## **Control Summary**

| Control Area | Controls | Status |
|-------------|---------:|--------|
| Access control | 4 | ![In Progress][badge-in-progress] |
| Cryptographic security | 2 | ![In Progress][badge-in-progress] |
| Certificate lifecycle security | 4 | ![In Progress][badge-in-progress] |
| Secure deployment | 4 | ![In Progress][badge-in-progress] |
| Logging and monitoring | 2 | ![In Progress][badge-in-progress] |
| Supply chain security | 5 | ![In Progress][badge-in-progress] |
| Vulnerability handling | 4 | ![In Progress][badge-in-progress] |
| **Total Controls** | **25** | **Initial Version** |

---

## **Security Controls**

### **C-TP-001: Authentication**

| Field              | Value                                                                                         |
| ------------------ | --------------------------------------------------------------------------------------------- |
| **Control Area**   | Access Control                                                                                |
| **Related Risks**  | R-TP-002                                                                                      |
| **Description**    | Trustpoint requires authenticated access for administrative and security-relevant operations. |
| **Implementation** | Django authentication · Session handling · API authentication                                 |
| **Status**         | ![Implemented][badge-implemented]  ![In Progress][badge-in-progress]                                                                    |
| **Evidence**       | Django auth configuration · Source code · Security tests                                      |

---

### **C-TP-002: Authorization and RBAC**

| Field              | Value                                                                                                                    |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------ |
| **Control Area**   | Access Control                                                                                                           |
| **Related Risks**  | R-TP-002 · R-TP-004                                                                                                      |
| **Description**    | Authorization checks restrict certificate, policy, lifecycle, and administrative operations to permitted users or roles. |
| **Implementation** | Role-based access control · Permission checks · Admin restrictions                                                       |
| **Status**         | ![Implemented][badge-implemented]  ![In Progress][badge-in-progress]                                                                                                            |
| **Evidence**       | Source code · Authorization tests · Admin documentation                                                                  |

---

### **C-TP-003: Administrative Auditability**

| Field              | Value                                                                                                |
| ------------------ | ---------------------------------------------------------------------------------------------------- |
| **Control Area**   | Access Control                                                                                       |
| **Related Risks**  | R-TP-002 · R-TP-004 · R-TP-007                                                                       |
| **Description**    | Security-relevant administrative actions are logged to support accountability and incident analysis. |
| **Implementation** | Audit logs · Lifecycle event logging                                                                 |
| **Status**         | ![Implemented][badge-implemented]                                                                                          |
| **Evidence**       | Audit log implementation · Logging documentation                                                     |

---

### **C-TP-004: Secure Session and Token Handling**

| Field              | Value                                                                       |
| ------------------ | --------------------------------------------------------------------------- |
| **Control Area**   | Access Control                                                              |
| **Related Risks**  | R-TP-002 · R-TP-007                                                         |
| **Description**    | Sessions and tokens are protected against unauthorized reuse or disclosure. |
| **Implementation** | Secure cookie settings · Token lifetime management · TLS requirement        |
| **Status**         | ![Implemented][badge-implemented]  ![In Progress][badge-in-progress]                                                                |
| **Evidence**       | Django security settings · Deployment documentation                         |

---

### **C-TP-005: CA Private Key Protection**

| Field              | Value                                                                                           |
| ------------------ | ----------------------------------------------------------------------------------------------- |
| **Control Area**   | Cryptographic Security                                                                          |
| **Related Risks**  | R-TP-003 · R-TP-004                                                                             |
| **Description**    | CA private keys are protected against unauthorized access, extraction, modification, or misuse. |
| **Implementation** | PKCS#11 / HSM support · Encrypted storage · Access restrictions                                 |
| **Status**         | ![Implemented][badge-implemented]  ![In Progress][badge-in-progress]                                                                                      |
| **Evidence**       | PKCS#11 integration · HSM configuration · Key management documentation                          |

---

### **C-TP-006: Secure Cryptographic Defaults**

| Field              | Value                                                                                                         |
| ------------------ | ------------------------------------------------------------------------------------------------------------- |
| **Control Area**   | Cryptographic Security                                                                                        |
| **Related Risks**  | R-TP-003 · R-TP-004 · R-TP-006                                                                                |
| **Description**    | Trustpoint should use secure cryptographic algorithms, key sizes, profiles, and protocol settings by default. |
| **Implementation** | Certificate profile validation · Cryptographic parameter restrictions · TLS guidance                          |
| **Status**         | ![Implemented][badge-implemented]                                                                                                  |
| **Evidence**       | Certificate profile code · Crypto tests · Documentation                                                       |

---

### **C-TP-007: Certificate Policy Enforcement**

| Field              | Value                                                                          |
| ------------------ | ------------------------------------------------------------------------------ |
| **Control Area**   | Certificate Lifecycle Security                                                 |
| **Related Risks**  | R-TP-004 · R-TP-006                                                            |
| **Description**    | Certificate issuance follows defined profiles, policies, and validation rules. |
| **Implementation** | Certificate templates · Policy validation · Request validation                 |
| **Status**         | ![Implemented][badge-implemented]                                                                    |
| **Evidence**       | CA/RA implementation · Policy documentation · Tests                            |

---

### **C-TP-008: Certificate Lifecycle Management**

| Field              | Value                                                                                                           |
| ------------------ | --------------------------------------------------------------------------------------------------------------- |
| **Control Area**   | Certificate Lifecycle Security                                                                                  |
| **Related Risks**  | R-TP-004 · R-TP-008                                                                                             |
| **Description**    | Trustpoint supports certificate issuance, renewal, revocation, expiry tracking, and lifecycle state management. |
| **Implementation** | Lifecycle workflows · Renewal handling · Revocation state                                                       |
| **Status**         | ![Implemented][badge-implemented]                                                                                                    |
| **Evidence**       | Lifecycle implementation · Tests · Documentation                                                                |

---

### **C-TP-009: Device Identity Verification**

| Field              | Value                                                                                          |
| ------------------ | ---------------------------------------------------------------------------------------------- |
| **Control Area**   | Certificate Lifecycle Security                                                                 |
| **Related Risks**  | R-TP-004 · R-TP-006                                                                            |
| **Description**    | Device onboarding and enrollment workflows verify device identity before certificate issuance. |
| **Implementation** | Enrollment validation · Protocol-specific checks · Operator approval where required            |
| **Status**         | ![Implemented][badge-implemented]                                                                                  |
| **Evidence**       | Enrollment implementation · Protocol tests · Operator documentation                            |

---

### **C-TP-010: Revocation Support**

| Field              | Value                                                                                        |
| ------------------ | -------------------------------------------------------------------------------------------- |
| **Control Area**   | Certificate Lifecycle Security                                                               |
| **Related Risks**  | R-TP-004 · R-TP-008                                                                          |
| **Description**    | Trustpoint supports revocation of compromised, obsolete, or incorrectly issued certificates. |
| **Implementation** | Revocation workflows · Revocation state · CRL / status distribution as applicable            |
| **Status**         | ![Implemented][badge-implemented]                                                                                 |
| **Evidence**       | Revocation implementation · Lifecycle tests · Documentation                                  |

---

### **C-TP-011: Secure Deployment Configuration**

| Field              | Value                                                                                                        |
| ------------------ | ------------------------------------------------------------------------------------------------------------ |
| **Control Area**   | Secure Deployment                                                                                            |
| **Related Risks**  | R-TP-002 · R-TP-007 · R-TP-008                                                                               |
| **Description**    | Trustpoint provides deployment guidance and configuration options to reduce insecure runtime configurations. |
| **Implementation** | Docker deployment · Environment configuration · Production settings guidance                                 |
| **Status**         | ![Implemented][badge-implemented]                                                                                                 |
| **Evidence**       | Deployment documentation · Docker configuration                                                              |

---

### **C-TP-012: TLS Protection**

| Field              | Value                                                                                          |
| ------------------ | ---------------------------------------------------------------------------------------------- |
| **Control Area**   | Secure Deployment                                                                              |
| **Related Risks**  | R-TP-002 · R-TP-006 · R-TP-007                                                                 |
| **Description**    | Network communication with Trustpoint should be protected using TLS or mTLS where appropriate. |
| **Implementation** | TLS deployment guidance · HTTPS configuration · Protocol-specific TLS requirements             |
| **Status**         | ![Implemented][badge-implemented]                                                                                    |
| **Evidence**       | Deployment documentation · Protocol documentation · TLS tests                                  |

---

### **C-TP-013: Secret Management**

| Field              | Value                                                                                                                  |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| **Control Area**   | Secure Deployment                                                                                                      |
| **Related Risks**  | R-TP-003 · R-TP-007                                                                                                    |
| **Description**    | Runtime secrets, database credentials, API tokens, and private material are protected against unauthorized disclosure. |
| **Implementation** | Environment-based secret configuration · Secure storage guidance · Secret rotation guidance                            |
| **Status**         | ![Implemented][badge-implemented]  ![In Progress][badge-in-progress]                                                                                                                 |
| **Evidence**       | Deployment documentation · Configuration reference                                                                     |

---

### **C-TP-014: Backup and Recovery**

| Field              | Value                                                                                                      |
| ------------------ | ---------------------------------------------------------------------------------------------------------- |
| **Control Area**   | Secure Deployment                                                                                          |
| **Related Risks**  | R-TP-003 · R-TP-007 · R-TP-008                                                                             |
| **Description**    | Trustpoint supports backup and recovery procedures for continuity and recovery from failures or incidents. |
| **Implementation** | Database backup support · Recovery guidance · RTO/RPO targets                                              |
| **Status**         | ![Implemented][badge-implemented]                                                                                               |
| **Evidence**       | Backup configuration · Recovery documentation                                                              |

---

### **C-TP-015: Monitoring and Metrics**

| Field              | Value                                                                                     |
| ------------------ | ----------------------------------------------------------------------------------------- |
| **Control Area**   | Logging and Monitoring                                                                    |
| **Related Risks**  | R-TP-007 · R-TP-008                                                                       |
| **Description**    | Trustpoint provides operational visibility through logs, health information, and metrics. |
| **Implementation** | Application logging · Health endpoints · Prometheus metrics                               |
| **Status**         | ![Implemented][badge-implemented]                                                                               |
| **Evidence**       | Logging implementation · Metrics documentation · Health endpoint documentation            |

---

### **C-TP-016: Sensitive Data Logging Controls**

| Field              | Value                                                                                                 |
| ------------------ | ----------------------------------------------------------------------------------------------------- |
| **Control Area**   | Logging and Monitoring                                                                                |
| **Related Risks**  | R-TP-007                                                                                              |
| **Description**    | Logs should avoid exposing private keys, credentials, tokens, secrets, or unnecessary sensitive data. |
| **Implementation** | Logging review · Redaction where needed · Minimal logging of sensitive values                         |
| **Status**         | ![Implemented][badge-implemented]                                                                                          |
| **Evidence**       | Logging configuration · Code review · Security tests                                                  |

---

### **C-TP-017: Dependency Management**

| Field              | Value                                                                                                                   |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| **Control Area**   | Supply Chain Security                                                                                                   |
| **Related Risks**  | R-TP-001 · R-TP-005 · R-TP-009                                                                                          |
| **Description**    | Dependencies are pinned, reviewed, and updated to reduce exposure to known vulnerabilities and supply chain compromise. |
| **Implementation** | `uv.lock` · Dependency review · Dependabot                                                                              |
| **Status**         | ![Implemented][badge-implemented]                                                               |
| **Evidence**       | `uv.lock` · Dependabot configuration · Dependency update PRs                                                            |

---

### **C-TP-018: Automated CI Checks**

| Field              | Value                                                                         |
| ------------------ | ----------------------------------------------------------------------------- |
| **Control Area**   | Supply Chain Security                                                         |
| **Related Risks**  | R-TP-001 · R-TP-005                                                           |
| **Description**    | Automated checks support code quality, test execution, and release readiness. |
| **Implementation** | GitHub Actions · Tests · MyPy · Ruff                                          |
| **Status**         | ![Implemented][badge-implemented] ![In Progress][badge-in-progress]                                                     |
| **Evidence**       | `.github/workflows/` · CI results · Test reports                              |

---

### **C-TP-019: Code Review**

| Field              | Value                                                                                              |
| ------------------ | -------------------------------------------------------------------------------------------------- |
| **Control Area**   | Supply Chain Security                                                                              |
| **Related Risks**  | R-TP-001 · R-TP-005 · R-TP-009                                                                     |
| **Description**    | Code changes are reviewed before merge to reduce security, quality, and maintainability risks.     |
| **Implementation** | Pull request workflow · Maintainer review · Two-person review target for security-relevant changes |
| **Status**         | ![Implemented][badge-implemented]                                                                                      |
| **Evidence**       | Pull requests · Review history · Contribution process                                              |

---

### **C-TP-020: SBOM Generation**

| Field              | Value                                                                            |
| ------------------ | -------------------------------------------------------------------------------- |
| **Control Area**   | Supply Chain Security                                                            |
| **Related Risks**  | R-TP-001 · R-TP-005 · R-TP-009                                                   |
| **Description**    | Trustpoint should generate a Software Bill of Materials for production releases. |
| **Implementation** | SBOM generation for release artifacts                                            |
| **Status**         | ![Implemented][badge-implemented]                                                                          |
| **Evidence**       | SBOM artifact once generated · Release workflow                                  |

---

### **C-TP-021: Release Integrity**

| Field              | Value                                                                                      |
| ------------------ | ------------------------------------------------------------------------------------------ |
| **Control Area**   | Supply Chain Security                                                                      |
| **Related Risks**  | R-TP-001                                                                                   |
| **Description**    | Release artifacts should be protected against tampering and should be verifiable by users. |
| **Implementation** | Release checks · Tagged releases · Checksums / signing planned                             |
| **Status**         | ![Implemented][badge-implemented]  ![In Progress][badge-in-progress]                                                                      |
| **Evidence**       | GitHub releases · Release workflow · Future attestations                                   |

---

### **C-TP-022: Vulnerability Disclosure Process**

| Field              | Value                                                                                         |
| ------------------ | --------------------------------------------------------------------------------------------- |
| **Control Area**   | Vulnerability Handling                                                                        |
| **Related Risks**  | R-TP-005 · R-TP-009                                                                           |
| **Description**    | Security vulnerabilities can be reported privately and handled through a coordinated process. |
| **Implementation** | `SECURITY.md` · Security contact · GitHub Security Advisories                                 |
| **Status**         | ![Implemented][badge-implemented]                                                                   |
| **Evidence**       | `SECURITY.md` · GitHub Security Advisory configuration                                        |

---

### **C-TP-023: Vulnerability Triage**

| Field              | Value                                                                                         |
| ------------------ | --------------------------------------------------------------------------------------------- |
| **Control Area**   | Vulnerability Handling                                                                        |
| **Related Risks**  | R-TP-005 · R-TP-009                                                                           |
| **Description**    | Reported vulnerabilities are reviewed, classified, prioritized, and assigned for remediation. |
| **Implementation** | Maintainer triage · Severity classification · Issue/advisory workflow                         |
| **Status**         | ![Implemented][badge-implemented]  ![In Progress][badge-in-progress]                                                                                 |
| **Evidence**       | Security advisories · Issue history · Release notes                                           |

---

### **C-TP-024: Security Update Process**

| Field              | Value                                                                                |
| ------------------ | ------------------------------------------------------------------------------------ |
| **Control Area**   | Vulnerability Handling                                                               |
| **Related Risks**  | R-TP-005 · R-TP-008 · R-TP-009                                                       |
| **Description**    | Security fixes are developed, reviewed, tested, released, and communicated to users. |
| **Implementation** | Security branches · Release notes · Advisory publication                             |
| **Status**         | ![Implemented][badge-implemented]  ![In Progress][badge-in-progress]                                                                           |
| **Evidence**       | Release notes · Advisories · GitHub releases                                         |

---

### **C-TP-025: Supported Versions Policy**

| Field              | Value                                                                              |
| ------------------ | ---------------------------------------------------------------------------------- |
| **Control Area**   | Vulnerability Handling                                                             |
| **Related Risks**  | R-TP-008 · R-TP-009                                                                |
| **Description**    | Trustpoint should define which versions receive security updates and for how long. |
| **Implementation** | Support policy before production release                                           |
| **Status**         | ![Planned][badge-planned]                                                                            |
| **Evidence**       | Future `SUPPORT.md` · Release policy                                               |

---

## **Control-to-Risk Mapping**

| Risk ID  | Risk                              | Key Controls                                                               |
| -------- | --------------------------------- | -------------------------------------------------------------------------- |
| R-TP-001 | Supply Chain Attack               | C-TP-017 · C-TP-018 · C-TP-019 · C-TP-020 · C-TP-021                       |
| R-TP-002 | Unauthorized Access               | C-TP-001 · C-TP-002 · C-TP-003 · C-TP-004 · C-TP-011 · C-TP-012            |
| R-TP-003 | Private Key Compromise            | C-TP-005 · C-TP-006 · C-TP-013 · C-TP-014                                  |
| R-TP-004 | Certificate Forgery               | C-TP-005 · C-TP-006 · C-TP-007 · C-TP-008 · C-TP-009 · C-TP-010            |
| R-TP-005 | Component Vulnerabilities         | C-TP-017 · C-TP-018 · C-TP-019 · C-TP-022 · C-TP-023 · C-TP-024            |
| R-TP-006 | Protocol Weaknesses               | C-TP-006 · C-TP-007 · C-TP-009 · C-TP-012                                  |
| R-TP-007 | Data Breach                       | C-TP-003 · C-TP-004 · C-TP-011 · C-TP-012 · C-TP-013 · C-TP-015 · C-TP-016 |
| R-TP-008 | Service Disruption                | C-TP-008 · C-TP-010 · C-TP-014 · C-TP-015 · C-TP-024 · C-TP-025            |
| R-TP-009 | Incomplete Vulnerability Handling | C-TP-020 · C-TP-022 · C-TP-023 · C-TP-024 · C-TP-025                       |

---

## **Open Items**

| ID       | Open Item                                                  | Priority | Target      |
| -------- | ---------------------------------------------------------- | -------- | ----------- |
| C-OI-001 | Validate control list against current implementation       | High     | Before v1.0 |
| C-OI-002 | Add evidence links for each implemented control            | High     | Before v1.0 |
| C-OI-003 | Define minimum security baseline for production deployment | High     | Before v1.0 |
| C-OI-004 | Define supported versions and security update policy       | High     | Before v1.0 |
| C-OI-005 | Add release signing or provenance attestations             | Medium   | Before v1.0 |
| C-OI-006 | Add security test coverage mapping                         | Medium   | Before v1.0 |
| C-OI-007 | Add control-to-CRA-requirement mapping                     | Medium   | Before v1.0 |


[badge-you-are-here]: https://img.shields.io/badge/You%20are%20here-blue?style=flat-square
[badge-implemented]: https://img.shields.io/badge/Implemented-success?style=flat-square
[badge-in-progress]: https://img.shields.io/badge/In%20Progress-yellow?style=flat-square
[badge-planned]: https://img.shields.io/badge/Planned-lightgrey?style=flat-square
[badge-na]: https://img.shields.io/badge/Not%20Applicable-lightgrey?style=flat-square