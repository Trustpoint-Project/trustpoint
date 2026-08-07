<p align="center">
  <img src="../_static/trustpoint_banner.png" alt="Trustpoint Logo" width="600">
</p>

# Risk Register

<p>
  <a href="#"><img src="https://img.shields.io/badge/Owner-Trustpoint_Project-0A66C2?style=for-the-badge" alt="Owner"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Version-1.0-555?style=for-the-badge" alt="Version"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Effective-2026--07--01-success?style=for-the-badge" alt="Effective Date"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Review-Quarterly-orange?style=for-the-badge" alt="Review Cycle"/></a>
</p>

**📋 Document Owner:** Trustpoint Project Maintainers | **📄 Version:** 1.0 | **📅 Last Updated:** 2026-07-01
**🔄 Review Cycle:** Quarterly | **⏰ Next Review:** 2026-09-26

---

## **Purpose**

Risk register documenting identified cybersecurity risks for Trustpoint's PKI management platform, supporting CRA readiness, BSI TR-03183-aligned risk management, and security excellence.

This document evaluates and treats risks derived from the threats identified in [`THREAT_MODEL.md`](./THREAT_MODEL.md).

---

## **Risk Management Process**

Trustpoint follows a structured security risk management process.

```text
Threat Model → Risk Register → Controls → Evidence → Review
```

| Step             | Document                                                                                                                       | Purpose                                                                                                               |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| 1. Threat Model  | [`THREAT_MODEL.md`](./THREAT_MODEL.md)                                                                                         | Identifies threats to Trustpoint                                  |
| 2. Risk Register | [`RISK_REGISTER.md`](./RISK_REGISTER.md)  -  [![Critical][badge-you-are-here]]()                                                                                   | Groups threats into cybersecurity risks
| 3. Controls      | [`CONTROLS.md`](./CONTROLS.md)                                                                                        | Documents implemented and planned controls                               |
| 4. Evidence      | [`CRA_COMPLIANCE.md`](./CRA_COMPLIANCE.md) · [`SECURITY.md`][security] · CI/CD artifacts · SBOM                           | Provides evidence for implemented controls, vulnerability handling, release processes, and security maintenance       |
| 5. Review        | [`THREAT_MODEL.md`](./THREAT_MODEL.md) · [`RISK_REGISTER.md`](./RISK_REGISTER.md) · [`CONTROLS.md`](./CONTROLS.md) · [`CRA_COMPLIANCE.md`](./CRA_COMPLIANCE.md) | Ensures that threats, risks, controls, and evidence remain current over time                                          |

---

## **Methodology**

**Likelihood:** H (≤12mo) · M (1-2yr) · L (>2yr)

**Impact (C/I/A):** H (High) · M (Medium) · L (Low)

**Residual Risk:** Critical · High · Medium · Low

Risks are grouped from one or more related threats. The related threat IDs provide traceability from threat identification to risk evaluation and treatment.

---

## **Traceability**

This risk register is based on the threats identified in [`THREAT_MODEL.md`](./THREAT_MODEL.md).

Each risk references one or more `TM-TP-xxx` threat IDs. This provides traceability across the CRA documentation chain:

**Threat Model → Risk Register → Controls → Evidence → Review**

| Risk ID  | Risk                              | Related Threats                                                       |
| -------- | --------------------------------- | --------------------------------------------------------------------- |
| R-TP-001 | Supply Chain Attack               | TM-TP-022 · TM-TP-023 · TM-TP-024                                     |
| R-TP-002 | Unauthorized Access               | TM-TP-001 · TM-TP-002 · TM-TP-003 · TM-TP-021                         |
| R-TP-003 | Private Key Compromise            | TM-TP-004 · TM-TP-005                                                 |
| R-TP-004 | Certificate Forgery               | TM-TP-006 · TM-TP-007 · TM-TP-008 · TM-TP-012 · TM-TP-013 · TM-TP-014 |
| R-TP-005 | Component Vulnerabilities         | TM-TP-022                                                             |
| R-TP-006 | Protocol Weaknesses               | TM-TP-013 · TM-TP-014 · TM-TP-020                                     |
| R-TP-007 | Data Breach                       | TM-TP-016 · TM-TP-017 · TM-TP-018 · TM-TP-024                         |
| R-TP-008 | Service Disruption                | TM-TP-009 · TM-TP-010 · TM-TP-018 · TM-TP-025 · TM-TP-026             |
| R-TP-009 | Incomplete Vulnerability Handling | TM-TP-022 · TM-TP-023 · TM-TP-024                                     |

---

## **Risk Summary**

**Next Review:** 2026-09-26

| Portfolio Overview | Current | Target |
| ------------------ | ------- | ------ |
| Total Risks        | 9       | 9      |
| Critical           | 0       | 0      |
| High               | 0       | 0      |
| Medium             | 6       | 4      |
| Low                | 3       | 5      |

---

## **Active Risks**

### **R-TP-001: Supply Chain Attack**

| Field               | Value                                                                               |
| ------------------- | ----------------------------------------------------------------------------------- |
| **Category**        | Supply Chain Security (CRA Art. 11)                                                 |
| **Related Threats** | TM-TP-022 · TM-TP-023 · TM-TP-024                                                   |
| **Asset**           | Build pipeline                                                                      |
| **Description**     | Pipeline/dependency compromise enabling malicious code injection                    |
| **Likelihood**      | M                                                                                   |
| **Impact**          | H/H/M                                                                               |
| **Inherent**        | High                                                                                |
| **Controls**        | GitHub Actions (restricted) · Dependabot · uv.lock pinning · 2-person review · SBOM |
| **Residual**        | **L**                                                                               |
| **Evidence**        | [workflows][workflows] · Dependabot · uv.lock                            |
| **Review**          | 2026-09-26                                                                          |

---

### **R-TP-002: Unauthorized Access**

| Field               | Value                                                         |
| ------------------- | ------------------------------------------------------------- |
| **Category**        | Access Control (CRA Art. 11)                                  |
| **Related Threats** | TM-TP-001 · TM-TP-002 · TM-TP-003 · TM-TP-021                 |
| **Asset**           | Certificate operations                                        |
| **Description**     | Unauthorized certificate management enabling forgery/issuance |
| **Likelihood**      | M                                                             |
| **Impact**          | H/H/H                                                         |
| **Inherent**        | Critical                                                      |
| **Controls**        | Django auth · JWT tokens · RBAC · MFA support · Audit logs    |
| **Residual**        | **L**                                                         |
| **Evidence**        | Django security · Auth logs                                   |
| **Review**          | 2026-09-26                                                    |

---

### **R-TP-003: Private Key Compromise**

| Field               | Value                                                                                    |
| ------------------- | ---------------------------------------------------------------------------------------- |
| **Category**        | Cryptographic Security (CRA Art. 11)                                                     |
| **Related Threats** | TM-TP-004 · TM-TP-005                                                                    |
| **Asset**           | CA private keys                                                                          |
| **Description**     | CA key compromise enabling certificate forgery                                           |
| **Likelihood**      | L                                                                                        |
| **Impact**          | H/H/H                                                                                    |
| **Inherent**        | Critical                                                                                 |
| **Controls**        | PKCS#11 HSM · Encrypted storage · Access controls · Key lifecycle · Separation of duties |
| **Residual**        | **L**                                                                                    |
| **Evidence**        | PKCS#11 integration · HSM config · Key procedures                                        |
| **Review**          | 2026-09-26                                                                               |

---

### **R-TP-004: Certificate Forgery**

| Field               | Value                                                                                                |
| ------------------- | ---------------------------------------------------------------------------------------------------- |
| **Category**        | PKI Infrastructure (CRA Art. 11)                                                                     |
| **Related Threats** | TM-TP-006 · TM-TP-007 · TM-TP-008 · TM-TP-012 · TM-TP-013 · TM-TP-014                                |
| **Asset**           | CA infrastructure                                                                                    |
| **Description**     | Weak issuance controls enabling unauthorized certificates                                            |
| **Likelihood**      | L                                                                                                    |
| **Impact**          | H/H/H                                                                                                |
| **Inherent**        | Critical                                                                                             |
| **Controls**        | Secure CA keys (R-TP-003) · Request validation · Access controls · Audit trails · Policy enforcement |
| **Residual**        | **L**                                                                                                |
| **Evidence**        | CA architecture · Issuance procedures                                                                |
| **Review**          | 2026-09-26                                                                                           |

---

### **R-TP-005: Component Vulnerabilities**

| Field               | Value                                                                                                                |
| ------------------- | -------------------------------------------------------------------------------------------------------------------- |
| **Category**        | Software Security (CRA Art. 11)                                                                                      |
| **Related Threats** | TM-TP-022                                                                                                            |
| **Asset**           | Python dependencies                                                                                                  |
| **Description**     | Third-party vulnerabilities such as Django or cryptographic library vulnerabilities compromising Trustpoint security |
| **Likelihood**      | M                                                                                                                    |
| **Impact**          | M/H/M                                                                                                                |
| **Inherent**        | High                                                                                                                 |
| **Controls**        | Dependabot (daily) · Regular updates · [![codecov][badge-codecov]][codecov] (→80%) · MyPy · Ruff · Security reviews                             |
| **Residual**        | **L**                                                                                                                |
| **Evidence**        | Dependabot · Test reports · CI/CD                                                                                    |
| **Review**          | 2026-09-26                                                                                                           |

---

### **R-TP-006: Protocol Weaknesses**

| Field               | Value                                                                                                                     |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **Category**        | Protocol Security (CRA Art. 11)                                                                                           |
| **Related Threats** | TM-TP-013 · TM-TP-014 · TM-TP-020                                                                                         |
| **Asset**           | EST/CMP/AOKI/GDS                                                                                                          |
| **Description**     | Protocol flaws, implementation weaknesses, or configuration errors enabling MITM, replay, tampering, or downgrade attacks |
| **Likelihood**      | L                                                                                                                         |
| **Impact**          | M/H/M                                                                                                                     |
| **Inherent**        | Medium                                                                                                                    |
| **Controls**        | RFC compliance (7030, 9483) · Mandatory TLS/mTLS · Protocol tests · Security reviews · Crypto best practices              |
| **Residual**        | **M**                                                                                                                     |
| **Evidence**        | Protocol docs · TLS config · Security tests                                                                               |
| **Review**          | 2026-09-26                                                                                                                |

---

### **R-TP-007: Data Breach**

| Field               | Value                                                                                                                                                 |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Category**        | Data Protection (CRA Art. 11)                                                                                                                         |
| **Related Threats** | TM-TP-016 · TM-TP-017 · TM-TP-018 · TM-TP-024                                                                                                         |
| **Asset**           | Certificate database                                                                                                                                  |
| **Description**     | Unauthorized database, backup, log, or monitoring access exposing certificate metadata, configuration, secrets, or security-relevant operational data |
| **Likelihood**      | M                                                                                                                                                     |
| **Impact**          | H/H/M                                                                                                                                                 |
| **Inherent**        | High                                                                                                                                                  |
| **Controls**        | DB encryption · RBAC · Network segmentation · Encrypted backups · Audit logs · Minimal PII                                                            |
| **Residual**        | **L**                                                                                                                                                 |
| **Evidence**        | Django security · DB encryption · Backup procedures                                                                                                   |
| **Review**          | 2026-09-26                                                                                                                                            |

---

### **R-TP-008: Service Disruption**

| Field               | Value                                                                                                                                                                            |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Category**        | Availability (CRA Art. 11)                                                                                                                                                       |
| **Related Threats** | TM-TP-009 · TM-TP-010 · TM-TP-018 · TM-TP-025 · TM-TP-026                                                                                                                        |
| **Asset**           | Certificate services                                                                                                                                                             |
| **Description**     | Outages, certificate expiry, revocation unavailability, backup failure, delayed updates, or misconfiguration preventing issuance, renewal, revocation, or certificate validation |
| **Likelihood**      | M                                                                                                                                                                                |
| **Impact**          | L/M/H                                                                                                                                                                            |
| **Inherent**        | Medium                                                                                                                                                                           |
| **Controls**        | django-dbbackup · Docker deployment · Health endpoints · Prometheus · RTO: 1-4h · RPO: 15-60min                                                                                  |
| **Residual**        | **M**                                                                                                                                                                            |
| **Evidence**        | Backup config · Docker · Monitoring                                                                                                                                              |
| **Review**          | 2026-09-26                                                                                                                                                                       |

---

### **R-TP-009: Incomplete Vulnerability Handling**

| Field               | Value                                                                                                            |
| ------------------- | ---------------------------------------------------------------------------------------------------------------- |
| **Category**        | Vulnerability Handling (CRA Art. 11 / Annex I Part II)                                                           |
| **Related Threats** | TM-TP-022 · TM-TP-023 · TM-TP-024                                                                                |
| **Asset**           | Vulnerability handling process                                                                                   |
| **Description**     | Reported vulnerabilities are not triaged, fixed, documented, communicated, or reported within required timelines |
| **Likelihood**      | M                                                                                                                |
| **Impact**          | M/H/M                                                                                                            |
| **Inherent**        | High                                                                                                             |
| **Controls**        | SECURITY.md · GitHub Security Advisories · Dependabot · Maintainer review · Release notes                        |
| **Residual**        | **M**                                                                                                            |
| **Evidence**        | SECURITY.md · GitHub advisories · Release process                                                                |
| **Review**          | 2026-09-26                                                                                                       |

---

## **Risk Treatment**

**Mitigated (Low):** R-TP-001, R-TP-002, R-TP-003, R-TP-004, R-TP-005, R-TP-007

**Accepted / Under Treatment (Medium):**

* R-TP-006: Protocol security (ongoing reviews)
* R-TP-008: Service disruption (RTO/RPO targets)
* R-TP-009: Vulnerability handling (process maturation before v1.0)


<!-- Reference Links -->
[security]: https://github.com/Trustpoint-Project/trustpoint/blob/main/SECURITY.md
[workflows]: https://github.com/Trustpoint-Project/trustpoint/tree/main/.github/workflows

[badge-you-are-here]: https://img.shields.io/badge/You%20are%20here-blue?style=flat-square