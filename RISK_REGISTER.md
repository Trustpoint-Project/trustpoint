<p align="center">
  <img src=".github-assets/trustpoint_banner.png" alt="Trustpoint Logo" width="600">
</p>

<h1 align="center">Trustpoint — Risk Register</h1>

<p align="center">
  <strong>Systematic Risk Management for PKI Trust Infrastructure</strong><br>
  <em>Enterprise-grade Risk Framework for Industrial Certificate Management</em>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/Owner-Trustpoint_Project-0A66C2?style=for-the-badge" alt="Owner"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Version-1.0-555?style=for-the-badge" alt="Version"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Effective-2026--06--26-success?style=for-the-badge" alt="Effective Date"/></a>
  <a href="#"><img src="https://img.shields.io/badge/Review-Quarterly-orange?style=for-the-badge" alt="Review Cycle"/></a>
</p>

**📋 Document Owner:** Trustpoint Project Maintainers | **📄 Version:** 1.0 | **📅 Last Updated:** 2026-06-26 (UTC)  
**🔄 Review Cycle:** Quarterly | **⏰ Next Review:** 2026-09-26

---

## **Purpose Statement**

This risk register documents all identified risks affecting Trustpoint's operation as a trust anchor and PKI management platform for industrial environments. Risk assessments support CRA (Cyber Resilience Act) compliance and align with Trustpoint's commitment to security excellence in OT/industrial certificate management.

---

## **Risk Assessment Methodology**

Risks are assessed using a **Likelihood × Impact** matrix with the following scales:

### **Likelihood Scale:**
- **H (High):** Likely to occur within 12 months
- **M (Medium):** May occur within 1-2 years
- **L (Low):** Unlikely to occur within 2+ years

### **Impact Scale (C/I/A):**
Impact assessed across three dimensions:
- **C (Confidentiality):** Impact on data/configuration confidentiality
- **I (Integrity):** Impact on system/data integrity
- **A (Availability):** Impact on service availability

**Impact Levels:** H (High), M (Medium), L (Low)

### **Residual Risk:**
After applying controls, risks are classified as:
- **Critical:** Requires immediate action
- **High:** Priority mitigation needed
- **Medium:** Monitored and managed
- **Low:** Accepted with documentation

---

## **Risk Summary Dashboard**

**Next Review:** 2026-09-26

### **Executive Risk Summary**

| **Risk Portfolio Overview** | **Value** | **Target** |
|---------------------------|-----------|------------|
| **Total Active Risks** | 8 | 8 |
| **Critical Risks** | 0 | 0 |
| **High Risks** | 0 | 0 |
| **Medium Risks** | 5 | 3 |
| **Low Risks** | 3 | 5 |

---

## **Active Risk Register**

### **R-TP-001: Supply Chain Attack**

| **Field** | **Value** |
|-----------|-----------|
| **Risk ID** | R-TP-001 |
| **Category** | Supply Chain Security (CRA Art. 11) |
| **Asset** | Build pipeline |
| **Description** | Compromise of build pipeline or dependencies could inject malicious code into Trustpoint releases, affecting all deployments |
| **Likelihood** | M (Medium) |
| **Impact (C/I/A)** | H/H/M (High Confidentiality, High Integrity, Medium Availability) |
| **Inherent Risk** | High |
| **Controls** | • GitHub Actions CI/CD with restricted permissions<br/>• Dependabot automated vulnerability scanning<br/>• Dependency pinning via uv.lock<br/>• Two-person review for critical changes<br/>• SBOM generation (planned automation) |
| **Residual Risk** | L (Low) |
| **Evidence** | [.github/workflows/](./.github/workflows/) · Dependabot alerts · uv.lock |
| **Owner** | Trustpoint Maintainers |
| **Review Date** | 2026-09-26 |

---

### **R-TP-002: Unauthorized Access**

| **Field** | **Value** |
|-----------|-----------|
| **Risk ID** | R-TP-002 |
| **Category** | Access Control (CRA Art. 11) |
| **Asset** | Certificate operations |
| **Description** | Unauthorized access to certificate management functions could enable certificate forgery or unauthorized issuance |
| **Likelihood** | M (Medium) |
| **Impact (C/I/A)** | H/H/H (High across all dimensions) |
| **Inherent Risk** | Critical |
| **Controls** | • Django authentication framework<br/>• JWT token-based API authentication<br/>• Role-based access control (RBAC)<br/>• Multi-factor authentication support<br/>• Comprehensive audit logging |
| **Residual Risk** | L (Low) |
| **Evidence** | Django security implementation · Authentication logs |
| **Owner** | Trustpoint Maintainers |
| **Review Date** | 2026-09-26 |

---

### **R-TP-003: Private Key Compromise**

| **Field** | **Value** |
|-----------|-----------|
| **Risk ID** | R-TP-003 |
| **Category** | Cryptographic Security (CRA Art. 11) |
| **Asset** | CA private keys |
| **Description** | Compromise of CA private keys would enable attackers to forge certificates, undermining entire trust infrastructure |
| **Likelihood** | L (Low) |
| **Impact (C/I/A)** | H/H/H (Catastrophic across all dimensions) |
| **Inherent Risk** | Critical |
| **Controls** | • PKCS#11 HSM support for key storage<br/>• Encrypted key storage for software keys<br/>• Access controls limiting key access<br/>• Key lifecycle management<br/>• Separation of duties for key operations |
| **Residual Risk** | L (Low) |
| **Evidence** | PKCS#11 integration · HSM configuration · Key management procedures |
| **Owner** | Trustpoint Maintainers |
| **Review Date** | 2026-09-26 |

---

### **R-TP-004: Certificate Forgery**

| **Field** | **Value** |
|-----------|-----------|
| **Risk ID** | R-TP-004 |
| **Category** | PKI Infrastructure (CRA Art. 11) |
| **Asset** | CA infrastructure |
| **Description** | Weaknesses in certificate issuance controls could enable unauthorized certificate creation |
| **Likelihood** | L (Low) |
| **Impact (C/I/A)** | H/H/H (High across all dimensions) |
| **Inherent Risk** | Critical |
| **Controls** | • Secure CA key management (see R-TP-003)<br/>• Certificate request validation<br/>• Access controls for issuance operations<br/>• Comprehensive audit trails<br/>• Certificate policy enforcement |
| **Residual Risk** | L (Low) |
| **Evidence** | CA security architecture · Certificate issuance procedures |
| **Owner** | Trustpoint Maintainers |
| **Review Date** | 2026-09-26 |

---

### **R-TP-005: Component Vulnerabilities**

| **Field** | **Value** |
|-----------|-----------|
| **Risk ID** | R-TP-005 |
| **Category** | Software Security (CRA Art. 11) |
| **Asset** | Python dependencies |
| **Description** | Vulnerabilities in third-party dependencies (Django, cryptography libraries, etc.) could compromise Trustpoint security |
| **Likelihood** | M (Medium) |
| **Impact (C/I/A)** | M/H/M (Medium Confidentiality, High Integrity, Medium Availability) |
| **Inherent Risk** | High |
| **Controls** | • Automated Dependabot scanning (daily)<br/>• Regular dependency updates<br/>• 69% test coverage (target 80%+)<br/>• MyPy type checking<br/>• Ruff linting<br/>• Security-focused code review |
| **Residual Risk** | L (Low) |
| **Evidence** | Dependabot alerts · Test reports · CI/CD workflows |
| **Owner** | Trustpoint Maintainers |
| **Review Date** | 2026-09-26 |

---

### **R-TP-006: Protocol Implementation Weaknesses**

| **Field** | **Value** |
|-----------|-----------|
| **Risk ID** | R-TP-006 |
| **Category** | Protocol Security (CRA Art. 11) |
| **Asset** | EST/CMP/AOKI/OPC UA GDS Push implementations |
| **Description** | Implementation flaws in certificate enrollment protocols could enable man-in-the-middle attacks or protocol downgrade |
| **Likelihood** | L (Low) |
| **Impact (C/I/A)** | M/H/M (Medium Confidentiality, High Integrity, Medium Availability) |
| **Inherent Risk** | Medium |
| **Controls** | • Standards-compliant implementations (RFC 7030, RFC 9483)<br/>• Mandatory TLS/mTLS enforcement<br/>• Protocol security testing<br/>• Regular security reviews<br/>• Cryptographic best practices |
| **Residual Risk** | M (Medium) |
| **Evidence** | Protocol documentation · TLS configuration · Security testing results |
| **Owner** | Trustpoint Maintainers |
| **Review Date** | 2026-09-26 |

---

### **R-TP-007: Data Breach**

| **Field** | **Value** |
|-----------|-----------|
| **Risk ID** | R-TP-007 |
| **Category** | Data Protection (CRA Art. 11) |
| **Asset** | Certificate database |
| **Description** | Unauthorized access to certificate database could expose certificate metadata and configuration data |
| **Likelihood** | M (Medium) |
| **Impact (C/I/A)** | H/H/M (High Confidentiality, High Integrity, Medium Availability) |
| **Inherent Risk** | High |
| **Controls** | • Database encryption support (configurable)<br/>• Access controls and RBAC<br/>• Network segmentation<br/>• Encrypted backups<br/>• Audit logging<br/>• Minimal personal data collection |
| **Residual Risk** | L (Low) |
| **Evidence** | Django security configuration · Database encryption · Backup procedures |
| **Owner** | Trustpoint Maintainers |
| **Review Date** | 2026-09-26 |

---

### **R-TP-008: Service Disruption**

| **Field** | **Value** |
|-----------|-----------|
| **Risk ID** | R-TP-008 |
| **Category** | Availability (CRA Art. 11) |
| **Asset** | Certificate services |
| **Description** | Service outages could prevent certificate issuance, renewal, or revocation, disrupting industrial operations |
| **Likelihood** | M (Medium) |
| **Impact (C/I/A)** | L/M/H (Low Confidentiality, Medium Integrity, High Availability) |
| **Inherent Risk** | Medium |
| **Controls** | • Database backup functionality (django-dbbackup)<br/>• Docker-based deployment for portability<br/>• Health monitoring endpoints<br/>• Prometheus telemetry integration<br/>• Recovery Time Objective: 1-4 hours<br/>• Recovery Point Objective: 15-60 minutes |
| **Residual Risk** | M (Medium) |
| **Evidence** | Backup configuration · Docker deployment · Monitoring implementation |
| **Owner** | Trustpoint Maintainers |
| **Review Date** | 2026-09-26 |

---

## **Risk Treatment Summary**

### **Mitigated Risks (Residual: Low)**
- R-TP-001: Supply Chain Attack
- R-TP-002: Unauthorized Access
- R-TP-003: Private Key Compromise
- R-TP-004: Certificate Forgery
- R-TP-005: Component Vulnerabilities
- R-TP-007: Data Breach

### **Accepted Risks (Residual: Medium)**
- R-TP-006: Protocol Implementation Weaknesses — Accepted with ongoing security reviews
- R-TP-008: Service Disruption — Accepted with RTO/RPO targets and backup procedures

---

## **Risk Monitoring Schedule**

| **Risk Level** | **Review Frequency** | **Monitoring Method** |
|---------------|---------------------|----------------------|
| **Critical** | Weekly | N/A (no critical residual risks) |
| **High** | Bi-weekly | N/A (no high residual risks) |
| **Medium** | Monthly | Maintainer review, automated monitoring |
| **Low** | Quarterly | Standard review cycle |
