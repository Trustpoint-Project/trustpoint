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

**📋 Document Owner:** Trustpoint Project Maintainers | **📄 Version:** 1.0 | **📅 Last Updated:** 2026-06-26  
**🔄 Review Cycle:** Quarterly | **⏰ Next Review:** 2026-09-26

---

## **Purpose**

Risk register documenting all identified risks for Trustpoint's PKI management platform, supporting CRA compliance and security excellence.

---

## **Methodology**

**Likelihood:** H (≤12mo) · M (1-2yr) · L (>2yr)  
**Impact (C/I/A):** H (High) · M (Medium) · L (Low)  
**Residual Risk:** Critical · High · Medium · Low

---

## **Risk Summary**

**Next Review:** 2026-09-26

| Portfolio Overview | Current | Target |
|-------------------|---------|--------|
| Total Risks | 8 | 8 |
| Critical | 0 | 0 |
| High | 0 | 0 |
| Medium | 5 | 3 |
| Low | 3 | 5 |

---

## **Active Risks**

### **R-TP-001: Supply Chain Attack**

| Field | Value |
|-------|-------|
| **Category** | Supply Chain Security (CRA Art. 11) |
| **Asset** | Build pipeline |
| **Description** | Pipeline/dependency compromise enabling malicious code injection |
| **Likelihood** | M |
| **Impact** | H/H/M |
| **Inherent** | High |
| **Controls** | GitHub Actions (restricted) · Dependabot · uv.lock pinning · 2-person review · SBOM |
| **Residual** | **L** |
| **Evidence** | [workflows](./.github/workflows/) · Dependabot · uv.lock |
| **Review** | 2026-09-26 |

---

### **R-TP-002: Unauthorized Access**

| Field | Value |
|-------|-------|
| **Category** | Access Control (CRA Art. 11) |
| **Asset** | Certificate operations |
| **Description** | Unauthorized certificate management enabling forgery/issuance |
| **Likelihood** | M |
| **Impact** | H/H/H |
| **Inherent** | Critical |
| **Controls** | Django auth · JWT tokens · RBAC · MFA support · Audit logs |
| **Residual** | **L** |
| **Evidence** | Django security · Auth logs |
| **Review** | 2026-09-26 |

---

### **R-TP-003: Private Key Compromise**

| Field | Value |
|-------|-------|
| **Category** | Cryptographic Security (CRA Art. 11) |
| **Asset** | CA private keys |
| **Description** | CA key compromise enabling certificate forgery |
| **Likelihood** | L |
| **Impact** | H/H/H |
| **Inherent** | Critical |
| **Controls** | PKCS#11 HSM · Encrypted storage · Access controls · Key lifecycle · Separation of duties |
| **Residual** | **L** |
| **Evidence** | PKCS#11 integration · HSM config · Key procedures |
| **Review** | 2026-09-26 |

---

### **R-TP-004: Certificate Forgery**

| Field | Value |
|-------|-------|
| **Category** | PKI Infrastructure (CRA Art. 11) |
| **Asset** | CA infrastructure |
| **Description** | Weak issuance controls enabling unauthorized certificates |
| **Likelihood** | L |
| **Impact** | H/H/H |
| **Inherent** | Critical |
| **Controls** | Secure CA keys (R-TP-003) · Request validation · Access controls · Audit trails · Policy enforcement |
| **Residual** | **L** |
| **Evidence** | CA architecture · Issuance procedures |
| **Review** | 2026-09-26 |

---

### **R-TP-005: Component Vulnerabilities**

| Field | Value |
|-------|-------|
| **Category** | Software Security (CRA Art. 11) |
| **Asset** | Python dependencies |
| **Description** | Third-party vulnerabilities (Django, crypto libs) compromising security |
| **Likelihood** | M |
| **Impact** | M/H/M |
| **Inherent** | High |
| **Controls** | Dependabot (daily) · Regular updates · 69% tests (→80%) · MyPy · Ruff · Security reviews |
| **Residual** | **L** |
| **Evidence** | Dependabot · Test reports · CI/CD |
| **Review** | 2026-09-26 |

---

### **R-TP-006: Protocol Weaknesses**

| Field | Value |
|-------|-------|
| **Category** | Protocol Security (CRA Art. 11) |
| **Asset** | EST/CMP/AOKI/GDS |
| **Description** | Protocol flaws enabling MITM or downgrade attacks |
| **Likelihood** | L |
| **Impact** | M/H/M |
| **Inherent** | Medium |
| **Controls** | RFC compliance (7030, 9483) · Mandatory TLS/mTLS · Protocol tests · Security reviews · Crypto best practices |
| **Residual** | **M** |
| **Evidence** | Protocol docs · TLS config · Security tests |
| **Review** | 2026-09-26 |

---

### **R-TP-007: Data Breach**

| Field | Value |
|-------|-------|
| **Category** | Data Protection (CRA Art. 11) |
| **Asset** | Certificate database |
| **Description** | Unauthorized DB access exposing certificate metadata/config |
| **Likelihood** | M |
| **Impact** | H/H/M |
| **Inherent** | High |
| **Controls** | DB encryption · RBAC · Network segmentation · Encrypted backups · Audit logs · Minimal PII |
| **Residual** | **L** |
| **Evidence** | Django security · DB encryption · Backup procedures |
| **Review** | 2026-09-26 |

---

### **R-TP-008: Service Disruption**

| Field | Value |
|-------|-------|
| **Category** | Availability (CRA Art. 11) |
| **Asset** | Certificate services |
| **Description** | Outages preventing issuance/renewal/revocation |
| **Likelihood** | M |
| **Impact** | L/M/H |
| **Inherent** | Medium |
| **Controls** | django-dbbackup · Docker deployment · Health endpoints · Prometheus · RTO: 1-4h · RPO: 15-60min |
| **Residual** | **M** |
| **Evidence** | Backup config · Docker · Monitoring |
| **Review** | 2026-09-26 |

---

## **Risk Treatment**

**Mitigated (Low):** R-TP-001, R-TP-002, R-TP-003, R-TP-004, R-TP-005, R-TP-007

**Accepted (Medium):**
- R-TP-006: Protocol security (ongoing reviews)
- R-TP-008: Service disruption (RTO/RPO targets)

---

## **Monitoring Schedule**

| Level | Frequency | Method |
|-------|-----------|--------|
| Critical | Weekly | N/A |
| High | Bi-weekly | N/A |
| Medium | Monthly | Maintainer review, automated monitoring |
| Low | Quarterly | Standard review cycle |
