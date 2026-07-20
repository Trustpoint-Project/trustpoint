# PKI Operating Modes: CA vs RA

Trustpoint can operate as a **local Certificate Authority (CA)** or as a **Registration Authority (RA)** forwarding requests to an external PKI. The operating mode is determined by the CA type configured for the issuing CA associated with each trust domain.

## Operating Mode Decision

```{mermaid}
flowchart TB
    DEVICE[Device enrollment request]
    VALIDATE["Trustpoint / authentication, policy, approval"]

    DEVICE --> VALIDATE

    VALIDATE --> MODE{Issuing CA type}

    MODE -->|"CA mode / LOCAL_PKCS11 / AUTOGEN"| LOCAL_SIGN[Generate certificate locally]
    LOCAL_SIGN --> CRYPTO[Crypto provider API]
    CRYPTO --> PKCS11[PKCS#11 provider]
    PKCS11 --> HSM_TOKEN[HSM or SoftHSM token]
    LOCAL_SIGN --> CERT_LOCAL[Issued certificate]

    MODE -->|"RA mode / REMOTE_EST_RA / REMOTE_CMP_RA"| FORWARD[Forward CSR to external CA]
    FORWARD --> EXT_EST[External EST endpoint]
    FORWARD --> EXT_CMP[External CMP endpoint]
    EXT_EST --> CERT_REMOTE[Issued certificate]
    EXT_CMP --> CERT_REMOTE

    CERT_LOCAL --> STORE["Store in PostgreSQL / update device state / trigger workflows"]
    CERT_REMOTE --> STORE
    STORE --> RESPOND[Return certificate to device]
```

## CA Mode (Trustpoint acts as Certificate Authority)

**CA types:** `AUTOGEN_ROOT`, `AUTOGEN`, `LOCAL_PKCS11`

In CA mode, Trustpoint owns the issuing CA and signs certificates using a private key managed by the configured cryptographic provider.

### Use Cases

- **Self-contained OT installations** without enterprise PKI
- **Test and development** environments
- **Isolated production cells** with local trust anchors
- **Air-gapped networks** requiring on-premises issuance
- **Temporary or emergency** certificate issuance when external CA is unavailable

### Implementation Details

**Certificate signing flow:**

1. Device sends CSR (Certificate Signing Request) via EST/CMP/AOKI
2. Trustpoint validates device identity and applies policies
3. Approval workflow executes (if required)
4. Trustpoint loads issuing CA private key from PKCS#11 token
5. Trustpoint generates certificate using CA key and profile
6. Certificate signed via crypto provider API
7. Certificate stored in PostgreSQL with device linkage
8. Certificate returned to device

**Key operations:**
- Issuing CA private key stored in PKCS#11 token (production) or SoftHSM (dev)
- Certificate signing performed in `trustpoint/pki/` domain services
- Key operations delegated to `crypto` module provider abstraction
- Trustpoint generates and manages CRLs for issued certificates

### CA Type Details

#### AUTOGEN_ROOT

**Purpose:** Auto-generated self-signed root CA

**Use case:** Testing and development only

**Characteristics:**
- Self-signed root certificate
- Generated automatically during setup
- Key stored in configured crypto provider
- Not suitable for production

**Generation:** Triggered by setup wizard or management UI

#### AUTOGEN

**Purpose:** Auto-generated intermediate CA

**Use case:** Testing and development

**Characteristics:**
- Signed by auto-generated root CA
- Automatically created issuing CA
- Key stored in configured crypto provider
- Suitable for test environments

**Generation:** Created when auto-gen PKI is enabled

#### LOCAL_PKCS11

**Purpose:** Locally managed CA with key in PKCS#11 provider

**Use case:** Production deployments

**Characteristics:**
- CA certificate imported or generated
- Private key in hardware HSM or secure PKCS#11 token
- Full control over CA hierarchy
- Production-grade key protection

**Setup:**
1. Generate CA key in HSM
2. Import CA certificate to Trustpoint
3. Configure crypto provider profile
4. Associate CA with trust domain

### Advantages of CA Mode

- **Full autonomy:** No dependency on external CA availability
- **Immediate issuance:** No network latency or external approval delays
- **Offline operation:** Works in air-gapped networks
- **Simplified architecture:** Fewer external dependencies
- **Complete control:** Full visibility and control over issued certificates

### Disadvantages of CA Mode

- **HSM requirement:** Requires hardware HSM for production security
- **Operational responsibility:** Organization owns CA security and compliance

---

## RA Mode (Trustpoint acts as Registration Authority)

**CA types:** `REMOTE_EST_RA`, `REMOTE_CMP_RA`

In RA mode, Trustpoint authenticates devices, enforces policies, and orchestrates approvals, but forwards the validated certificate request to an external CA for issuance.

### Use Cases

- **Integration with existing enterprise PKI**
- **Regulatory or compliance requirements** for centralized CA control
- **Separation of OT device management** from IT certificate issuance
- **Hybrid deployments** where some domains use local CAs and others use external CAs
- **Risk mitigation** by not hosting CA private keys

### Implementation Details

**Certificate request flow:**

1. Device sends CSR via EST/CMP/AOKI
2. Trustpoint validates device identity and applies policies
3. Approval workflow executes (if required)
4. Trustpoint forwards CSR to external CA via EST or CMP
5. External CA issues certificate
6. Trustpoint receives issued certificate
7. Certificate stored in PostgreSQL with device linkage
8. Certificate returned to device

**Key characteristics:**
- No issuing CA private key in Trustpoint
- Certificate signing delegated to external CA
- Trustpoint acts as policy enforcement point
- Lifecycle management (renewal, revocation) remains in Trustpoint

### RA Type Details

#### REMOTE_EST_RA

**Purpose:** Forward requests to external EST server

**Protocol:** RFC 7030 (Enrollment over Secure Transport)

**Configuration requirements:**
- External EST server URL
- Authentication credentials (mTLS or HTTP Basic Auth)
- CA certificate chain

**Example use case:** Integration with enterprise EST-enabled CA

#### REMOTE_CMP_RA

**Purpose:** Forward requests to external CMP server

**Protocol:** RFC 9483 (Certificate Management Protocol)

**Configuration requirements:**
- External CMP server URL
- Authentication method (shared secret or certificate)
- CA certificate chain

**Example use case:** Integration with legacy PKI infrastructure

### Advantages of RA Mode

- **Centralized PKI management:** Leverage existing enterprise CA
- **Compliance:** Meet requirements for centralized CA control
- **No HSM required:** Trustpoint doesn't need signing key
- **Trust simplification:** Devices already trust enterprise CA
- **Risk distribution:** CA key management responsibility with IT PKI team

### Disadvantages of RA Mode

- **External dependency:** Requires CA availability and network connectivity
- **Latency:** Enrollment includes network round-trip to CA
- **Limited offline operation:** Cannot issue certificates without CA access
- **External approval:** May require additional CA-side approval steps
- **Integration complexity:** Must integrate with specific CA API/protocol

---

## Future Enhancements

- **SCEP RA mode:** Integration with SCEP-enabled CAs
- **ACME RA mode:** Integration with ACME-enabled CAs (e.g., Let's Encrypt)
- **REST API RA mode:** Generic REST-based CA integration
- **Automatic fallback:** CA mode as fallback when RA mode CA unreachable
- **Certificate caching:** Cache external CA responses for faster renewal
- **Multi-CA support:** Issue from different CAs based on device type or policy
