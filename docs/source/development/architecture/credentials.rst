==========================
Credentials - Architecture
==========================

Overview
--------

The **CredentialModel** is the central abstraction for managing certificates and private keys in Trustpoint. It supports multiple credential types (TLS Server, Root CA, Issuing CA, Issued Credentials, DevOwnerID, Signer) and can store keys either directly in the database or in hardware security modules (HSM) via PKCS#11.

The credential architecture manages the lifecycle from issuance through validation, storage, and deployment to devices.


CredentialModel Types
---------------------

The ``CredentialTypeChoice`` enum defines the purpose and restrictions of each credential:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Type
     - Purpose
   * - **TRUSTPOINT_TLS_SERVER**
     - Trustpoint's own TLS server certificate for HTTPS
   * - **ROOT_CA**
     - Root certificate authority (self-signed, trusted anchor)
   * - **ISSUING_CA**
     - Intermediate issuing CA (signed by root, issues device credentials)
   * - **ISSUED_CREDENTIAL**
     - Device credentials issued by Trustpoint (LDevID, application certificates)
   * - **DEV_OWNER_ID**
     - Device Owner ID certificates (IEEE 802.1AR DevOwnerID)
   * - **SIGNER**
     - Signing authority for hash-and-sign operations


Core Storage Model
------------------

CredentialModel stores:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Field
     - Purpose
   * - **credential_type**
     - One of the CredentialTypeChoice values above
   * - **private_key** (PEM)
     - Encrypted private key stored in database (for software keys)
   * - **pkcs11_private_key**
     - Reference to private key in HSM/token (for PKCS#11 keys)
   * - **certificate**
     - Primary certificate (ForeignKey to CertificateModel)
   * - **certificates**
     - All certificates in the credential (ManyToMany via PrimaryCredentialCertificate)
   * - **certificate_chain**
     - Ordered chain of issuing CA certificates (ManyToMany via CertificateChainOrderModel)


Primary Certificate vs Certificate Chain
-----------------------------------------

Each credential has a **primary certificate** (the leaf/end-entity certificate) and an optional **certificate chain** (issuing CA certificates up the trust path):

.. uml::

   CredentialModel {
      + certificate: CertificateModel (primary/leaf)
      + certificates: [CertificateModel] (via PrimaryCredentialCertificate)
      + certificate_chain: [CertificateModel] (ordered, via CertificateChainOrderModel)
   }

   PrimaryCredentialCertificate {
      + credential: CredentialModel
      + certificate: CertificateModel (OneToOne)
      + is_primary: bool
   }

   CertificateChainOrderModel {
      + credential: CredentialModel
      + certificate: CertificateModel
      + order: int
   }

The **primary certificate** (``certificate`` field) is the credential's active end-entity certificate. When a new certificate is issued or renewed, it becomes the new primary, and the old one is retained for revocation handling.

The **certificate chain** preserves issuing CA certificates in order, enabling certificate chain construction for protocols like EST (which require the full chain in PKCS#7 format).


IssuedCredentialModel - Device Credentials
--------------------------------------------

The ``IssuedCredentialModel`` bridges credentials to devices. It represents a credential issued to a specific device within a specific domain:

.. code-block:: python

   class IssuedCredentialModel(models.Model):
       # Link to the credential (OneToOne)
       credential = OneToOneField(CredentialModel)
       
       # Link to the device (ForeignKey)
       device = ForeignKey(DeviceModel)
       
       # Link to the domain
       domain = ForeignKey(DomainModel)
       
       # Metadata
       common_name: str
       issued_credential_type: DOMAIN_CREDENTIAL | APPLICATION_CREDENTIAL
       issued_using_cert_profile: str
       created_at: DateTimeField


Credential Types - IssuedCredentialModel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**DOMAIN_CREDENTIAL**
   The device's identity credential (LDevID) used to authenticate and enroll for application credentials. Typically the first credential issued during device onboarding. Used for EST client-certificate authentication or CMP authentication.

**APPLICATION_CREDENTIAL**
   Operational credentials for specific use cases (TLS Client, TLS Server, OPC UA). Issued after device authentication with a domain credential. Multiple application credentials can be issued to the same device.


Lifecycle: From Issuance to Deployment
--------------------------------------

1. **Credential Issuance** → Certificate is generated/signed by the issuing CA
2. **Database Storage** → ``CredentialModel`` created with primary certificate
3. **Issued Credential Record** → ``IssuedCredentialModel`` links credential to device/domain
4. **Device Retrieval** → Device downloads credential via EST, CMP, or manual download
5. **Renewal/Rekeying** → New certificate becomes primary, old retained for transition
6. **Revocation** → Certificate marked as revoked in CRL, old credentials cleaned up


PrimaryCredentialCertificate - Chain Management
------------------------------------------------

The ``PrimaryCredentialCertificate`` model manages which certificates belong to a credential:

- One credential can have **multiple certificates** (e.g., during renewal)
- The **primary** flag identifies the active/current certificate
- When a new certificate is added, it automatically becomes primary
- Old certificates are retained for validation of client certificates during transitions


CertificateChainOrderModel - CA Chain Ordering
-----------------------------------------------

The ``CertificateChainOrderModel`` preserves the order of issuing CA certificates:

- Ordered as: leaf certificate → intermediate CAs → root CA
- Required for EST `/cacerts` responses (PKCS#7 chain format)
- Prevents ambiguity when multiple possible chains exist


Credential Validation
---------------------

CredentialModel provides validation methods:

**is_valid_issued_credential()**
   Checks if credential meets requirements for deployment:
   - Type must be ISSUED_CREDENTIAL
   - Primary certificate must exist
   - Primary certificate status must be OK (not expired, revoked, etc.)

**IssuedCredentialModel.is_valid_domain_credential()**
   Checks if a domain credential is valid for issuing application credentials:
   - Must be DOMAIN_CREDENTIAL type
   - Underlying credential must pass ``is_valid_issued_credential()``
   - Certificate must be OK status


Private Key Storage Options
----------------------------

**Database Storage (Software Keys)**
   - Private key stored as encrypted PEM in ``private_key`` field
   - Fast, suitable for CA credentials
   - Encrypted using Trustpoint's key encryption mechanism

**HSM/PKCS#11 Storage**
   - Private key stored in hardware security module (TPM, SoftHSM, etc.)
   - ``pkcs11_private_key`` field references the ``PKCS11Key`` model
   - Higher security for sensitive credentials
   - Requires HSM configuration and PIN management

The ``PKCS11Key`` model stores references:

.. code-block:: python

   class PKCS11Key(models.Model):
       token_label: str  # HSM token identifier
       key_label: str    # Key identifier within token
       key_type: RSA | EC | AES
       created_at: DateTimeField

For request pipeline details and component architecture, see :doc:`../workflow`.


