.. _trustpoint_usage_guide:

==========================================
Trustpoint Usage Guide
==========================================

Trustpoint provides secure and efficient certificate management. This guide outlines the main stages of using Trustpoint and describes the various ways it can operate in regard to the Issuing Certificate Authority (CA).

Stages of Trustpoint Operation
==============================

Trustpoint works in two main stages:

1. **Onboarding a Device**
    - Onboarding a device to Trustpoint by issuing an initial certificate (so called domain credential), which enables secure authentication to Trustpoint.
    - Onboarding is available in two ways:
        - **User-driven Onboarding**: This is the primary method currently available, offering several options for onboarding devices:
            - **Using the Trustpoint Client**: The Trustpoint client, available at `Trustpoint Client GitHub <https://github.com/Trustpoint-Project/trustpoint-client>`_, provides a user-friendly interface to onboard devices.
            - **Using the device CLI**: Users can request a domain credential via CMP or EST (WIP).
            - **Browser-Based Onboarding**: Trustpoint offers a web interface for convenient onboarding through a browser.
            - **Manual Download of a P12 File**: Users can download a PKCS#12 file containing the certificate and manually distribute it to the target machine.
        - **Zero-touch Onboarding (Work in Progress)**: A feature under development that will allow fully automated device onboarding without user intervention.
            - **BRSKI**: A zero-touch onboarding standard defined in RFC 8995
            - **AOKI**: A custom and simplified zero-touch onboarding

.. admonition:: Why Onboarding First is Crucial!
   :class: tip

   It is essential to onboard a device before issuing application certificates to ensure the device has a trusted identity and secure communication channel with Trustpoint. The initial certificate (domain credential) obtained during onboarding establishes the device's authenticity and allows it to authenticate to Trustpoint. Without this foundational step, the security of subsequent application certificate requests could be compromised, potentially exposing the system to unauthorized access and other security risks.

.. admonition:: No Onbaording Desired
   :class: tip

   Although we recommend the use of domain credentials, many applications do not support this functionality. Trustpoint therefore also offers the issuing of application certificates without prior onboarding. To do this, ‘Domain Credential Onboarding’ must be deactivated when configuring a new device.

2. **Issuing and Managing Application Certificates**
    - Requesting certificates for applications or systems.
    - Trustpoint currently supports **TLS server** and **TLS client** application certificates. In the future, additional certificate types will be supported for generic requests or specific applications such as OPC UA server or client certificates.
    - Issuing certificates from the configured Issuing CA.
    - Managing the lifecycle of certificates, including renewal, revocation, and status monitoring.


Issuing CA Operating Modes
==========================

Trustpoint can be configured to operate in different modes in relation to the Issuing CA. These modes provide flexibility for various environments and security requirements:

1. **Importing an Issuing CA**
    - Trustpoint can operate using an external Issuing CA certificate.
    - This configuration is ideal for integrating with existing PKI setups.
    - **Steps to Configure:**
        - In PKI > Issuing CAs > Add new Issuing CA
        - You can Import a new Issuing CA from a file by importing an PKCS#12 file oder by importing the key and certificate separately
        - or you can generate a keypair and request an issuing CA Certificate by rerquesting it via EST (WIP), CMP or SCEP
    - **Use Case:** Issuing certificates in air-gapped environments

2. **Operating as a Registration Authority (RA)**
    - Trustpoint can function as an RA, forwarding certificate requests to an external Issuing CA.
    - Provides the ability to handle large-scale certificate requests efficiently while offloading the actual certificate issuance to a trusted CA.
    - **Note**: Not supported right now. Will be available in future versions
    - **Benefits:**
        - Enhanced security by separating the RA and CA roles.
        - Scalability for large environments.
    - **Use Case:** Management of certificate requests from multiple departments while maintaining tight control over the actual certificate issuance process, which is handled by a trusted external CA.

.. admonition:: RA mode is WIP
   :class: tip

   We are working on making the RA mode available as soon as possible.


3. **Self-Generated Root and Issuing CA (Testing Purposes)**
    - Suitable for development, testing, or non-production environments.
    - Trustpoint can generate its own Root and Issuing CA to simplify testing.
    - **Steps to Configure:**
        - In Settings > Security > Advanced security settings
        - Activate "Enable local auto-generated PKI"
        - Select a key algorithm
        - Click save
    - **Note:** This setup is not recommended for production use.
    - **Use Case:** Testing Trustpoint and its features

Domains and Issuing CAs
=======================

Trustpoint provides flexibility in managing multiple domains, each of which can be configured with its own Issuing CA. This feature is particularly useful for organizations that need to separate certificate management across different departments, environments, or use cases.

Domain Configuration
--------------------
- **Domains in Trustpoint**: A domain in Trustpoint represents a logical grouping of devices, applications, or services that require certificate management. Each domain can have its own policies, configurations, and Issuing CA.
- **Separate Issuing CAs per Domain**: Trustpoint allows each domain to be associated with a distinct Issuing CA. This configuration ensures that certificate issuance is tailored to the specific needs of each domain, providing greater control and flexibility.
- **Granular Protocol Selection**: In order to reduce the possible attack surface according to the principle of least privilege, Trustpoint supports selecting which protocols and operations are allowed on a per-domain basis. For instance, the CMP protocol may be enabled to request application certificates via the Trustpoint client.

Use Cases for Domain and Issuing CA Segregation
-----------------------------------------------
1. **Production Line Segregation**: In a manufacturing facility with multiple production lines, each line can have its own domain and Issuing CA.
2. **Facility Segregation**: Organizations operating multiple physical facilities can assign separate domains and Issuing CAs to each facility, providing localized certificate management and improving overall security.
3. **Application-Specific CAs**: For applications with unique security or compliance requirements (e.g. using RSA or ECDSA), a dedicated domain and Issuing CA can be set up to meet these specific needs.

Truststores
===========

A Truststore is a secure repository that holds trusted certificates, such as Root and Issuing CA certificates, which are used to verify the authenticity of other certificates. In industrial environments, Truststores play a critical role in ensuring that communication between devices, applications, and systems is secure and trusted.

Managing Truststores in Trustpoint
----------------------------------

- **Adding Certificates**: Administrators can add new trusted certificates to the Truststore by importing Root or Issuing CA certificates. This process is essential for maintaining the trust relationships necessary for secure communication.

- **Steps to Add a Truststore**:
    - Navigate to **PKI > Truststores**.
    - Click **Add New Truststore**.
    - Define a unique name for the Truststore.
    - Import a certificate file in **PEM** or **PKCS#7** format.
    - Save the Truststore configuration to ensure the new trusted certificates are active and ready for use.

- **IDevID onboarding**: Truststores can be used to onboard new devices to Trustpoint. For this purpose, serial number patterns can be stored in the domain configuration to check the associated IDevID of a request.

- **Integrating Truststores with Domains**: Truststores can be added to specific Domains, and once configured, they will automatically be provided to devices associated with those Domains. This feature is currently a work in progress (WIP).

.. note::

      Distribution of truststores through domains is not yet supported.


Security Considerations
=======================

With the current versions of Trustpoint, there is no built-in capability to securely store private keys. However, this feature is planned for future releases and will include HSM / TPM support, likely through the use of PKCS#11.

Backup and Recovery
===================

The Trustpoint is currently in an early Beta Phase and does not yet have backup, update and restore features implemented. Thus, be aware that you will not be able to update the current version and take your configurations with you on migration to a later version.