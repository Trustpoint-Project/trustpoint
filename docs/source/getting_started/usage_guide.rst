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
            - **Using the device CLI**: Users can request a domain credential via CMP or EST.
            - **Browser-Based Onboarding**: Trustpoint offers a web interface for convenient onboarding through a browser.
            - **Manual Download of a P12 File**: Users can download a PKCS#12 file containing the certificate and manually distribute it to the target machine.
            - **OPC UA GDS Push**: For OPC UA servers, register them directly without traditional onboarding; Trustpoint manages their certificates via GDS Push.
        - **Zero-touch Onboarding (Work in Progress)**: A feature under development that will allow fully automated device onboarding without user intervention.
            - **AOKI**: An automated and simplified zero-touch onboarding protocol designed for industrial environments

.. admonition:: Why Onboarding First is Crucial!
   :class: tip

   It is essential to onboard a device before issuing application certificates to ensure the device has a trusted identity and secure communication channel with Trustpoint. The initial certificate (domain credential) obtained during onboarding establishes the device's authenticity and allows it to authenticate to Trustpoint. Without this foundational step, the security of subsequent application certificate requests could be compromised, potentially exposing the system to unauthorized access and other security risks.

.. admonition:: No Onbaording Desired
   :class: tip

   Although we recommend the use of domain credentials, many applications do not support this functionality. Trustpoint therefore also offers the issuing of application certificates without prior onboarding. To do this, ‘Domain Credential Onboarding’ must be deactivated when configuring a new device.

2. **Issuing and Managing Application Certificates**
    - Requesting certificates for applications or systems.
    - Trustpoint currently supports:
        - **TLS server and TLS client** certificates for generic HTTPS applications
        - **OPC UA server and client** certificates for OPC UA-based industrial automation
        - Generic certificates for custom applications
    - Issuing certificates from the configured Issuing CA or Remote CA.
    - Managing the lifecycle of certificates, including renewal, revocation, and status monitoring.

3. **Distributing Certificates via OPC UA GDS Push (Experimental)**
    - For OPC UA-based deployments, Trustpoint can automatically distribute certificates and trust anchors to OPC UA servers using the standardized OPC UA GDS Push protocol.
    - This is useful for large-scale OPC UA deployments where centralized certificate management is required.
    - **How it Works:**
        - Register OPC UA servers as devices in Trustpoint
        - Trustpoint automatically manages and pushes certificates and CRLs to the servers
        - Servers automatically retrieve and install updated credentials



Issuing CA Operating Modes
==========================

Trustpoint can be configured to operate in different modes in relation to the Issuing CA. These modes provide flexibility for various environments and security requirements:

1. **Importing an Issuing CA**
    - Trustpoint can operate using an external Issuing CA certificate.
    - This configuration is ideal for integrating with existing PKI setups.
    - **Steps to Configure:**
        - In **PKI > Certificate Authorities > Add new CA**
        - Select CA type **Local-Unprotected** or **Local-PKCS11**
        - You can import an Issuing CA from a file by importing a PKCS#12 file or by importing the key and certificate separately
    - **Use Case:** Issuing certificates in air-gapped environments or when you already have a CA certificate available

2. **Requesting CA Certificates via PKI Protocols**
    - Trustpoint can request Issuing CA certificates from a superior Certificate Authority using standard PKI protocols (CMP or EST).
    - This is the recommended approach for obtaining Issuing CA certificates in networked environments.
    - **Steps to Configure:**
        - In **PKI > Certificate Authorities > Add new CA**
        - Select CA type **Local-Unprotected** or **Local-PKCS11**
        - Generate a keypair locally
        - Use CMP or EST to request an Issuing CA certificate from a superior CA
        - Trustpoint will receive and store the issued CA certificate
    - **Advantages:**
        - Avoid manual certificate uploads 
        - Automated certificate chain management
        - Leverage existing PKI infrastructure
        - Maintain security by not exposing private keys during import
    - **Use Case:** Obtaining Issuing CA certificates from a central PKI without manual file transfers

3. **Operating as a Registration Authority (RA)**
    - Trustpoint can function as an RA, forwarding device certificate requests to an external Issuing CA.
    - Provides the ability to handle large-scale certificate requests efficiently while offloading the actual certificate issuance to a trusted CA.
    - **Steps to Configure:**
        - In **PKI > Certificate Authorities > Add new CA**
        - Select CA type **Remote-EST-RA** or **Remote-CMP-RA**
        - Configure the remote CA connection details (host, port, path)
        - Configure authentication method for the remote CA (username, password, or shared secret)
    - **Supported Protocols:**
        - EST (Enrollment over Secure Transport) with HTTP Basic Auth
        - CMP (Certificate Management Protocol) with shared secret or certificate-based auth
    - **Benefits:**
        - Enhanced security by separating the RA and CA roles
        - Scalability for large environments
        - Integration with existing PKI infrastructure
        - Centralized device management with distributed certificate issuance
    - **Use Case:** Management of certificate requests from multiple departments while maintaining tight control over the actual certificate issuance process, which is handled by a trusted external CA.

4. **Operating with Remote-Issuing CAs**
    - Trustpoint can issue certificates through remote Issuing CAs operated by external organizations.
    - Similar to RA mode, but Trustpoint maintains full control over device onboarding and certificate management.
    - **Steps to Configure:**
        - In **PKI > Certificate Authorities > Add new CA**
        - Select CA type **Remote-Issuing-EST** or **Remote-Issuing-CMP**
        - Configure the remote CA connection details
        - Configure authentication method
    - **Use Case:** Organizations that want to offload CA operations entirely while maintaining centralized device management in Trustpoint.

5. **Self-Generated Root and Issuing CA (Testing Purposes)**
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

- **IDevID Onboarding**: Truststores can be used to onboard new devices to Trustpoint using their Initial Device Identifier (IDevID) certificate issued by the manufacturer. For this purpose, serial number patterns can be stored in the domain configuration to check the associated IDevID of a request. This enables automated onboarding with manufacturer-backed device identity.

- **Integrating Truststores with Domains**: Truststores can be added to specific Domains, and once configured, they will automatically be provided to devices associated with those Domains. This feature is currently a work in progress (WIP).

.. note::

      Distribution of truststores through domains is not yet supported.


Security Considerations
=======================

With the current versions of Trustpoint, there is no built-in capability to securely store private keys. However, this feature is planned for future releases and will include HSM / TPM support, likely through the use of PKCS#11.

Backup and Recovery
===================

The Trustpoint is currently in an early Beta Phase and does not yet have backup, update and restore features implemented. Thus, be aware that you will not be able to update the current version and take your configurations with you on migration to a later version.