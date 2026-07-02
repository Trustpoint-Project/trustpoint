.. _glossary:

========
Glossary
========

.. glossary::
    :sorted:

    Certificate
        A certificate refers to a X.509 certificate, which contains the corresponding public key.

    Private Key
        A private key of an asymmetric key pair. A public key can usually be derived or is contained in a private key object.

    Public Key
        A key that can be shared publicly and is used to verify the digital signature created by the corresponding private key.

    Certificate Chain
        The certificate chain corresponding to a certificate, including the Root CA certificate, but excluding the
        certificate itself that the certificate chain is concerned about.

    Credential
        A credential is a set of a private key, corresponding certificate and certificate chain. Both the certificate and
        private key implicitly include the public key.

    Domain Credential
        A domain credential is the credential the device will acquire when onboarding to a domain.
        This credential is then used to authenticate itself against the Trustpoint and thus allows the device to
        request application certificates corresponding to that domain.

    IDevID
        Initial Device Identifier is a certificate issued by the device manufacturer per IEEE 802.1AR.
        It serves as a permanent identity of the device and can be used to authenticate the device during onboarding
        to establish trust with Trustpoint or other PKI systems.

    LDevID
        Locally-significant Device Identifier is a certificate issued by Trustpoint or a local PKI to a device
        during the onboarding process. Unlike IDevID, LDevID is domain-specific and is used for authentication
        within a particular industrial environment or domain.

    Root CA
        A trusted Certificate Authority that is the anchor of trust in a PKI.
        It is used to sign Issuing CAs and other subordinate certificates, establishing the basis for the certificate chain.

    Issuing CA
        An Issuing CA is an entity on the Trustpoint that issues new certificates while forcing all certificates
        in the certificate hierarchy to utilize the same Signature-Suite,
        that is the same signature algorithm and the same hash function.

    Registration Authority (RA)
        An entity that acts as an intermediary between end-users and the Certificate Authority (CA),
        responsible for accepting certificate requests, authenticating the requestor's identity,
        and forwarding the requests to the CA for certificate issuance.

    Self-Generated Root and Issuing CA
        A configuration within Trustpoint where the system generates its own Root Certificate Authority and Issuing Certificate Authority.
        .. warning::
        Self-Generated Root and Issuing CAs are primarily intended for testing purposes to simulate a complete certificate issuance environment without relying on external CAs.

    Signature Suite
        A combination of a signature algorithm and a hash function used to create digital signatures.
        It ensures that certificates issued under a particular domain maintain consistent cryptographic properties.

    Onboarding
        Onboarding describes the process of acquiring a first credential, the domain credential, which allows
        the device to authenticate itself against the Trustpoint and thus request further application
        certificates from that domain.

    User-Driven Onboarding
        A method where users manually initiate and control the process of adding devices to Trustpoint,
        utilizing tools such as the Trustpoint Client, command-line interfaces, browser-based interfaces,
        or by manually downloading and distributing PKCS#12 files.

    Zero-Touch Onboarding
        An automated onboarding process, currently under development,
        designed to allow devices to be added to Trustpoint without manual intervention,
        streamlining the integration of new devices into the system.

    Domain
        Domains are an abstraction on top of the Issuing CAs. Every Domain has exactly one Issuing CA associated to it,
        while an Issuing CA can be part of multiple domains.
        Certificates associated with a domain will always have the same Signature-Suite (compare Issuing-CA)

    Trust-Store
        Trust-Stores are sets of certificates that are trustworthy. The Trustpoint can be configured to offer arbitrary
        Trust-Stores in any domain which can then be requested and stored within the Trustpoint-Client.

    CRL
        The Certificate Revocation List is a list of certificates that have been revoked by the Certificate Authority before their scheduled expiration date,
        indicating that they should no longer be trusted.

    CSR
        A Certificate Signing Request is a message sent from an applicant to a Certificate Authority to request the issuance of a digital certificate.
        It typically contains the applicant’s public key and identifying information.

    PKCS#12
        PKCS#12 (Public Key Cryptography Standards #12) is a binary format used to store cryptographic objects,
        such as private keys, certificates, and any related intermediate chain certificates.
        A PKCS#12 file is often used to bundle these objects into a single file,
        making it easy to transport and securely protect using a password.
        Common file extensions for PKCS#12 files are ``.p12`` or ``.pfx``.

    PEM
        Privacy Enhanced Mail is a base64-encoded format often used for storing cryptographic keys and certificates,
        typically with extensions such as ``.pem``, ``.crt``, ``.cer``, or ``.key``.
        PEM files are ASCII-text and are easily readable,
        with headers like ``-----BEGIN CERTIFICATE-----`` and ``-----END CERTIFICATE-----``,
        making them versatile for use in different environments and applications.

    EST
        The Enrollment over Secure Transport protocol is used for securely enrolling devices with a Certificate Authority,
        allowing for the automated issuance and renewal of digital certificates.

    CMP
        The Certificate Management Protocol is used for managing digital certificates within a Public Key Infrastructure (PKI),
        including certificate issuance, renewal, and revocation.

    OPC UA GDS Push
        OPC UA Global Discovery Server Push is a standardized protocol for distributing and updating certificates,
        trust anchors, and Certificate Revocation Lists (CRLs) to OPC UA servers.
        This allows centralized management of credentials for OPC UA-based industrial automation infrastructure.

    AOKI
        Automated Onboarding for Keyless Infrastructure is a zero-touch onboarding protocol designed specifically for industrial environments.
        It uses mDNS for server discovery and REST APIs for mutual trust establishment before transitioning to standard PKI protocols (CMP or EST).

    Application Certificates
        Digital certificates issued by Trustpoint for specific applications or systems (like TLS server/client, OPC UA server/client),
        enabling secure communication and authentication for those applications within the Trustpoint-managed environment.

    BDD
        Behavior-Driven Development is a collaborative software development approach
        that uses natural language descriptions of expected behavior to bridge communication between developers,
        testers, and business stakeholders.
        See also: `BDD <https://cucumber.io/docs/bdd/>`_.

    Gherkin
        Gherkin is a human-readable,
        structured language used in :term:`BDD` to write test scenarios in a Given-When-Then format,
        making them understandable by both technical and non-technical stakeholders.
        See also: `Gherkin <https://cucumber.io/docs/gherkin/>`_.

    Cucumber
        Cucumber is a tool for running automated acceptance tests, written in plain language.
        See also: `Cucumber <https://cucumber.io/>`_.

    behave
        Python behave is a :term:`BDD` framework that allows developers to write test scenarios
        in :term:`Gherkin` syntax and execute them with step definitions implemented in Python.
        See also: `behave <https://behave.readthedocs.io/en/latest/>`_.

    uv
        Astrals uv is a really fast python package manager.
        See also: `uv <https://astral.sh/blog/uv>`_.

    Django
        Django is a python web framework which simplifies the development of web apps.
        See also: `Django <https://www.djangoproject.com/>`_.

    mypy
        mypy is a static type checker for python.
        See also: `mypy <https://mypy.readthedocs.io/en/stable/>`_.

    ruff
        Astrals ruff ist a really fast python linter and code formatter.
        See also: `ruff <https://docs.astral.sh/ruff/>`_.

    Composite Pattern
        A structural design pattern that allows you to compose objects into tree structures to represent part-whole hierarchies.
        Composite lets clients treat individual objects and compositions of objects uniformly.
        Trustpoint uses this pattern extensively for composing validation, parsing, authentication, and authorization components.

    Request Context
        An object that carries state through the entire request pipeline in Trustpoint.
        It includes raw HTTP request data, parsed messages, extracted credentials, domain information, and device identity.
        Different context types (EstCertificateRequestContext, CmpBaseRequestContext, etc.) extend BaseRequestContext for protocol-specific attributes.

    ParsingComponent
        A component in the Trustpoint request pipeline responsible for parsing and validating a specific aspect of the request.
        Examples include EstPkiMessageParsing (parses CSR), CmpPkiMessageParsing (parses CMP messages), and DomainParsing (resolves domain).

    AuthenticationComponent
        A component responsible for verifying the authenticity of credentials provided in the request
        (e.g., HTTP Basic Auth, shared secret, client certificate).
        Does not determine which device is making the request; that is the role of authorization.

    AuthorizationComponent
        A component responsible for determining what operations are allowed for an authenticated request.
        Examples include DomainScopeValidation, CertificateProfileAuthorization, and ProtocolAuthorization.

    TM
        Test Manager

    PM
        Project Manager

    Dev
        Development Team

    Client
        Stakeholders or End Users

