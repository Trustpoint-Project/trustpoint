================
Request Pipeline
================

Overview
========

The request pipeline processes incoming PKI requests (EST, CMP) through a series of composable stages, each responsible for a specific aspect of request handling. The architecture uses the **Composite Pattern** throughout to allow flexible composition of validation, parsing, authentication, and authorization logic.

For a comprehensive overview of the credential architecture and component organization, see :doc:`./architecture/credentials`.

**Pipeline Stages:**

1. **HTTP Request Validation** - Validates HTTP-level attributes (headers, content-type, payload size)
2. **Message Parsing** - Parses and validates protocol-specific message content
3. **Authentication** - Verifies the authenticity of credentials presented by the client
4. **Authorization** - Determines what operations are permitted for the authenticated request
5. **Request Processing** - Processes the request to issue certificates or perform other PKI operations
6. **Response Generation** - Generates a protocol-specific response

Each stage uses the Composite Pattern with a base component interface, allowing individual components to be composed into more complex operations.


Request Pipeline Flow
=====================

The following diagram shows how requests flow through the entire pipeline:

.. plantuml::

    @startuml
    start
    :Receive HTTP Request;
    :HTTP Validation;
    if (Valid?) then (yes)
    else (no)
        :Return HTTP Error;
        stop
    endif
    :Message Parsing;
    if (Valid?) then (yes)
    else (no)
        :Return Parse Error;
        stop
    endif
    :Authentication;
    if (Authentic?) then (yes)
    else (no)
        :Return Auth Error;
        stop
    endif
    :Authorization;
    if (Authorized?) then (yes)
    else (no)
        :Return Auth Error;
        stop
    endif
    :Process Request;
    if (Success?) then (yes)
    else (no)
        :Return Processing Error;
        stop
    endif
    :Generate Response;
    :Return Response;
    stop
    @enduml


Request Context Hierarchy
=========================

The RequestContext hierarchy carries state through the entire pipeline:

.. plantuml::

    @startuml
    ' Base context for all request types.
    class BaseRequestContext {
        + raw_message: HttpRequest
        + protocol: str
        + operation: str
        + domain_str: str
        + cert_profile_str: str
        --
        + domain: DomainModel | None
        + device: DeviceModel | None
    }

    ' Validation request contexts.
    class EstBaseRequestContext {
        + est_username: str | None
        + est_password: str | None
        + client_certificate: x509.Certificate | None
        + client_intermediate_certificate: list[x509.Certificate] | None
    }

    class CmpBaseRequestContext {
        + parsed_message: rfc4210.PKIMessage | None
        + cmp_shared_secret: str | None
        + client_certificate: x509.Certificate | None
    }

    ' Certificate request contexts.
    class EstCertificateRequestContext {
        + cert_requested: x509.CertificateSigningRequest | None
        + est_encoding: str | None
    }

    class CmpCertificateRequestContext {
        + parsed_message: rfc4210.PKIMessage
    }

    ' Revocation request contexts.
    class CmpRevocationRequestContext {
        + parsed_message: rfc4210.PKIMessage
    }

    ' Relationships.
    BaseRequestContext <|-- EstBaseRequestContext
    BaseRequestContext <|-- CmpBaseRequestContext
    EstBaseRequestContext <|-- EstCertificateRequestContext
    CmpBaseRequestContext <|-- CmpCertificateRequestContext
    CmpBaseRequestContext <|-- CmpRevocationRequestContext

    @enduml


HTTP Request Validator Module Diagram
=====================================

.. plantuml::

    @startuml
    ' General interface for all validation classes.
    interface ValidationComponent {
        + validate(context: RequestContext)
    }

    ' Composite class for grouping and executing multiple validation rules.
    class CompositeValidation {
        + components: list[ValidationComponent]
        + add(component: ValidationComponent)
        + remove(component: ValidationComponent)
        + validate(context: RequestContext)
    }

    ' Composite validators for CMP and EST-specific requests.
    class CmpHttpRequestValidator {
        + __init__()
        + validate(context: RequestContext)
    }

    class EstHttpRequestValidator {
        + __init__()
        + validate(context: RequestContext)
    }

    ' Individual validation components.
    class PayloadSizeValidation {
        + max_payload_size: int
        + validate(context: RequestContext)
    }

    class ContentTypeValidation {
        + expected_content_type: str
        + validate(context: RequestContext)
    }

    class AcceptHeaderValidation {
        + allowed_content_types: list[str]
        + validate(context: RequestContext)
    }

    class AuthorizationHeaderValidation {
        + validate(context: RequestContext)
    }

    class ClientCertificateValidation {
        + validate(context: RequestContext)
    }

    class IntermediateCertificatesValidation {
        + validate(context: RequestContext)
    }

    class ContentTransferEncodingValidation {
        + validate(context: RequestContext)
    }

    ' Dependency relationship with RequestContext.
    class RequestContext {
        + raw_message: Request
        + parsed_message: bytes
        + est_username: str
        + est_password: str
        + client_certificate: x509.Certificate
        + client_intermediate_certificate: list[x509.Certificate]
    }

    ' Relationships.
    ValidationComponent <|-- CompositeValidation
    CompositeValidation <|-- CmpHttpRequestValidator
    CompositeValidation <|-- EstHttpRequestValidator
    ValidationComponent <|-- PayloadSizeValidation
    ValidationComponent <|-- ContentTypeValidation
    ValidationComponent <|-- AcceptHeaderValidation
    ValidationComponent <|-- AuthorizationHeaderValidation
    ValidationComponent <|-- ClientCertificateValidation
    ValidationComponent <|-- IntermediateCertificatesValidation
    ValidationComponent <|-- ContentTransferEncodingValidation

    ' Composite relationships.
    CompositeValidation o--> ValidationComponent : "validates using"
    CompositeValidation --> RequestContext : "uses"
    CmpHttpRequestValidator --> CompositeValidation : "extends"
    EstHttpRequestValidator --> CompositeValidation : "extends"
    PayloadSizeValidation --> RequestContext : "validates payload size"
    ContentTypeValidation --> RequestContext : "checks content type"
    AcceptHeaderValidation --> RequestContext : "checks 'Accept'"
    AuthorizationHeaderValidation --> RequestContext : "extracts credentials"
    ClientCertificateValidation --> RequestContext : "verifies SSL client cert"
    IntermediateCertificatesValidation --> RequestContext : "validates CA chain"
    ContentTransferEncodingValidation --> RequestContext : "decodes base64"

    @enduml

Message Parser Module Diagram
=============================

.. plantuml::

    @startuml
    ' General interface for all parsing components.
    interface ParsingComponent {
        + parse(context: RequestContext)
    }

    ' Composite parser to group and execute individual parsing strategies.
    class CompositeParsing {
        + components: list[ParsingComponent]
        + add(component: ParsingComponent)
        + remove(component: ParsingComponent)
        + parse(context: RequestContext)
    }

    ' Specialized composite parsers for specific protocols.
    class CmpMessageParser {
        + __init__()
        + parse(context: RequestContext)
    }

    class EstMessageParser {
        + __init__()
        + parse(context: RequestContext)
    }

    ' Individual parsing components.
    class EstPkiMessageParsing {
        + parse(context: RequestContext)
    }

    class CmpPkiMessageParsing {
        + parse(context: RequestContext)
    }

    class EstCsrSignatureVerification {
        + parse(context: RequestContext)
    }

    class DomainParsing {
        + parse(context: RequestContext)
    }

    class CertProfileParsing {
        + parse(context: RequestContext)
    }

    ' Dependency relationship with RequestContext.
    class RequestContext {
        + raw_message: Request
        + domain_str: str
        + cert_profile_str: str
        + cert_requested: x509.CertificateSigningRequest
        + domain: DomainModel
        + parsed_message: PKIMessage
        + est_encoding: str
    }

    ' Relationships.
    ParsingComponent <|-- CompositeParsing
    CompositeParsing <|-- CmpMessageParser
    CompositeParsing <|-- EstMessageParser
    ParsingComponent <|-- EstPkiMessageParsing
    ParsingComponent <|-- CmpPkiMessageParsing
    ParsingComponent <|-- EstCsrSignatureVerification
    ParsingComponent <|-- DomainParsing
    ParsingComponent <|-- CertProfileParsing

    ' Composite dependencies.
    CompositeParsing o--> ParsingComponent : "parses with"
    CompositeParsing --> RequestContext : "uses"
    CmpMessageParser --> CompositeParsing : "extends"
    EstMessageParser --> CompositeParsing : "extends"
    EstPkiMessageParsing --> RequestContext : "parses CSR"
    CmpPkiMessageParsing --> RequestContext : "handles CMP messages"
    EstCsrSignatureVerification --> RequestContext : "verifies CSR signature"
    DomainParsing --> RequestContext : "validates domain"
    CertProfileParsing --> RequestContext : "parses certificate template"

    @enduml


Authentication Module Diagram
=============================

.. plantuml::

    @startuml
    ' General interface for all authentication classes.
    interface AuthenticationComponent {
        + authenticate(context: RequestContext)
    }

    ' Defines the structure for aggregating multiple authentications.
    class CompositeAuthentication {
        + components: list[AuthenticationComponent]
        + add(component: AuthenticationComponent)
        + remove(component: AuthenticationComponent)
        + authenticate(context: RequestContext)
    }

    ' Composite for EST-specific authentication methods.
    class EstAuthentication {
        + __init__()
        + authenticate(context: RequestContext)
    }

    ' Individual concrete authentication implementations for specialized use cases.
    class UsernamePasswordAuthentication {
        + authenticate(context: RequestContext)
    }

    class ClientCertificateAuthentication {
        + authenticate(context: RequestContext)
    }

    class ReenrollmentAuthentication {
        + authenticate(context: RequestContext)
    }

    class IDevIDAuthentication {
        + authenticate(context: RequestContext)
    }

    ' Dependency relationship with request context.
    class RequestContext {
        + est_username: str
        + est_password: str
        + client_certificate: Certificate
        + cert_requested: Certificate
        + raw_message: Message
        + device: DeviceModel
        + domain: DomainModel
    }

    ' Relationship between AuthenticationComponent and implementations.
    AuthenticationComponent <|-- UsernamePasswordAuthentication
    AuthenticationComponent <|-- ClientCertificateAuthentication
    AuthenticationComponent <|-- ReenrollmentAuthentication
    AuthenticationComponent <|-- IDevIDAuthentication
    AuthenticationComponent <|-- CompositeAuthentication
    CompositeAuthentication <|-- EstAuthentication

    ' Internal dependencies
    CompositeAuthentication o--> AuthenticationComponent : components
    CompositeAuthentication --> RequestContext : uses
    EstAuthentication --> CompositeAuthentication : extends

    UsernamePasswordAuthentication --> RequestContext : reads credentials
    ClientCertificateAuthentication --> RequestContext : verifies certificate
    ReenrollmentAuthentication --> RequestContext : validates re-enrollment
    IDevIDAuthentication --> RequestContext : checks IDevID authentication

    @enduml


Authorization Module Diagram
============================

.. plantuml::

    @startuml
    ' General interface for all authorization logic.
    interface AuthorizationComponent {
        + authorize(context: RequestContext)
    }

    ' Composite that combines multiple authorization mechanisms.
    class CompositeAuthorization {
        + components: list[AuthorizationComponent]
        + add(component: AuthorizationComponent)
        + remove(component: AuthorizationComponent)
        + authorize(context: RequestContext)
    }

    ' Specific composite for EST authorization rules.
    class EstAuthorization {
        + __init__()
        + authorize(context: RequestContext)
    }

    ' Concrete authorization rules for different aspects of a request.
    class ProtocolAuthorization {
        + allowed_protocols: list[str]
        + authorize(context: RequestContext)
    }

    class OperationAuthorization {
        + allowed_operations: list[str]
        + authorize(context: RequestContext)
    }

    class CertificateProfileAuthorization {
        + authorize(context: RequestContext)
    }

    class DomainScopeValidation {
        + authorize(context: RequestContext)
    }

    ' Dependency: Context object used in all authorization methods.
    class RequestContext {
        + protocol: str
        + operation: str
        + cert_profile_str: str
        + domain: DomainModel
        + device: DeviceModel
    }

    ' Relationships between components.
    AuthorizationComponent <|-- ProtocolAuthorization
    AuthorizationComponent <|-- OperationAuthorization
    AuthorizationComponent <|-- CertificateProfileAuthorization
    AuthorizationComponent <|-- DomainScopeValidation
    AuthorizationComponent <|-- CompositeAuthorization
    CompositeAuthorization <|-- EstAuthorization

    ' Aggregations and dependencies.
    CompositeAuthorization o--> AuthorizationComponent : components
    CompositeAuthorization --> RequestContext : uses
    EstAuthorization --> CompositeAuthorization : extends
    ProtocolAuthorization --> RequestContext : reads protocol
    OperationAuthorization --> RequestContext : reads operation
    CertificateProfileAuthorization --> RequestContext : checks template
    DomainScopeValidation --> RequestContext : validates domain

    @enduml


Request Pipeline Flow
=====================

The following diagram shows how requests flow through the entire pipeline:

.. plantuml::

    @startuml
    start
    :Receive HTTP Request;
    :HTTP Validation;
    if (Valid?) then (yes)
    else (no)
        :Return HTTP Error;
        stop
    endif
    :Message Parsing;
    if (Valid?) then (yes)
    else (no)
        :Return Parse Error;
        stop
    endif
    :Authentication;
    if (Authentic?) then (yes)
    else (no)
        :Return Auth Error;
        stop
    endif
    :Authorization;
    if (Authorized?) then (yes)
    else (no)
        :Return Auth Error;
        stop
    endif
    :Process Request;
    if (Success?) then (yes)
    else (no)
        :Return Processing Error;
        stop
    endif
    :Generate Response;
    :Return Response;
    stop
    @enduml


Key Concepts
============

**Composite Pattern**
    Each pipeline stage (validation, parsing, authentication, authorization) uses the Composite Pattern with a base component interface. This allows individual components to be composed into more complex operations, enabling flexible configuration of what rules apply to each protocol and operation.

**Request Context**
    The RequestContext object carries state through the entire pipeline. Different context types (EstCertificateRequestContext, CmpBaseRequestContext, etc.) extend BaseRequestContext to provide protocol-specific attributes while maintaining a consistent interface.

**ParsingComponent**
    Parsing components sequentially process the request context, extracting and validating message content. Examples include:

    - EstAuthorizationHeaderParsing: Extracts HTTP Basic Auth credentials
    - EstPkiMessageParsing: Parses PKCS#10 CSR
    - CmpPkiMessageParsing: Parses CMP PKIMessage
    - DomainParsing: Resolves domain identifier to DomainModel
    - CertProfileParsing: Resolves certificate profile

**AuthenticationComponent**
    Authentication components verify the authenticity of credentials. Unlike authorization, authentication does NOT determine device identity; that happens during authorization. Authentication simply validates that the provided credentials are valid.

**AuthorizationComponent**
    Authorization components determine what operations are allowed. They access the fully populated RequestContext (including domain and device information) to make authorization decisions.

**Error Handling**
    Each stage can raise exceptions with appropriate error messages. Errors are caught at the view level and converted to protocol-specific error responses (EST error messages or CMP PKIFailureInfo).