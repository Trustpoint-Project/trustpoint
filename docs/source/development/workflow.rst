=================
Request Workflow
=================


Request Context Module Diagram
==============================

This diagram illustrates the `RequestContext` class, its attributes, and its methods for managing request-specific data within the system.

### UML Diagram:

.. plantuml::

    @startuml
    ' Representation of the RequestContext class.
    class RequestContext {
        + raw_message: HttpRequest | None
        + parsed_message: CertificateSigningRequest | PKIMessage | None
        + operation: str | None
        + protocol: str | None
        + certificate_template: str | None
        + response_format: str | None
        + est_encoding: str | None
        + domain_str: str | None
        + domain: DomainModel | None
        + device: DeviceModel | None
        + cert_requested: CertificateSigningRequest | None
        + est_username: str | None
        + est_password: str | None
        + cmp_shared_secret: str | None
        + client_certificate: x509.Certificate | None
        + client_intermediate_certificate: list[x509.Certificate] | None
        --
        + to_dict(): dict[str, Any]
        + clear(): None
    }

    ' Dependencies and related models.
    class HttpRequest
    class CertificateSigningRequest
    class PKIMessage
    class DomainModel
    class DeviceModel
    class x509.Certificate

    ' Relationships.
    RequestContext --> HttpRequest : "raw_message"
    RequestContext --> CertificateSigningRequest : "parsed_message/cert_requested"
    RequestContext --> PKIMessage : "parsed_message"
    RequestContext --> DomainModel : "domain"
    RequestContext --> DeviceModel : "device"
    RequestContext --> x509.Certificate : "client_certificate"
    RequestContext --> x509.Certificate : "client_intermediate_certificate"

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

    class CertTemplateParsing {
        + parse(context: RequestContext)
    }

    ' Dependency relationship with RequestContext.
    class RequestContext {
        + raw_message: Request
        + domain_str: str
        + certificate_template: str
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
    ParsingComponent <|-- CertTemplateParsing

    ' Composite dependencies.
    CompositeParsing o--> ParsingComponent : "parses with"
    CompositeParsing --> RequestContext : "uses"
    CmpMessageParser --> CompositeParsing : "extends"
    EstMessageParser --> CompositeParsing : "extends"
    EstPkiMessageParsing --> RequestContext : "parses CSR"
    CmpPkiMessageParsing --> RequestContext : "handles CMP messages"
    EstCsrSignatureVerification --> RequestContext : "verifies CSR signature"
    DomainParsing --> RequestContext : "validates domain"
    CertTemplateParsing --> RequestContext : "parses certificate template"

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

    class CertificateTemplateAuthorization {
        + allowed_templates: list[str]
        + authorize(context: RequestContext)
    }

    class DomainScopeValidation {
        + authorize(context: RequestContext)
    }

    class ManualAuthorization {
        + authorize(context: RequestContext)
    }

    ' Dependency: Context object used in all authorization methods.
    class RequestContext {
        + protocol: str
        + operation: str
        + certificate_template: str
        + domain: DomainModel
        + device: DeviceModel
    }

    ' Relationships between components.
    AuthorizationComponent <|-- ProtocolAuthorization
    AuthorizationComponent <|-- OperationAuthorization
    AuthorizationComponent <|-- CertificateTemplateAuthorization
    AuthorizationComponent <|-- DomainScopeValidation
    AuthorizationComponent <|-- ManualAuthorization
    AuthorizationComponent <|-- CompositeAuthorization
    CompositeAuthorization <|-- EstAuthorization

    ' Aggregations and dependencies.
    CompositeAuthorization o--> AuthorizationComponent : components
    CompositeAuthorization --> RequestContext : uses
    EstAuthorization --> CompositeAuthorization : extends
    ProtocolAuthorization --> RequestContext : reads protocol
    OperationAuthorization --> RequestContext : reads operation
    CertificateTemplateAuthorization --> RequestContext : checks template
    DomainScopeValidation --> RequestContext : validates domain
    ManualAuthorization --> RequestContext : overrides decisions

    @enduml

