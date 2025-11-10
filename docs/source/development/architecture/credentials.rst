==========================
Credentials - Architecture
==========================



General Message Flow
--------------------

.. uml::

   :Message;
   :Http validation - HttpRequestValidator;
   :Message parsing - RequestMessageParser -> parsed message;
   :Request Authentication - Authenticator -> DeviceModel object;
   :Request Authorization - Authorizer;
   :Message normalization, if required - CsrAdapter;
   :Certificate profile handling - JsonProfileValidator
   :Message processing - OperationProcessor;


HttpRequestValidator
--------------------

These classes validate the http attributes for requests, e.g. content-types, body size etc.


.. uml::

   HttpRequestValidator <|-- EstHttpRequestValidator
   HttpRequestValidator <|-- CmpHttpRequestValidator

   abstract HttpRequestValidator {
      +<<validate>>(request : HttpRequest) : Boolean
   }

   class EstHttpRequestValidator {
      +validate(request : HttpRequest) : Boolean
   }

   class CmpHttpRequestValidator {
      +validate(request : HttpRequest) : Boolean
   }



RequestMessageParser
--------------------

These classes parse PKI messages, e.g., CSRs and CMP messages.

.. uml::

   RequestMessageParser <|-- EstMessageParser
   RequestMessageParser <|-- CmpMessageParser
   
   abstract RequestMessageParser<M> {
      +<<parse>>(message : Bytes) : M
   }

   class EstMessageParser<CertificateSigningRequest> {
      +parse(message : Bytes) : CertificateSigningRequest
   }

   class CmpMessageParser<rfc4210.PKIMessage> {
      +parse(message : Bytes) : rfc4210.PKIMessage
   }


Authentication
--------------

The Authentication classes explicitly only handle the authentication, that is, they check if the authentication method applied to the request is
allowed and validate it. If all checks were successfull, the corresponding DeviceModel is returned.

.. uml::

   Authenticator <|-- EstAuthenticator
   Authenticator <|-- CmpAuthenticator

   abstract Authenticator<M, A> {
      +<<Authenticator>>(allowed_methods : List[A]) : Authenticator
      +<<authenticate>>(message : M, request : HttpRequest) : DeviceModel
   }

   class EstAuthenticator<Csr, EstAuthMethods> {
      +EstAuthentictor(allowed_methods : List[EstAuthMethods])
      +authenticate(message : Csr, request : HttpRequest) : DeviceModel
   }

   enum EstAuthMethods {
      USERNAME_AND_PASSWORD
      CLIENT_CERTIFICATE
   }

   class CmpAuthenticator<rfc4210.PKIMessage, CmpAuthMethods> {
      +CmpAuthenticator(allowed_methods : List[CmpAuthMethods])
      +authenticate(message : rfc4210.PKIMessage, request: HttpRequest) : DeviceModel
   }

   Enum CmpAuthMethods {
      SHARED_SECRET
      CLIENT_CERTIFICATE
   }


Authorization
-------------

The Authorizers will determine if the requested action is generally allowed to be performed by the DeviceModel object. This will not include any template checks etc.
The is_authorized method shall return true if the operation is allowed, and it shall raise an exception with an appropriate error message if not rather then just
return a plain false value.

.. note::

   Depending on the operation, multiple Authenticators may be invoked and used for the same request.

.. uml::

   Authorizer <|-- EstAuthorizer
   Authorizer <|-- CmpAuthorizer
   Authorizer <|-- CertTemplateAuthorizer

   abstract Authorizer<O> {
      +<<is_authorized>>(cls, device : DeviceModel, operation : O) : Boolean
   }

   class EstAuthorizer<EstOperation> {
      +<<is_authorized>>(cls, device : DeviceModel, operation : EstOperation) : Boolean
   }

   enum EstOperation {
      SIMPLE_ENROLL
      SIMPLE_RE_ENROLL
   }

   class CmpAuthorizer<CmpOperation> {
      +<<is_authorized>>(cls, device : DeviceModel, operation : CmpOperation) : Boolean
   }

   enum CmpOperation {
      IR
      CR
   }

   class CertTemplateAuthorizer<CertTemplate> {
      +<<is_authorized>>(cls, device : DeviceModel, template : CertTemplate) : Boolean
   }

   enum CertTemplate {
      HTTPS_CLIENT
      HTTPS_SERVER
      OPC_UA_CLIENT
      OPC_UA_SERVER
   }


CsrAdapter
----------

This class is an implementation of the adapter pattern so that the same code for handling certificate requests can be used.


.. uml::

   class CsrAdapter {
      +not_valid_after
      +not_valid_before
      +subject
      +<and so on>
      
      +get_extensions() -> List
   }


