"""Provides the `PkiMessageParser` class for parsing PKI messages."""
import base64
import re
from abc import ABC, abstractmethod

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from django.http import HttpResponse
from pki.models import DomainModel
from pyasn1.codec.ber import decoder
from pyasn1_modules import rfc4210, rfc2511  # type: ignore[import-untyped]

from request.request_context import RequestContext
from trustpoint.logger import LoggerMixin


class ParsingComponent(ABC):
    """Abstract base class for components in the composite parsing pattern."""

    @abstractmethod
    def parse(self, context: RequestContext) -> None:
        """Execute parsing logic and store results in the context."""


class EstPkiMessageParsing(ParsingComponent, LoggerMixin):
    """Component for parsing EST-specific PKI messages."""

    def parse(self, context: RequestContext) -> None:
        """Parse a DER-encoded PKCS#10 certificate signing request."""

        def raise_parsing_error(message: str) -> None:
            """Helper to raise a ValueError with given error message."""
            raise ValueError(message)

        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            self.logger.warning("EST PKI message parsing failed: Raw message is missing")
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'body') or not context.raw_message.body:
            error_message = 'Raw message is missing body.'
            self.logger.warning("EST PKI message parsing failed: Raw message body is missing")
            raise ValueError(error_message)

        try:
            body_size = len(context.raw_message.body)

            if b'CERTIFICATE REQUEST-----' in context.raw_message.body:
                est_encoding = 'pem'
                csr = x509.load_pem_x509_csr(context.raw_message.body)
                self.logger.debug(f"EST PKI message parsing: Detected PEM format, body size: {body_size} bytes")
            elif re.match(rb'^[A-Za-z0-9+/=\n]+$', context.raw_message.body):
                est_encoding = 'base64_der'
                der_data = base64.b64decode(context.raw_message.body)
                csr = x509.load_der_x509_csr(der_data)
                self.logger.debug(f"EST PKI message parsing: Detected Base64 DER format, body size: {body_size} bytes, "
                                  f"decoded: {len(der_data)} bytes")
            elif context.raw_message.body.startswith(b'\x30'):  # ASN.1 DER starts with 0x30
                est_encoding = 'der'
                csr = x509.load_der_x509_csr(context.raw_message.body)
                self.logger.debug(f"EST PKI message parsing: Detected DER format, body size: {body_size} bytes")
            else:
                self.logger.warning(f"EST PKI message parsing failed: Unsupported CSR format, "
                                    f"body size: {body_size} bytes")
                raise_parsing_error("Unsupported CSR format. Ensure it's PEM, Base64, or raw DER.")

            context.cert_requested = csr
            context.est_encoding = est_encoding

            subject_cn = "unknown"
            try:
                subject_cn = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            except (IndexError, AttributeError):
                pass

            self.logger.info(f"EST PKI message parsing successful: {est_encoding} format, subject CN: {subject_cn}")

        except Exception as e:
            error_message = 'Failed to parse the CSR.'
            self.logger.error(f"EST PKI message parsing failed: {e}")
            raise ValueError(error_message) from e

class EstCsrSignatureVerification(ParsingComponent, LoggerMixin):
    """Parses the context to fetch the CSR and verifies its signature using the public key contained in the CSR."""

    def parse(self, context: RequestContext) -> None:
        """Validates the signature of the CSR stored in the context."""
        csr = context.cert_requested
        if csr is None:
            error_message = 'CSR not found in the parsing context. Ensure it was parsed before signature verification.'
            self.logger.warning("EST CSR signature verification failed: CSR not found in context")
            raise ValueError(error_message)

        public_key = csr.public_key()
        signature_hash_algorithm = csr.signature_hash_algorithm

        if signature_hash_algorithm is None:
            error_message = 'CSR does not contain a signature hash algorithm.'
            self.logger.warning("EST CSR signature verification failed: No signature hash algorithm")
            raise ValueError(error_message)

        if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            error_message = 'Unsupported public key type for CSR signature verification.'
            self.logger.warning(
                f"EST CSR signature verification failed: Unsupported public key type: {type(public_key)}")
            raise TypeError(error_message)

        try:
            key_type = "RSA" if isinstance(public_key, rsa.RSAPublicKey) else "EC"

            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature=csr.signature,
                    data=csr.tbs_certrequest_bytes,
                    padding=padding.PKCS1v15(),
                    algorithm=signature_hash_algorithm,
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature=csr.signature,
                    data=csr.tbs_certrequest_bytes,
                    signature_algorithm=ec.ECDSA(signature_hash_algorithm),
                )

            self.logger.info(f"EST CSR signature verification successful: {key_type} key "
                             f"with {signature_hash_algorithm.name} hash")
        except Exception as e:
            error_message = 'Failed to verify the CSR signature.'
            self.logger.error(f"EST CSR signature verification failed: {e}")
            raise ValueError(error_message) from e

class DomainParsing(ParsingComponent, LoggerMixin):
    """Parses and validates the domain from the request context object."""

    def parse(self, context: RequestContext) -> None:
        """Extract and validate the domain, then add it to the context."""
        domain_str = context.domain_str
        if not domain_str:
            error_message = 'Domain is missing in the request context.'
            self.logger.warning("Domain parsing failed: Domain string is missing")
            raise ValueError(error_message)

        try:
            domain = self._extract_requested_domain(domain_str)
            context.domain = domain
            self.logger.info(f"Domain parsing successful: Domain '{domain_str}'")
        except ValueError as e:
            raise e

    def _extract_requested_domain(self, domain_name: str) -> DomainModel:
        """Validate and fetch the domain object by name."""
        try:
            domain = DomainModel.objects.get(unique_name=domain_name)
            self.logger.debug(f"Domain lookup successful: Found domain '{domain_name}'")
            return domain
        except DomainModel.DoesNotExist:
            error_message = f"Domain '{domain_name}' does not exist."
            self.logger.warning(f"Domain lookup failed: Domain '{domain_name}' does not exist")
            raise ValueError(error_message)
        except DomainModel.MultipleObjectsReturned:
            error_message = f"Multiple domains found for '{domain_name}'."
            self.logger.warning(f"Domain lookup failed: Multiple domains found for '{domain_name}'")
            raise ValueError(error_message)

class CertTemplateParsing(ParsingComponent, LoggerMixin):
    """Parses the certificate template from the request context object."""

    def parse(self, context: RequestContext) -> None:
        """Extract and validate the certificate template, then add it to the context."""
        certtemplate_str = context.certificate_template
        if not certtemplate_str:
            error_message = 'Certificate template is missing in the request context.'
            self.logger.warning("Certificate template parsing failed: Template string is missing")
            raise ValueError(error_message)

        context.certificate_template = certtemplate_str
        self.logger.info(f"Certificate template parsing successful: Template '{certtemplate_str}'")


class CmpPkiMessageParsing(ParsingComponent, LoggerMixin):
    """Component for parsing CMP-specific PKI messages."""

    def parse(self, context: RequestContext) -> None:
        """Parse a CMP PKI message."""
        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            self.logger.warning("CMP PKI message parsing failed: Raw message is missing")
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'body') or not context.raw_message.body:
            error_message = 'Raw message is missing body.'
            self.logger.warning("CMP PKI message parsing failed: Raw message body is missing")
            raise ValueError(error_message)

        try:
            body_size = len(context.raw_message.body)
            serialized_message, _ = decoder.decode(context.raw_message.body, asn1Spec=rfc4210.PKIMessage())
            context.parsed_message = serialized_message

            self.logger.info(f"CMP PKI message parsing successful: Parsed {body_size} bytes")
        except (ValueError, TypeError) as e:
            error_message = 'Failed to parse the CMP message. It seems to be corrupted.'
            self.logger.error(f"CMP PKI message parsing failed: {e}")
            raise ValueError(error_message) from e


class CmpHeaderValidation(ParsingComponent, LoggerMixin):
    """Component for validating CMP message headers."""

    def __init__(self, cmp_message_version: int = 2, transaction_id_length: int = 16,
                 sender_nonce_length: int = 16, implicit_confirm_oid: str = '1.3.6.1.5.5.7.4.13',
                 implicit_confirm_str_value: str = 'NULL') -> None:
        """Initialize the CMP header validation component with configurable parameters.

        Args:
            cmp_message_version: Expected CMP message version (default: 2)
            transaction_id_length: Expected transaction ID length in bytes (default: 16)
            sender_nonce_length: Expected sender nonce length in bytes (default: 16)
            implicit_confirm_oid: Expected implicit confirm OID (default: '1.3.6.1.5.5.7.4.13')
            implicit_confirm_str_value: Expected implicit confirm string value (default: 'NULL')
        """
        self.cmp_message_version = cmp_message_version
        self.transaction_id_length = transaction_id_length
        self.sender_nonce_length = sender_nonce_length
        self.implicit_confirm_oid = implicit_confirm_oid
        self.implicit_confirm_str_value = implicit_confirm_str_value

    def parse(self, context: RequestContext) -> None:
        """Validate the CMP message header."""
        if context.parsed_message is None:
            error_message = 'Parsed message is missing from the context.'
            self.logger.warning("CMP header validation failed: Parsed message is missing")
            raise ValueError(error_message)

        try:
            self._check_header(context.parsed_message)
            self.logger.info("CMP header validation successful")
        except ValueError as e:
            self.logger.error(f"CMP header validation failed: {e}")
            raise

    def _check_header(self, serialized_pyasn1_message: rfc4210.PKIMessage) -> None:
        """Checks some parts of the header."""
        if serialized_pyasn1_message['header']['pvno'] != self.cmp_message_version:
            err_msg = 'pvno fail'
            raise ValueError(err_msg)

        transaction_id = serialized_pyasn1_message['header']['transactionID'].asOctets()
        if len(transaction_id) != self.transaction_id_length:
            err_msg = 'transactionID fail'
            raise ValueError(err_msg)

        sender_nonce = serialized_pyasn1_message['header']['senderNonce'].asOctets()
        if len(sender_nonce) != self.sender_nonce_length:
            err_msg = 'senderNonce fail'
            raise ValueError(err_msg)

        implicit_confirm_entry = None
        for entry in serialized_pyasn1_message['header']['generalInfo']:
            if entry['infoType'].prettyPrint() == self.implicit_confirm_oid:
                implicit_confirm_entry = entry
                break
        if implicit_confirm_entry is None:
            err_msg = 'implicit confirm missing'
            raise ValueError(err_msg)

        if implicit_confirm_entry['infoValue'].prettyPrint() != self.implicit_confirm_str_value:
            err_msg = 'implicit confirm entry fail'
            raise ValueError(err_msg)


class CmpBodyValidation(ParsingComponent, LoggerMixin):
    """Component for validating CMP message body, specifically for IR/CR requests."""

    def __init__(self, cert_template_version: int = 2) -> None:
        """Initialize the CMP body validation component.

        Args:
            cert_template_version: Expected certificate template version (default: 2)
        """
        self.cert_template_version = cert_template_version

    def parse(self, context: RequestContext) -> None:
        """Validate the CMP message body and extract certificate request template."""
        if context.parsed_message is None:
            error_message = 'Parsed message is missing from the context.'
            self.logger.warning("CMP body validation failed: Parsed message is missing")
            raise ValueError(error_message)

        try:
            pki_body = context.parsed_message['body']
            self._validate_body_type_matches_operation(pki_body, context.operation)
            cert_req_template = self._extract_cert_req_template(pki_body)
            #context.cert_req_template = cert_req_template
            self.logger.info("CMP body validation successful")
        except ValueError as e:
            self.logger.error(f"CMP body validation failed: {e}")
            raise

    def _validate_body_type_matches_operation(self, pki_body: rfc4210.PKIBody, operation: str | None) -> None:
        """Validate that the PKI body type matches the expected operation."""
        body_type = pki_body.getName()

        if operation == 'initialization' and body_type != 'ir':
            err_msg = f'Expected CMP IR body for initialization operation, but got CMP {body_type.upper()} body.'
            raise ValueError(err_msg)
        elif operation == 'certification' and body_type != 'cr':
            err_msg = f'Expected CMP CR body for certification operation, but got CMP {body_type.upper()} body.'
            raise ValueError(err_msg)

    def _extract_cert_req_template(self, pki_body: rfc4210.PKIBody) -> rfc2511.CertTemplate:
        """Extracts the certificate request template from the PKI (IR/CR) message body."""
        cert_req_msg = pki_body[0]['certReq']

        if cert_req_msg['certReqId'] != 0:
            err_msg = 'certReqId must be 0.'
            raise ValueError(err_msg)

        body_type = pki_body.getName()
        if body_type in ('ir', 'cr'):
            if not cert_req_msg['certTemplate'].hasValue():
                err_msg = 'certTemplate must be contained in IR/CR CertReqMessage.'
                raise ValueError(err_msg)

        cert_req_template = cert_req_msg['certTemplate']

        if cert_req_template['version'].hasValue() and cert_req_template['version'] != self.cert_template_version:
            err_msg = 'Version must be 2 if supplied in certificate request.'
            raise ValueError(err_msg)

        return cert_req_template


class CmpBodyTypeValidation(ParsingComponent, LoggerMixin):
    """Component for validating CMP body type based on operation context."""

    def parse(self, context: RequestContext) -> None:
        """Validate the CMP body type and extract the appropriate body."""
        if context.parsed_message is None:
            error_message = 'Parsed message is missing from the context.'
            self.logger.warning("CMP body type validation failed: Parsed message is missing")
            raise ValueError(error_message)

        try:
            body_type = context.parsed_message['body'].getName()

            if context.operation == 'initialization' and body_type == 'ir':
                ir_body = self._extract_ir_body(context.parsed_message)
                context.ir_body = ir_body
                self.logger.info("CMP body type validation successful: IR body extracted")
            elif context.operation == 'certification' and body_type == 'cr':
                cr_body = self._extract_cr_body(context.parsed_message)
                context.cr_body = cr_body
                self.logger.info("CMP body type validation successful: CR body extracted")
            else:
                err_msg = f'Expected CMP {context.operation} body, but got CMP {body_type.upper()} body.'
                raise ValueError(err_msg)

        except ValueError as e:
            self.logger.error(f"CMP body type validation failed: {e}")
            raise

    def _extract_ir_body(self, serialized_pyasn1_message: rfc4210.PKIMessage) -> rfc4210.PKIBody:
        """Extract and validate the IR body from the CMP message."""
        message_body_name = serialized_pyasn1_message['body'].getName()
        if message_body_name != 'ir':
            err_msg = f'Expected CMP IR body, but got CMP {message_body_name.upper()} body.'
            raise ValueError(err_msg)

        if serialized_pyasn1_message['body'].getName() != 'ir':
            err_msg = 'not ir message'
            raise ValueError(err_msg)

        ir_body = serialized_pyasn1_message['body']['ir']
        if len(ir_body) > 1:
            err_msg = 'multiple CertReqMessages found for IR.'
            raise ValueError(err_msg)

        if len(ir_body) < 1:
            err_msg = 'no CertReqMessages found for IR.'
            raise ValueError(err_msg)

        return ir_body

    def _extract_cr_body(self, serialized_pyasn1_message: rfc4210.PKIMessage) -> rfc4210.PKIBody:
        """Extract and validate the CR body from the CMP message."""
        message_body_name = serialized_pyasn1_message['body'].getName()
        if message_body_name != 'cr':
            err_msg = f'Expected CMP CR body, but got CMP {message_body_name.upper()} body.'
            raise ValueError(err_msg)

        if serialized_pyasn1_message['body'].getName() != 'cr':
            err_msg = 'not cr message'
            raise ValueError(err_msg)

        cr_body = serialized_pyasn1_message['body']['cr']
        if len(cr_body) > 1:
            err_msg = 'multiple CertReqMessages found for CR.'
            raise ValueError(err_msg)

        if len(cr_body) < 1:
            err_msg = 'no CertReqMessages found for CR.'
            raise ValueError(err_msg)

        return cr_body


class CompositeParsing(ParsingComponent, LoggerMixin):
    """Composite parser to group multiple parsing strategies."""

    def __init__(self) -> None:
        """Initialize the composite parser with an empty list of components."""
        self.components: list[ParsingComponent] = []

    def add(self, component: ParsingComponent) -> None:
        """Add a parsing component to the composite parser."""
        self.components.append(component)

    def remove(self, component: ParsingComponent) -> None:
        """Remove a parsing component from the composite parser."""
        if component in self.components:
            self.components.remove(component)
            self.logger.debug(f"Removed parsing component: {component.__class__.__name__}")
        else:
            error_message = f"Attempted to remove non-existent parsing component: {component.__class__.__name__}"
            self.logger.warning(error_message)
            raise ValueError(error_message)


    def parse(self, context: RequestContext) -> None:
        """Execute all child parsers."""
        self.logger.debug(f"Starting composite parsing with {len(self.components)} components")

        for i, component in enumerate(self.components):
            try:
                component.parse(context)
                self.logger.debug(f"Parsing component {component.__class__.__name__} completed successfully")
            except ValueError as e:
                error_message = f"{component.__class__.__name__}: {e}"
                self.logger.warning(f"Parsing component {component.__class__.__name__} failed: {e}")
                self.logger.error(
                    f"Composite parsing failed at component {i + 1}/{len(self.components)}: {component.__class__.__name__}")
                raise ValueError(error_message) from e
            except Exception as e:
                error_message = f"Unexpected error in {component.__class__.__name__}: {e}"
                self.logger.error(f"Unexpected error in parsing component {component.__class__.__name__}: {e}")
                self.logger.error(
                    f"Composite parsing failed at component {i + 1}/{len(self.components)}: {component.__class__.__name__}")
                raise ValueError(error_message) from e

        self.logger.info(f"Composite parsing successful. All {len(self.components)} components completed")


class CmpMessageParser(CompositeParsing):
    """Parser for CMP-specific HTTP requests."""

    def __init__(self) -> None:
        """Initialize the composite parser with the default set of parsing components."""
        super().__init__()
        self.add(CmpPkiMessageParsing())
        self.add(CmpHeaderValidation())
        self.add(CmpBodyValidation())
        self.add(CmpBodyTypeValidation())


class EstMessageParser(CompositeParsing):
    """Parser for EST-specific HTTP requests."""

    def __init__(self) -> None:
        """Initialize the composite parser with the default set of parsing components."""
        super().__init__()
        self.add(EstPkiMessageParsing())
        self.add(DomainParsing())
        self.add(CertTemplateParsing())
        self.add(EstCsrSignatureVerification())


