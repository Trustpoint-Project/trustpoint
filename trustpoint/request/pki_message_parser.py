"""Provides the `PkiMessageParser` class for parsing PKI messages."""
import base64
import re
from abc import ABC, abstractmethod

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from django.http import HttpResponse
from pki.models import DomainModel
from pyasn1.codec.ber import decoder
from pyasn1_modules import rfc4210  # type: ignore[import-untyped]

from request.request_context import RequestContext


class ParsingComponent(ABC):
    """Abstract base class for components in the composite parsing pattern."""

    @abstractmethod
    def parse(self, context: RequestContext) -> None:
        """Execute parsing logic and store results in the context."""


class EstPkiMessageParsing(ParsingComponent):
    """Component for parsing EST-specific PKI messages."""

    def parse(self, context: RequestContext) -> None:
        """Parse a DER-encoded PKCS#10 certificate signing request."""

        def raise_parsing_error(message: str) -> None:
            """Helper to raise a ValueError with given error message."""
            raise ValueError(message)

        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'body') or not context.raw_message.body:
            error_message = 'Raw message is missing body.'
            raise ValueError(error_message)


        try:
            if b'CERTIFICATE REQUEST-----' in context.raw_message.body:
                est_encoding = 'pem'
                csr = x509.load_pem_x509_csr(context.raw_message.body)
            elif re.match(rb'^[A-Za-z0-9+/=\n]+$', context.raw_message.body):
                est_encoding = 'base64_der'
                der_data = base64.b64decode(context.raw_message.body)
                csr = x509.load_der_x509_csr(der_data)
            elif context.raw_message.body.startswith(b'\x30'):  # ASN.1 DER starts with 0x30
                est_encoding = 'der'
                csr = x509.load_der_x509_csr(context.raw_message.body)
            else:
                raise_parsing_error("Unsupported CSR format. Ensure it's PEM, Base64, or raw DER.")

            context.cert_requested = csr
            context.est_encoding = est_encoding
        except Exception as e:
            error_message = 'Failed to parse the CSR.'
            raise ValueError(error_message) from e

class EstCsrSignatureVerification(ParsingComponent):
    """Parses the context to fetch the CSR and verifies its signature using the public key contained in the CSR."""

    def parse(self, context: RequestContext) -> None:
        """Validates the signature of the CSR stored in the context."""
        csr = context.cert_requested
        if csr is None:
            error_message = 'CSR not found in the parsing context. Ensure it was parsed before signature verification.'
            raise ValueError(error_message)

        public_key = csr.public_key()
        signature_hash_algorithm = csr.signature_hash_algorithm
        if signature_hash_algorithm is None:
            error_message = 'CSR does not contain a signature hash algorithm.'
            raise ValueError(error_message)

        if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            error_message = 'Unsupported public key type for CSR signature verification.'
            raise TypeError(error_message)

        try:
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
        except Exception as e:
            error_message = 'Failed to verify the CSR signature.'
            raise ValueError(error_message) from e

class DomainParsing(ParsingComponent):
    """Parses and validates the domain from the request context object."""

    def parse(self, context: RequestContext) -> None:
        """Extract and validate the domain, then add it to the context."""
        domain_str = context.domain_str
        if not domain_str:
            error_message = 'Domain is missing in the request context.'
            raise ValueError(error_message)

        domain, error_response = self._extract_requested_domain(domain_str)
        if error_response:
            error_message = f'Domain validation failed: {error_response.content.decode()}'
            raise ValueError(error_message)

        if not domain:
            error_message = 'Domain validation failed: Domain not found.'
            raise ValueError(error_message)

        context.domain = domain

    def _extract_requested_domain(self, domain_name: str) -> tuple[DomainModel | None, HttpResponse | None]:
        """Validate and fetch the domain object by name."""
        try:
            domain = DomainModel.objects.get(unique_name=domain_name)
        except DomainModel.DoesNotExist:
            return None, HttpResponse(f"Domain '{domain_name}' does not exist.", status=404)
        except DomainModel.MultipleObjectsReturned:
            return None, HttpResponse(f"Multiple domains found for '{domain_name}'.", status=400)
        else:
            return domain, None

class CertTemplateParsing(ParsingComponent):
    """Parses the certificate template from the request context object."""

    def parse(self, context: RequestContext) -> None:
        """Extract and validate the certificate template, then add it to the context."""
        certtemplate_str = context.certificate_template
        if not certtemplate_str:
            error_message = 'Certificate template is missing in the request context.'
            raise ValueError(error_message)

        context.certificate_template = certtemplate_str


class CmpPkiMessageParsing(ParsingComponent):
    """Component for parsing CMP-specific PKI messages."""

    def parse(self, context: RequestContext) -> None:
        """Parse a CMP PKI message."""
        if context.raw_message is None:
            error_message = 'Raw message is missing from the context.'
            raise ValueError(error_message)

        if not hasattr(context.raw_message, 'body') or not context.raw_message.body:
            error_message = 'Raw message is missing body.'
            raise ValueError(error_message)

        try:
            serialized_message, _ = decoder.decode(context.raw_message.body, asn1Spec=rfc4210.PKIMessage())
            context.parsed_message = serialized_message
        except (ValueError, TypeError) as e:
            error_message = 'Failed to parse the CMP message. It seems to be corrupted.'
            raise ValueError(error_message) from e


class CompositeParsing(ParsingComponent):
    """Composite parser to group multiple parsing strategies."""

    def __init__(self) -> None:
        """Initialize the composite parser with an empty list of components."""
        self.components: list[ParsingComponent] = []

    def add(self, component: ParsingComponent) -> None:
        """Add a parsing component to the composite parser."""
        self.components.append(component)

    def remove(self, component: ParsingComponent) -> None:
        """Remove a parsing component from the composite parser."""
        self.components.remove(component)

    def parse(self, context: RequestContext) -> None:
        """Execute all child parsers."""
        for component in self.components:
            component.parse(context)

class CmpMessageParser(CompositeParsing):
    """Parser for CMP-specific HTTP requests."""

    def __init__(self) -> None:
        """Initialize the composite parser with the default set of parsing components."""
        super().__init__()
        self.add(CmpPkiMessageParsing())


class EstMessageParser(CompositeParsing):
    """Parser for EST-specific HTTP requests."""

    def __init__(self) -> None:
        """Initialize the composite parser with the default set of parsing components."""
        super().__init__()
        self.add(EstPkiMessageParsing())
        self.add(DomainParsing())
        self.add(CertTemplateParsing())
        self.add(EstCsrSignatureVerification())


