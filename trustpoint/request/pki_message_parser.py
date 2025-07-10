import base64
import re
from abc import ABC, abstractmethod
from typing import Any, Optional

from cryptography.hazmat._oid import NameOID
from django.http import HttpRequest, HttpResponse
from cryptography import x509
from pyasn1.codec.ber import decoder
from pyasn1_modules import rfc4210  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.x509 import CertificateSigningRequest, NameAttribute, ExtensionNotFound
import ipaddress

from pki.models import DomainModel


class ParsingContext:
    """A context object to carry parsed data or errors during parsing."""

    def __init__(self) -> None:
        self.data = {}

    def set(self, key: str, value: Any) -> None:
        self.data[key] = value

    def get(self, key: str, default: Optional[Any] = None) -> Any:
        return self.data.get(key, default)


class ParsingComponent(ABC):
    """Abstract base class for components in the composite parsing pattern."""

    @abstractmethod
    def parse(self, data: bytes, context: ParsingContext) -> None:
        """Execute parsing logic and store results in the context."""
        pass


class EstPkiMessageParsing(ParsingComponent):
    """Component for parsing EST-specific PKI messages."""

    def parse(self, data: bytes, context: ParsingContext) -> None:
        """Parse a DER-encoded PKCS#10 certificate signing request."""
        try:
            if b'CERTIFICATE REQUEST-----' in data:
                request_format = 'pem'
                csr = x509.load_pem_x509_csr(data)
            elif re.match(rb'^[A-Za-z0-9+/=\n]+$', data):
                request_format = 'base64_der'
                der_data = base64.b64decode(data)
                csr = x509.load_der_x509_csr(der_data)
            elif data.startswith(b'\x30'):  # ASN.1 DER starts with 0x30
                request_format = 'der'
                csr = x509.load_der_x509_csr(data)
            else:
                raise ValueError("Unsupported CSR format. Ensure it's PEM, Base64, or raw DER.")

            context.set('csr', csr)
            context.set('request_format', request_format)
        except Exception:
            raise ValueError('Failed to deserialize PKCS#10 certificate signing request')

class EstCsrSignatureVerification(ParsingComponent):
    """Parses the context to fetch the CSR and verifies its signature using the public key contained in the CSR."""

    def parse(self, data: bytes, context: ParsingContext) -> None:
        """Validates the signature of the CSR stored in the context."""
        csr: CertificateSigningRequest = context.get("csr")
        if not csr:
            raise ValueError("CSR not found in the parsing context. Ensure it was parsed before signature verification.")

        public_key = csr.public_key()
        signature_hash_algorithm = csr.signature_hash_algorithm
        if signature_hash_algorithm is None:
            raise ValueError("CSR signature hash algorithm is missing.")

        if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            raise TypeError("Unsupported public key type for CSR signature verification.")

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
            raise ValueError("CSR signature verification failed.") from e


class EstSerialNumberExtraction(ParsingComponent):
    """Extracts the serial number from CSR subject attributes and stores it in the context."""

    def parse(self, data: bytes, context: ParsingContext) -> None:
        """Extracts the serial number from CSR and stores it in the parsing context."""
        csr: CertificateSigningRequest = context.get("csr")
        if not csr:
            raise ValueError(
                "CSR not found in the parsing context. Ensure it was parsed before serial number extraction.")

        subject_attributes: list[NameAttribute] = csr.subject
        serial_number_attrs = [attr for attr in subject_attributes if attr.oid == NameOID.SERIAL_NUMBER]

        if not serial_number_attrs:
            context.set("serial_number", None)
            return

        if len(serial_number_attrs) > 1:
            raise ValueError("CSR subject must contain only one serial number attribute.")

        serial_number = serial_number_attrs[0].value
        if isinstance(serial_number, bytes):
            serial_number = serial_number.decode("utf-8")

        context.set("serial_number", serial_number)


class EstCommonNameExtraction(ParsingComponent):
    """Extracts the Common Name (CN) from CSR subject attributes and stores it in the context."""

    def parse(self, data: bytes, context: ParsingContext) -> None:
        """Extracts the Common Name (CN) from CSR and stores it in the parsing context."""
        csr: CertificateSigningRequest = context.get("csr")
        if not csr:
            raise ValueError(
                "CSR not found in the parsing context. Ensure it was parsed before common name extraction.")

        subject_attributes: list[NameAttribute] = csr.subject
        common_name_attrs = [attr for attr in subject_attributes if attr.oid == NameOID.COMMON_NAME]

        if not common_name_attrs:
            raise ValueError("CSR subject must contain a Common Name attribute.")

        if len(common_name_attrs) > 1:
            raise ValueError("CSR subject must contain only one Common Name attribute.")

        common_name = common_name_attrs[0].value
        if isinstance(common_name, bytes):
            common_name = common_name.decode("utf-8")

        context.set("common_name", common_name)


class EstSanExtraction(ParsingComponent):
    """Extracts Subject Alternative Names (SANs) from CSR and stores them in the context."""

    def parse(self, data: bytes, context: ParsingContext) -> None:
        """Extracts DNS names, IPv4/IPv6 addresses, and URIs from CSR's SAN extension."""
        csr: CertificateSigningRequest = context.get("csr")
        if not csr:
            raise ValueError("CSR not found in the parsing context. Ensure it was parsed before SAN extraction.")

        try:
            san_extension = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = san_extension.value
        except ExtensionNotFound:
            context.set("san", ([], [], [], []))
            return

        dns_names = san.get_values_for_type(x509.DNSName)
        ip_addresses = san.get_values_for_type(x509.IPAddress)
        ipv4_addresses = [ip for ip in ip_addresses if isinstance(ip, ipaddress.IPv4Address)]
        ipv6_addresses = [ip for ip in ip_addresses if isinstance(ip, ipaddress.IPv6Address)]
        uniform_resource_identifiers = san.get_values_for_type(x509.UniformResourceIdentifier)

        context.set("san", (dns_names, ipv4_addresses, ipv6_addresses, uniform_resource_identifiers))


class DomainParsing(ParsingComponent):
    """Parses and validates the domain from the request context object.

    Stores the validated domain object in the parsing context.
    """

    def parse(self, data: bytes, context: ParsingContext) -> None:
        """Extract and validate the domain, then add it to the context."""

        domain_str = context.get("domain_str")
        if not domain_str:
            raise ValueError("Domain name is missing in the request context.")

        domain, error_response = self._extract_requested_domain(domain_str)
        if error_response:
            raise ValueError(f"Domain validation failed: {error_response.content.decode()}")

        context.set("requested_domain", domain)

    def _extract_requested_domain(self, domain_name: str) -> tuple[DomainModel | None, HttpResponse | None]:
        """Validate and fetch the domain object by name."""
        try:
            domain = DomainModel.objects.get(unique_name=domain_name)
            return domain, None
        except DomainModel.DoesNotExist:
            return None, HttpResponse(f"Domain '{domain_name}' does not exist.", status=404)
        except DomainModel.MultipleObjectsReturned:
            return None, HttpResponse(f"Multiple domains found for '{domain_name}'.", status=400)

class CertTemplateParsing(ParsingComponent):
    """Parses the certificate template from the request context object."""

    def parse(self, data: bytes, context: ParsingContext) -> None:
        """Extract and validate the certificate template, then add it to the context."""

        certtemplate_str = context.get("certtemplate_str")
        if not certtemplate_str:
            raise ValueError("Certificate template is missing in the request context.")

        context.set("requested_cert_template", certtemplate_str)


class CmpPkiMessageParsing(ParsingComponent):
    """Component for parsing CMP-specific PKI messages."""

    def parse(self, data: bytes, context: ParsingContext) -> None:
        """Parse a CMP PKI message."""
        try:
            serialized_message, _ = decoder.decode(data, asn1Spec=rfc4210.PKIMessage())
            context.set('serialized_pyasn1_message', serialized_message)
        except (ValueError, TypeError):
            raise ValueError("Failed to parse the CMP message. It seems to be corrupted.")


class CompositeParsing(ParsingComponent):
    """Composite parser to group multiple parsing strategies."""

    def __init__(self) -> None:
        self.components: list[ParsingComponent] = []

    def add(self, component: ParsingComponent) -> None:
        """Add a parsing component to the composite parser."""
        self.components.append(component)

    def remove(self, component: ParsingComponent) -> None:
        """Remove a parsing component from the composite parser."""
        self.components.remove(component)

    def parse(self, data: bytes, context: ParsingContext) -> None:
        """Execute all child parsers."""
        for component in self.components:
            component.parse(data, context)
            if context.get('error'):
                break


class CmpMessageParser(CompositeParsing):
    """Parser for CMP-specific HTTP requests."""

    def __init__(self) -> None:
        super().__init__()
        self.add(CmpPkiMessageParsing())


class EstMessageParser(CompositeParsing):
    """Parser for EST-specific HTTP requests."""

    def __init__(self) -> None:
        super().__init__()
        self.add(EstPkiMessageParsing())
        self.add(DomainParsing())
        self.add(CertTemplateParsing())
        self.add(EstCsrSignatureVerification())
        self.add(EstSerialNumberExtraction())
        self.add(EstCommonNameExtraction())
        self.add(EstSanExtraction())


