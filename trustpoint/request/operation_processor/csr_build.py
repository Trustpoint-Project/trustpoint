"""CSR build operation processor classes."""
from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import (
    CertificateSigningRequest,
    CertificateSigningRequestBuilder,
    Name,
    NameAttribute,
    NameOID,
    SubjectAlternativeName,
)

from pki.util.cert_profile import JSONProfileVerifier
from request.request_context import BaseCertificateRequestContext, BaseRequestContext
from trustpoint.logger import LoggerMixin

from .base import AbstractOperationProcessor

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
    from cryptography.x509.general_name import DNSName, IPAddress, RFC822Name, UniformResourceIdentifier


class CsrBuilder(LoggerMixin, AbstractOperationProcessor):
    """Operation processor for building a CSR from validated request data."""

    _csr: CertificateSigningRequest | None = None

    def process_operation(self, context: BaseRequestContext) -> None:
        """Build a CSR from the validated request data in the context.

        Args:
            context: Request context containing the certificate request data.

        Raises:
            TypeError: If context is not a BaseCertificateRequestContext.
            ValueError: If required context attributes are missing.
        """
        if not isinstance(context, BaseCertificateRequestContext):
            exc_msg = 'CSR building requires a BaseCertificateRequestContext.'
            raise TypeError(exc_msg)

        if not context.certificate_profile_model:
            exc_msg = 'Certificate profile model must be set in the context.'
            raise ValueError(exc_msg)

        if not hasattr(context, 'validated_request_data') or context.validated_request_data is None:
            exc_msg = 'Validated request data must be set in the context.'
            raise ValueError(exc_msg)

        validated_request_data = context.validated_request_data
        subject = self._build_subject(validated_request_data)
        extensions = self._build_extensions(validated_request_data)
        private_key = self._get_private_key(context)

        csr_builder = CertificateSigningRequestBuilder().subject_name(subject)
        for ext_value, critical in extensions:
            csr_builder = csr_builder.add_extension(ext_value, critical=critical)

        self._csr = csr_builder.sign(private_key, hashes.SHA256())

        self.logger.info('Built CSR with subject: %s', subject.rfc4514_string())

    def _build_subject(self, validated_request_data: dict[str, Any]) -> Name:
        """Build the subject name from validated request data.

        Args:
            validated_request_data: The validated request data containing subject fields.

        Returns:
            The X.509 Name object for the CSR subject.
        """
        subject_attributes = []
        subj = validated_request_data.get('subject', validated_request_data.get('subj', {}))

        subject_field_map = {
            'common_name': NameOID.COMMON_NAME,
            'organization_name': NameOID.ORGANIZATION_NAME,
            'organizational_unit_name': NameOID.ORGANIZATIONAL_UNIT_NAME,
            'country_name': NameOID.COUNTRY_NAME,
            'state_or_province_name': NameOID.STATE_OR_PROVINCE_NAME,
            'locality_name': NameOID.LOCALITY_NAME,
            'email_address': NameOID.EMAIL_ADDRESS,
        }

        for field_key, name_oid in subject_field_map.items():
            value = subj.get(field_key)
            if value:
                subject_attributes.append(NameAttribute(name_oid, value))

        return Name(subject_attributes)

    def _build_extensions(self, validated_request_data: dict[str, Any]) -> list[tuple[Any, bool]]:
        """Build extensions from validated request data.

        Args:
            validated_request_data: The validated request data containing extension fields.

        Returns:
            List of tuples (extension_value, critical) for X.509 extensions.
        """
        extensions: list[tuple[Any, bool]] = []
        ext = validated_request_data.get('ext', validated_request_data.get('extensions', {}))

        san = ext.get('subject_alternative_name', {})
        san_names = self._build_san_names(san)

        if san_names:
            extensions.append((SubjectAlternativeName(san_names), False))

        return extensions

    def _build_san_names(
        self, san: dict[str, Any]
    ) -> list[DNSName | IPAddress | RFC822Name | UniformResourceIdentifier]:
        """Build Subject Alternative Name entries from validated data.

        Args:
            san: The subject_alternative_name dictionary from validated request data.

        Returns:
            List of GeneralName objects for the SAN extension.
        """
        san_names: list[DNSName | IPAddress | RFC822Name | UniformResourceIdentifier] = []

        self._add_dns_names(san, san_names)
        self._add_ip_addresses(san, san_names)
        self._add_rfc822_names(san, san_names)
        self._add_uris(san, san_names)

        return san_names

    def _add_dns_names(
        self,
        san: dict[str, Any],
        san_names: list[DNSName | IPAddress | RFC822Name | UniformResourceIdentifier],
    ) -> None:
        """Add DNS names to the SAN list."""
        dns_names_str = san.get('dns_names')
        if not dns_names_str:
            return

        for dns_name_raw in dns_names_str.split(','):
            dns_name_clean = dns_name_raw.strip()
            if dns_name_clean:
                san_names.append(x509.DNSName(dns_name_clean))

    def _add_ip_addresses(
        self,
        san: dict[str, Any],
        san_names: list[DNSName | IPAddress | RFC822Name | UniformResourceIdentifier],
    ) -> None:
        """Add IP addresses to the SAN list."""
        ip_addresses_str = san.get('ip_addresses')
        if not ip_addresses_str:
            return

        for ip_addr_raw in ip_addresses_str.split(','):
            ip_addr_clean = ip_addr_raw.strip()
            if not ip_addr_clean:
                continue

            try:
                ip_obj = IPv4Address(ip_addr_clean) if '.' in ip_addr_clean else IPv6Address(ip_addr_clean)
                san_names.append(x509.IPAddress(ip_obj))
            except ValueError as exc:
                self.logger.warning('Invalid IP address "%s": %s', ip_addr_clean, exc)

    def _add_rfc822_names(
        self,
        san: dict[str, Any],
        san_names: list[DNSName | IPAddress | RFC822Name | UniformResourceIdentifier],
    ) -> None:
        """Add RFC822 names (email addresses) to the SAN list."""
        rfc822_names_str = san.get('rfc822_names')
        if not rfc822_names_str:
            return

        for email_addr_raw in rfc822_names_str.split(','):
            email_addr_clean = email_addr_raw.strip()
            if email_addr_clean:
                san_names.append(x509.RFC822Name(email_addr_clean))

    def _add_uris(
        self,
        san: dict[str, Any],
        san_names: list[DNSName | IPAddress | RFC822Name | UniformResourceIdentifier],
    ) -> None:
        """Add URIs to the SAN list."""
        uris_str = san.get('uris')
        if not uris_str:
            return

        for uri_addr_raw in uris_str.split(','):
            uri_addr_clean = uri_addr_raw.strip()
            if uri_addr_clean:
                san_names.append(x509.UniformResourceIdentifier(uri_addr_clean))

    def _get_private_key(self, context: BaseCertificateRequestContext) -> CertificateIssuerPrivateKeyTypes:
        """Get the private key to sign the CSR.

        Args:
            context: Request context containing credential information.

        Returns:
            The private key to use for signing the CSR.

        Raises:
            ValueError: If no credential with private key is available.
        """
        if context.owner_credential:
            return context.owner_credential.get_private_key()

        if context.issuer_credential:
            return context.issuer_credential.get_private_key()

        exc_msg = 'No credential with private key available in context for CSR signing.'
        raise ValueError(exc_msg)

    def get_csr(self) -> CertificateSigningRequest:
        """Get the built CSR.

        Returns:
            The built CertificateSigningRequest.

        Raises:
            ValueError: If CSR has not been built yet.
        """
        if self._csr is None:
            exc_msg = 'CSR not built. Call process_operation first.'
            raise ValueError(exc_msg)
        return self._csr


class ProfileAwareCsrBuilder(CsrBuilder):
    """CSR builder that applies certificate profile validation before building the CSR."""

    def process_operation(self, context: BaseRequestContext) -> None:
        """Build a CSR from request data after applying profile validation.

        Args:
            context: Request context containing the certificate request data and profile.

        Raises:
            TypeError: If context is not a BaseCertificateRequestContext.
            ValueError: If required context attributes are missing.
        """
        if not isinstance(context, BaseCertificateRequestContext):
            exc_msg = 'CSR building requires a BaseCertificateRequestContext.'
            raise TypeError(exc_msg)

        if not context.certificate_profile_model:
            exc_msg = 'Certificate profile model must be set in the context.'
            raise ValueError(exc_msg)

        if not hasattr(context, 'request_data') or context.request_data is None:
            exc_msg = 'Request data must be set in the context.'
            raise ValueError(exc_msg)

        profile_json = context.certificate_profile_model.profile
        profile_verifier = JSONProfileVerifier(profile_json)
        context.validated_request_data = profile_verifier.apply_profile_to_request(context.request_data)

        self.logger.debug('Applied profile validation. Validated data: %s', context.validated_request_data)

        super().process_operation(context)
