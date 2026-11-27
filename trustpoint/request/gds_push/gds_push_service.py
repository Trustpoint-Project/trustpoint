# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Service for OPC UA GDS Push operations."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import datetime as dt
import hashlib
import io
import ipaddress
import os
import tempfile
from typing import TYPE_CHECKING, Any, ClassVar, NoReturn

from asgiref.sync import sync_to_async
from asyncua import ua
from asyncua.client.client import Client
from asyncua.crypto import security_policies
from asyncua.ua.status_codes import StatusCodes, get_name_and_doc
from asyncua.ua.ua_binary import struct_from_binary, struct_to_binary
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import KeyUsage
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID
from django.conf import settings
from django.db import transaction

from pki.models import CertificateModel, IssuedCredentialModel, TruststoreOrderModel
from pki.models.certificate import RevokedCertificateModel
from pki.services.csr import parse_csr
from pki.services.revocation import revoke_certificate
from request.operation_processor import CertificateIssueProcessor
from request.profile_validator import ProfileValidator
from request.request_context import BaseCertificateRequestContext
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from asyncua.common.node import Node

    from devices.models import DeviceModel
    from pki.models import CaModel
    from pki.models.truststore import TruststoreModel

__all__ = ['GdsPushError', 'GdsPushService']


class GdsPushError(Exception):
    """Exception raised for GDS Push operation failures."""


class CertificateTypes:
    """OPC UA GDS Certificate Types (Section 7.8.4)."""

    ECC_APPLICATION_TYPE_ID = 23537
    ECC_NIST_P256_TYPE_ID = 23538
    ECC_NIST_P384_TYPE_ID = 23539
    ECC_BRAINPOOL_P256_TYPE_ID = 23540
    ECC_BRAINPOOL_P384_TYPE_ID = 23541
    ECC_CURVE25519_TYPE_ID = 23542
    ECC_CURVE448_TYPE_ID = 23543

    APPLICATION_CERTIFICATE = ua.NodeId.from_string('ns=0;i=12557')
    HTTPS_CERTIFICATE = ua.NodeId.from_string('ns=0;i=12558')
    RSA_MIN_APPLICATION_CERTIFICATE = ua.NodeId.from_string('ns=0;i=12559')
    RSA_SHA256_APPLICATION_CERTIFICATE = ua.NodeId.from_string('ns=0;i=12560')
    ECC_NIST_P256_APPLICATION_CERTIFICATE = ua.NodeId.from_string('ns=0;i=23538')
    ECC_NIST_P384_APPLICATION_CERTIFICATE = ua.NodeId.from_string('ns=0;i=23539')
    ECC_BRAINPOOL_P256R1_APPLICATION_CERTIFICATE = ua.NodeId.from_string('ns=0;i=23540')
    ECC_BRAINPOOL_P384R1_APPLICATION_CERTIFICATE = ua.NodeId.from_string('ns=0;i=23541')

    # CertificateType subtypes that may be assigned to an application (Section 7.8.4).
    APPLICATION_TYPE_IDS = frozenset(
        {
            12557,  # ApplicationCertificateType
            12559,  # RsaMinApplicationCertificateType
            12560,  # RsaSha256ApplicationCertificateType
            23537,  # EccApplicationCertificateType
            23538,  # EccNistP256ApplicationCertificateType
            23539,  # EccNistP384ApplicationCertificateType
            23540,  # EccBrainpoolP256r1ApplicationCertificateType
            23541,  # EccBrainpoolP384r1ApplicationCertificateType
            23542,  # EccCurve25519ApplicationCertificateType
            23543,  # EccCurve448ApplicationCertificateType
        }
    )
    # CertificateGroupType.Purpose values that are not application certificates.
    NON_APPLICATION_PURPOSE_IDS = frozenset({12558, 19323, 19324, 19325, 19326})
    # Prefer SHA-256 RSA, then RSA minimum, then the named ECC curves.
    PREFERRED_APPLICATION_TYPE_IDS = (
        12560,
        12559,
        23538,
        23539,
        23540,
        23541,
        23542,
        23543,
        23537,
        12557,
    )


class GdsPushService(LoggerMixin):
    """Service for managing OPC UA GDS Push operations.

    This service handles secure communication with OPC UA servers and implements
    GDS Push workflows for certificate and trustlist management.

    Architecture:
    - Device provides connection info (IP, port)
    - Device's domain provides the CA hierarchy
    - Domain credential provides client authentication
    - Truststore (opc_trust_store) provides server validation
    - TrustList (CA chain + CRLs) gets pushed to server
    """

    device: DeviceModel
    server_url: str
    domain_credential: IssuedCredentialModel | None
    server_truststore: TruststoreModel | None

    def __init__(
        self,
        device: DeviceModel,
        *,
        insecure: bool = False,
    ) -> None:
        """Initialize GDS Push service.

        Args:
            device: The OPC UA device to manage. Must have:
                   - IP address and port configured
                   - Domain with issuing CA (for secure operations)
                   - Domain credential (for secure operations)
                   - GDS Push config with opc_trust_store (for secure operations)
            insecure: If True, skip authentication setup for discovery operations.

        Raises:
            GdsPushError: If device configuration is invalid.
        """
        self.device = device
        self._capabilities: dict[str, Any] = {}
        self._apply_changes_required = False
        self._apply_changes_attempted = False
        self._validate_device_config()

        configured_url = (getattr(device.opc_ua_gds_push_config, 'opc_server_url', '') or '').strip()
        self.server_url = configured_url or (
            f'opc.tcp://{device.ip_address}:{device.opc_ua_gds_push_config.opc_server_port}'
        )

        if insecure:
            self.domain_credential = None
            self.server_truststore = None
            return

        self._setup_secure_mode()

    def _validate_device_config(self) -> None:
        """Validate device has required configuration.

        Raises:
            GdsPushError: If device configuration is invalid.
        """
        config = getattr(self.device, 'opc_ua_gds_push_config', None)
        has_url = bool((getattr(config, 'opc_server_url', '') or '').strip())
        if config is None or (not has_url and (not self.device.ip_address or not config.opc_server_port)):
            msg = (
                f'Device "{self.device.common_name}" must have an IP address and OPC server port, '
                'or an OPC server URL configured'
            )
            self._raise_gds_push_error(msg)

    def _setup_secure_mode(self) -> None:
        """Setup credentials and truststore for secure operations.

        Raises:
            GdsPushError: If secure configuration is incomplete.
        """
        self.domain_credential = self._get_domain_credential()

        self.server_truststore = self._get_server_truststore()

    def _get_domain_credential(self) -> IssuedCredentialModel:
        """Get domain credential from device for client authentication.

        Returns:
            The most recent valid domain credential.

        Raises:
            GdsPushError: If no valid domain credential found.
        """
        credentials = IssuedCredentialModel.objects.filter(
            device=self.device, issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL
        ).order_by('-created_at')

        if not credentials.exists():
            msg = (
                f'No domain credential found for device "{self.device.common_name}". '
                f'Please issue a domain credential first.'
            )
            raise GdsPushError(msg)

        credential = credentials.first()
        if credential is None:
            msg = 'Failed to retrieve domain credential'
            raise GdsPushError(msg)

        return credential

    def _get_server_truststore(self) -> TruststoreModel:
        """Get truststore containing OPC UA server certificate.

        This truststore is used to validate the OPC UA server during connection.

        Returns:
            Truststore from the device's OPC UA GDS Push configuration.

        Raises:
            GdsPushError: If truststore not configured or empty.
        """
        if not hasattr(self.device, 'opc_ua_gds_push_config'):
            msg = f'Device "{self.device.common_name}" has no OPC UA GDS Push config'
            raise GdsPushError(msg)

        if not self.device.opc_ua_gds_push_config.opc_trust_store:
            msg = (
                f'Device "{self.device.common_name}" GDS Push config has no OPC UA '
                f'server truststore (opc_trust_store) configured'
            )
            raise GdsPushError(msg)

        truststore = self.device.opc_ua_gds_push_config.opc_trust_store

        cert_count = truststore.truststoreordermodel_set.count()
        if cert_count == 0:
            msg = (
                f'Server truststore "{truststore.unique_name}" is empty. '
                f'Please add the OPC UA server certificate to the truststore.'
            )
            raise GdsPushError(msg)

        return truststore

    # ========================================================================
    # TrustList Building (CA Chain + CRLs)
    # ========================================================================

    async def _build_ca_chain(self) -> list[CaModel]:
        """Build CA certificate chain from device's domain issuing CA to root.

        Returns:
            List of CA models from issuing CA to root CA.

        Raises:
            GdsPushError: If chain is incomplete or invalid.
        """
        device = await sync_to_async(lambda: self.device)()
        domain = await sync_to_async(lambda: device.domain)()

        if not domain:
            msg = f'Device "{device.common_name}" has no domain configured'
            raise GdsPushError(msg)

        issuing_ca = await sync_to_async(lambda: domain.issuing_ca)()
        if not issuing_ca:
            msg = f'Domain "{domain.unique_name}" has no issuing CA configured'
            raise GdsPushError(msg)

        return await sync_to_async(issuing_ca.get_ca_chain_from_truststore)()

    @staticmethod
    def _validate_ca_material(
        certificate: x509.Certificate,
        ca_name: str,
        *,
        has_crl: bool,
    ) -> None:
        """Reject CA certificates that cannot sign certificates or CRLs."""
        try:
            basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound as e:
            msg = f'CA "{ca_name}" has no BasicConstraints extension.'
            raise GdsPushError(msg) from e
        if not basic_constraints.ca:
            msg = f'CA "{ca_name}" is not marked as a CA in BasicConstraints.'
            raise GdsPushError(msg)

        try:
            key_usage: x509.KeyUsage | None = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            key_usage = None
        if key_usage is not None:
            if not key_usage.key_cert_sign:
                msg = f'CA "{ca_name}" does not permit certificate signing (keyCertSign).'
                raise GdsPushError(msg)
            if has_crl and not key_usage.crl_sign:
                msg = f'CA "{ca_name}" does not permit CRL signing (cRLSign) but a CRL is included.'
                raise GdsPushError(msg)

    async def _build_trustlist_for_server(self) -> ua.TrustListDataType:
        """Build OPC UA TrustList to push to server.

        The TrustList tells the OPC UA server which CAs to trust for client
        certificate validation. The root is the trust anchor
        (TrustedCertificates/TrustedCrls); issuing and intermediate CAs are
        chain material (IssuerCertificates/IssuerCrls). All CA CRLs are
        mandatory.

        Returns:
            TrustListDataType ready to push to server.

        Raises:
            GdsPushError: If trustlist cannot be built, any CA is missing a CRL,
                         or any CRL is expired.
        """
        ca_chain = await self._build_ca_chain()
        if not ca_chain:
            msg = 'CA chain is empty; cannot build the OPC UA TrustList.'
            raise GdsPushError(msg)

        config = getattr(self.device, 'opc_ua_gds_push_config', None)
        require_crls = bool(getattr(config, 'opc_gds_push_require_crls', True))

        # get_ca_chain_from_truststore returns issuing CA -> root.
        chain_material: list[tuple[bytes, bytes | None]] = []
        for ca in ca_chain:
            ca_cert_model = await sync_to_async(lambda ca=ca: ca.ca_certificate_model)()

            ca_cert_crypto = await sync_to_async(ca_cert_model.get_certificate_serializer().as_crypto)()
            ca_cert_der = ca_cert_crypto.public_bytes(encoding=serialization.Encoding.DER)

            crl_pem = await sync_to_async(lambda ca=ca: ca.crl_pem)()
            if not crl_pem:
                if require_crls:
                    msg = (
                        f'CA "{ca.unique_name}" has no CRL configured. CRL is mandatory for OPC UA GDS Push trustlist.'
                    )
                    raise GdsPushError(msg)
                self.logger.warning(
                    'CA "%s" has no CRL; continuing because CRLs are optional for this device',
                    ca.unique_name,
                )
                self._validate_ca_material(ca_cert_crypto, ca.unique_name, has_crl=False)
                chain_material.append((ca_cert_der, None))
                continue

            try:
                crl_crypto = x509.load_pem_x509_crl(crl_pem.encode())
            except Exception as e:
                msg = f'Failed to load CRL for CA "{ca.unique_name}": {e}'
                raise GdsPushError(msg) from e

            now = dt.datetime.now(tz=dt.UTC)
            if crl_crypto.next_update_utc and crl_crypto.next_update_utc < now:
                msg = (
                    f'CRL for CA "{ca.unique_name}" has expired. '
                    f'Next update was: {crl_crypto.next_update_utc.isoformat()}, '
                    f'Current time: {now.isoformat()}'
                )
                raise GdsPushError(msg)

            self._validate_ca_material(ca_cert_crypto, ca.unique_name, has_crl=True)
            crl_der = crl_crypto.public_bytes(encoding=serialization.Encoding.DER)
            chain_material.append((ca_cert_der, crl_der))

        root_cert, root_crl = chain_material[-1]
        issuers = chain_material[:-1]

        trustlist = ua.TrustListDataType()
        trustlist.SpecifiedLists = ua.TrustListMasks.All
        trustlist.TrustedCertificates = [root_cert]
        trustlist.TrustedCrls = [root_crl] if root_crl else []
        trustlist.IssuerCertificates = [cert for cert, _crl in issuers]
        trustlist.IssuerCrls = [crl for _cert, crl in issuers if crl]

        return trustlist

    # ========================================================================
    # OPC UA Client Creation & Connection
    # ========================================================================

    async def _get_client_credentials(self) -> tuple[x509.Certificate, bytes]:
        """Get client certificate and private key from domain credential.

        Returns:
            Tuple of (certificate crypto object, private key PEM bytes).

        Raises:
            GdsPushError: If credentials are invalid.
        """
        if self.domain_credential is None:
            msg = 'No domain credential available'
            raise GdsPushError(msg)

        domain_cred = self.domain_credential

        is_valid, reason = await sync_to_async(domain_cred.is_valid_domain_credential)()
        if not is_valid:
            msg = f'Invalid domain credential: {reason}'
            raise GdsPushError(msg)

        credential = await sync_to_async(lambda: domain_cred.credential)()
        cert_model = await sync_to_async(lambda: credential.certificate)()

        if not cert_model:
            msg = 'Domain credential has no certificate'
            raise GdsPushError(msg)

        cert_crypto = await sync_to_async(cert_model.get_certificate_serializer().as_crypto)()

        self._validate_client_certificate(cert_crypto)

        try:
            key_crypto = await sync_to_async(credential.get_private_key)()
        except RuntimeError as e:
            msg = f'Failed to get private key: {e}'
            raise GdsPushError(msg) from e

        self._verify_certificate_key_match(cert_crypto, key_crypto)

        key_pem = key_crypto.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return cert_crypto, key_pem

    async def _build_client_certificate_chain(self) -> bytes:
        """Build complete client certificate chain in PEM format.

        OPC UA servers need the full chain to validate the client certificate.
        The chain includes: client cert + issuing CA + intermediate CAs + root CA.

        Returns:
            Complete certificate chain in PEM format (client cert + CA chain).

        Raises:
            GdsPushError: If chain cannot be built.
        """
        if self.domain_credential is None:
            msg = 'No domain credential available'
            raise GdsPushError(msg)

        domain_cred = self.domain_credential

        credential = await sync_to_async(lambda: domain_cred.credential)()
        cert_model = await sync_to_async(lambda: credential.certificate)()

        if not cert_model:
            msg = 'Domain credential has no certificate'
            raise GdsPushError(msg)

        client_cert = await sync_to_async(cert_model.get_certificate_serializer().as_crypto)()

        chain_pems = [client_cert.public_bytes(encoding=serialization.Encoding.PEM)]

        ca_chain = await self._build_ca_chain()
        for ca in ca_chain:
            ca_cert_model = await sync_to_async(lambda ca=ca: ca.ca_certificate_model)()
            ca_cert = await sync_to_async(ca_cert_model.get_certificate_serializer().as_crypto)()
            chain_pems.append(ca_cert.public_bytes(encoding=serialization.Encoding.PEM))

        return b''.join(chain_pems)

    def _verify_certificate_key_match(
        self,
        cert: x509.Certificate,
        private_key: Any,
    ) -> None:
        """Verify that certificate and private key are a matching pair.

        Args:
            cert: The certificate.
            private_key: The private key.

        Raises:
            GdsPushError: If certificate and key don't match.
        """
        cert_public_key = cert.public_key()
        private_public_key = private_key.public_key()

        cert_public_bytes = cert_public_key.public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_public_bytes = private_public_key.public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if cert_public_bytes != private_public_bytes:
            msg = 'Certificate and private key do not match (public keys differ)'
            raise GdsPushError(msg)

    def _validate_client_certificate(self, cert: x509.Certificate) -> None:  # noqa: C901
        """Validate client certificate meets OPC UA requirements.

        Args:
            cert: The client certificate to validate.

        Raises:
            GdsPushError: If certificate doesn't meet OPC UA requirements.
        """
        issues = []

        now = dt.datetime.now(tz=dt.UTC)
        if cert.not_valid_before_utc > now:
            issues.append(f'Certificate not yet valid (valid from: {cert.not_valid_before_utc.isoformat()})')
        if cert.not_valid_after_utc < now:
            issues.append(f'Certificate expired (valid until: {cert.not_valid_after_utc.isoformat()})')

        try:
            key_usage_value = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            if isinstance(key_usage_value, KeyUsage):
                required_usages = {
                    'digital_signature': key_usage_value.digital_signature,
                    'content_commitment': key_usage_value.content_commitment,
                    'key_encipherment': key_usage_value.key_encipherment,
                    'data_encipherment': key_usage_value.data_encipherment,
                }
                missing_usages = [name for name, present in required_usages.items() if not present]
                if missing_usages:
                    issues.append(f'Missing required key usages: {", ".join(missing_usages)}')
        except x509.ExtensionNotFound:
            issues.append('Key Usage extension is missing (required for OPC UA)')

        try:
            ext_key_usage_value = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            if (
                isinstance(ext_key_usage_value, frozenset)
                and ExtendedKeyUsageOID.CLIENT_AUTH not in ext_key_usage_value
            ):
                issues.append('Certificate missing CLIENT_AUTH extended key usage')
        except x509.ExtensionNotFound:
            issues.append('Extended Key Usage extension is missing (should have CLIENT_AUTH)')

        try:
            san_value = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            if isinstance(san_value, x509.SubjectAlternativeName):
                has_uri = any(isinstance(gn, x509.UniformResourceIdentifier) for gn in san_value)
                if not has_uri:
                    issues.append('Certificate SAN has no URI (application URI required for OPC UA)')
        except x509.ExtensionNotFound:
            issues.append('Subject Alternative Name extension is missing (required for OPC UA)')

        if issues:
            msg = (
                f'Client certificate does not meet OPC UA requirements:\n'
                f'{chr(10).join(f"  - {issue}" for issue in issues)}'
            )
            raise GdsPushError(msg)

    @staticmethod
    def _san_values(cert_or_csr: Any) -> tuple[set[str], set[str], set[str]]:
        """Return the URI, DNS and IP SAN values of a certificate or CSR."""
        uris: set[str] = set()
        dns_names: set[str] = set()
        ip_addresses: set[str] = set()
        try:
            san = cert_or_csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        except x509.ExtensionNotFound:
            return uris, dns_names, ip_addresses
        if not isinstance(san, x509.SubjectAlternativeName):
            return uris, dns_names, ip_addresses
        for general_name in san:
            if isinstance(general_name, x509.UniformResourceIdentifier):
                uris.add(general_name.value)
            elif isinstance(general_name, x509.DNSName):
                dns_names.add(general_name.value.casefold())
            elif isinstance(general_name, x509.IPAddress):
                ip_addresses.add(str(general_name.value))
        return uris, dns_names, ip_addresses

    @staticmethod
    def _name_value(value: str | bytes) -> str:
        """Return a DN attribute value as text."""
        return value.decode('utf-8', errors='replace') if isinstance(value, bytes) else value

    def _validate_issued_certificate_policy(self, certificate: x509.Certificate) -> None:
        """Preflight the issued certificate against the configured device policy."""
        config = getattr(self.device, 'opc_ua_gds_push_config', None)
        minimum_key_size = getattr(config, 'opc_gds_push_minimum_key_size', 0) or 0
        if minimum_key_size:
            key_size = getattr(certificate.public_key(), 'key_size', 0)
            if key_size and key_size < minimum_key_size:
                msg = (
                    f'Issued certificate key size {key_size} is below the configured minimum '
                    f'of {minimum_key_size} bits.'
                )
                self._raise_gds_push_error(msg)

        if getattr(config, 'opc_gds_push_reject_sha1', True):
            try:
                algorithm = certificate.signature_hash_algorithm
            except Exception:  # noqa: BLE001
                algorithm = None
            if algorithm is not None and algorithm.name.lower() == 'sha1':
                msg = 'Issued certificate is signed with SHA-1; the device policy requires a stronger hash.'
                self._raise_gds_push_error(msg)

    async def _validate_csr_identity(  # noqa: C901
        self,
        csr: x509.CertificateSigningRequest,
        *,
        expect_new_key: bool = False,
    ) -> None:
        """Validate that the CSR preserves the server's identity and SANs."""
        uris, dns_names, ip_addresses = self._san_values(csr)
        if len(uris) != 1:
            msg = f'Server CSR must contain exactly one ApplicationUri SAN; found {len(uris)}.'
            self._raise_gds_push_error(msg)
        if not dns_names and not ip_addresses:
            msg = 'Server CSR must contain at least one DNS or IP SAN.'
            self._raise_gds_push_error(msg)

        common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not common_names:
            msg = 'Server CSR has no Common Name; the certificate must identify the application.'
            self._raise_gds_push_error(msg)

        current: x509.Certificate | None = None
        if self.server_truststore is not None:
            try:
                current = x509.load_der_x509_certificate(await self._get_server_certificate())
            except GdsPushError:
                self.logger.debug('No current server certificate available for CSR identity comparison')

        if current is None:
            return

        current_uris, current_dns, current_ips = self._san_values(current)
        if current_uris and not uris.issubset(current_uris):
            msg = (
                f'CSR ApplicationUri {sorted(uris)} does not match the current server certificate '
                f'{sorted(current_uris)}.'
            )
            self._raise_gds_push_error(msg)

        current_cn = current.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        csr_cn = self._name_value(common_names[0].value)
        if current_cn and csr_cn.casefold() != self._name_value(current_cn[0].value).casefold():
            msg = (
                f'CSR Common Name "{csr_cn}" does not match the current certificate '
                f'"{self._name_value(current_cn[0].value)}". Some servers reject a changed CN.'
            )
            self._raise_gds_push_error(msg)

        missing_dns = current_dns - dns_names
        missing_ips = current_ips - ip_addresses
        if missing_dns or missing_ips:
            msg = (
                'CSR does not preserve the current server certificate SANs: '
                f'missing DNS {sorted(missing_dns)}, IP {sorted(missing_ips)}.'
            )
            self._raise_gds_push_error(msg)

        if expect_new_key:
            csr_key = csr.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            current_key = current.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            if csr_key == current_key:
                msg = 'Server ignored RegeneratePrivateKey; the CSR still uses the current public key.'
                self._raise_gds_push_error(msg)

    def _extract_application_uri(self, cert: x509.Certificate) -> str:
        """Extract application URI from certificate.

        Args:
            cert: The certificate to extract from.

        Returns:
            The application URI.

        Raises:
            GdsPushError: If no application URI found.
        """
        try:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for general_name in san.value:  # type: ignore[attr-defined]
                if isinstance(general_name, x509.UniformResourceIdentifier):
                    return general_name.value
        except x509.ExtensionNotFound:
            pass

        msg = 'No application URI found in domain credential certificate'
        raise GdsPushError(msg)

    async def _get_server_certificate(self) -> bytes:
        """Get the OPC UA server certificate used to authenticate the secure channel.

        In pinned mode the certificate at truststore order 0 is used. In CA mode the
        current server certificate is fetched from discovery and accepted only when it
        chains to a certificate in the truststore, so server certificate rotation does
        not require editing the truststore first.

        Returns:
            Server certificate in DER format.

        Raises:
            GdsPushError: If truststore is empty, misconfigured or the CA chain is invalid.
        """
        if self.server_truststore is None:
            msg = 'No server truststore configured'
            raise GdsPushError(msg)

        config = getattr(self.device, 'opc_ua_gds_push_config', None)
        mode = getattr(config, 'opc_gds_push_server_validation', 'pinned') or 'pinned'
        if mode == 'ca':
            return await self._get_server_certificate_via_ca()

        server_truststore = self.server_truststore

        try:
            truststore_order = await sync_to_async(lambda: server_truststore.truststoreordermodel_set.get(order=0))()
        except Exception as e:
            msg = f'Server truststore "{self.server_truststore.unique_name}" has no certificate at order 0: {e}'
            raise GdsPushError(msg) from e

        cert_model = await sync_to_async(lambda: truststore_order.certificate)()
        cert_crypto = await sync_to_async(cert_model.get_certificate_serializer().as_crypto)()
        cert_der = cert_crypto.public_bytes(encoding=serialization.Encoding.DER)

        is_ca = False
        try:
            basic_constraints = cert_crypto.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            is_ca = basic_constraints.value.ca  # type: ignore[attr-defined]
        except x509.ExtensionNotFound:
            pass

        if is_ca:
            self.logger.warning(
                'Certificate at order 0 appears to be a CA certificate. '
                'Server certificate should be at order 0, followed by CA certificates.'
            )

        self.logger.info('Using server certificate: %s (%d bytes)', cert_crypto.subject.rfc4514_string(), len(cert_der))

        return cert_der

    async def _load_server_truststore_certificates(self) -> list[x509.Certificate]:
        """Load every certificate from the configured server truststore."""
        truststore = self.server_truststore
        if truststore is None:
            msg = 'No server truststore configured'
            raise GdsPushError(msg)
        orders = await sync_to_async(
            lambda: list(truststore.truststoreordermodel_set.order_by('order').select_related('certificate'))
        )()
        certificates: list[x509.Certificate] = []
        for order in orders:
            cert_model = order.certificate
            certificates.append(
                await sync_to_async(lambda model=cert_model: model.get_certificate_serializer().as_crypto())()
            )
        return certificates

    @staticmethod
    def _first_der_certificate(blob: bytes) -> bytes:
        """Peel the leading certificate out of a possibly chained DER blob."""
        if len(blob) < 4:  # noqa: PLR2004
            msg = 'Server returned an empty certificate'
            raise GdsPushError(msg)
        length = int.from_bytes(blob[2:4], byteorder='big', signed=False) + 4
        return blob[:length]

    def _validate_server_certificate_chain(  # noqa: C901
        self,
        leaf: x509.Certificate,
        trusted: list[x509.Certificate],
    ) -> None:
        """Verify that the server leaf chains to a certificate in the truststore."""
        now = dt.datetime.now(dt.UTC)

        def check_validity(certificate: x509.Certificate) -> None:
            if not certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc:
                msg = f'Certificate "{certificate.subject.rfc4514_string()}" is not currently valid.'
                raise GdsPushError(msg)

        def fingerprint(certificate: x509.Certificate) -> bytes:
            return certificate.fingerprint(hashes.SHA256())

        trusted_fingerprints = {fingerprint(cert) for cert in trusted}
        check_validity(leaf)
        if fingerprint(leaf) in trusted_fingerprints and leaf.subject == leaf.issuer:
            return

        current = leaf
        seen = {fingerprint(leaf)}
        for _ in range(len(trusted) + 1):
            if current.subject == current.issuer:
                if fingerprint(current) in trusted_fingerprints:
                    return
                break
            issuer = None
            for candidate in trusted:
                if candidate.subject != current.issuer or fingerprint(candidate) in seen:
                    continue
                try:
                    current.verify_directly_issued_by(candidate)
                except (InvalidSignature, ValueError, TypeError):
                    continue
                issuer = candidate
                break
            if issuer is None:
                break
            check_validity(issuer)
            seen.add(fingerprint(issuer))
            if fingerprint(issuer) in trusted_fingerprints:
                return
            current = issuer

        msg = 'Server certificate does not chain to a certificate in the configured truststore.'
        raise GdsPushError(msg)

    async def _get_server_certificate_via_ca(self) -> bytes:
        """Fetch the current server certificate and validate it against the truststore CA chain."""
        trusted = await self._load_server_truststore_certificates()
        discovery = self._create_insecure_client()
        try:
            endpoints = await discovery.connect_and_get_server_endpoints()
        except Exception as e:
            msg = f'Could not discover the server certificate: {e}'
            raise GdsPushError(msg) from e
        finally:
            with contextlib.suppress(Exception):
                await discovery.disconnect()

        errors: list[str] = []
        for endpoint in endpoints:
            blob = bytes(endpoint.ServerCertificate or b'')
            if not blob:
                continue
            try:
                leaf_der = self._first_der_certificate(blob)
                leaf = x509.load_der_x509_certificate(leaf_der)
                self._validate_server_certificate_chain(leaf, trusted)
            except Exception as e:  # noqa: BLE001
                errors.append(str(e))
                continue
            self.logger.info(
                'Using CA-validated server certificate: %s (%d bytes)',
                leaf.subject.rfc4514_string(),
                len(leaf_der),
            )
            return leaf_der

        detail = f': {errors[0]}' if errors else ''
        msg = f'No server certificate advertised by the endpoint chains to the configured truststore{detail}'
        raise GdsPushError(msg)

    _SECURITY_POLICIES: ClassVar[dict[str, type[security_policies.SecurityPolicy]]] = {
        'Aes256Sha256RsaPss': security_policies.SecurityPolicyAes256Sha256RsaPss,
        'Aes128Sha256RsaOaep': security_policies.SecurityPolicyAes128Sha256RsaOaep,
        'Basic256Sha256': security_policies.SecurityPolicyBasic256Sha256,
        'Basic256': security_policies.SecurityPolicyBasic256,
        'Basic128Rsa15': security_policies.SecurityPolicyBasic128Rsa15,
    }
    _SECURITY_POLICY_PREFERENCE: ClassVar[tuple[str, ...]] = (
        'Aes256Sha256RsaPss',
        'Aes128Sha256RsaOaep',
        'Basic256Sha256',
        'Basic256',
        'Basic128Rsa15',
    )

    async def _select_security_policy(self) -> tuple[type[security_policies.SecurityPolicy], str]:
        """Select the strongest SignAndEncrypt policy advertised by the server."""
        discovery = None
        try:
            discovery = self._create_insecure_client()
            endpoints = await discovery.connect_and_get_server_endpoints()
        except Exception as e:  # noqa: BLE001
            self.logger.warning('Could not discover server security policies: %s', e)
            return security_policies.SecurityPolicyBasic256Sha256, 'Basic256Sha256'
        finally:
            if discovery is not None:
                with contextlib.suppress(Exception):
                    await discovery.disconnect()

        available = {
            endpoint.SecurityPolicyUri.rsplit('#', 1)[-1]
            for endpoint in endpoints
            if endpoint.SecurityMode == ua.MessageSecurityMode.SignAndEncrypt
        }
        for name in self._SECURITY_POLICY_PREFERENCE:
            if name in available:
                return self._SECURITY_POLICIES[name], name

        self.logger.warning('No supported SignAndEncrypt endpoint advertised; falling back to Basic256Sha256')
        return security_policies.SecurityPolicyBasic256Sha256, 'Basic256Sha256'

    async def _create_secure_client(self) -> Client:
        """Create OPC UA client with secure connection.

        Certificate credentials are always used for the secure channel. Optional
        OPC username/password credentials are sent only when a username is configured.

        Returns:
            Configured OPC UA client ready to connect.

        Raises:
            GdsPushError: If client creation fails.
        """
        try:
            client_cert_crypto, client_key_pem = await self._get_client_credentials()
            server_cert_der = await self._get_server_certificate()

            application_uri = self._extract_application_uri(client_cert_crypto)

            policy, policy_name = await self._select_security_policy()
            self.logger.info('Setting security policy: %s', policy_name)

            client_cert_chain_pem = await self._build_client_certificate_chain()

            with tempfile.TemporaryDirectory() as temp_dir:
                with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', dir=temp_dir, delete=False) as f:
                    f.write(client_cert_chain_pem)
                    client_cert_path = f.name

                with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', dir=temp_dir, delete=False) as f:
                    f.write(client_key_pem)
                    client_key_path = f.name

                with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', dir=temp_dir, delete=False) as f:
                    f.write(server_cert_der)
                    server_cert_path = f.name

                client = Client(self.server_url)
                client.application_uri = application_uri
                client.secure_channel_timeout = getattr(settings, 'GDS_PUSH_CHANNEL_TIMEOUT_MS', 10000)
                client.session_timeout = getattr(settings, 'GDS_PUSH_SESSION_TIMEOUT_MS', 20000)

                await client.set_security(
                    policy,
                    certificate=client_cert_path,
                    private_key=client_key_path,
                    server_certificate=server_cert_path,
                    mode=ua.MessageSecurityMode.SignAndEncrypt,
                )

            if hasattr(self.device, 'opc_ua_gds_push_config'):
                opc_user = self.device.opc_ua_gds_push_config.opc_user
                opc_password = self.device.opc_ua_gds_push_config.opc_password
                if opc_user:
                    client.set_user(opc_user)
                    if opc_password:
                        client.set_password(opc_password)

        except Exception as e:
            msg = f'Failed to create secure client: {e}'
            raise GdsPushError(msg) from e
        else:
            return client

    def _create_insecure_client(self) -> Client:
        """Create OPC UA client without security for discovery.

        Returns:
            Configured OPC UA client.
        """
        client = Client(self.server_url)
        client.application_uri = 'urn:trustpoint:gds-push'
        client.secure_channel_timeout = getattr(settings, 'GDS_PUSH_CHANNEL_TIMEOUT_MS', 10000)
        client.session_timeout = getattr(settings, 'GDS_PUSH_SESSION_TIMEOUT_MS', 20000)
        return client

    async def _log_certificate_mismatch_details(self, client: Client) -> None:
        """Log essential information about certificate mismatch.

        Args:
            client: The OPC UA client that failed to connect.
        """
        try:
            expected_cert_der = await self._get_server_certificate()
            expected_cert = x509.load_der_x509_certificate(expected_cert_der)

            if self.server_truststore is None:
                self.logger.error('Server truststore is None')
                return

            self.logger.error(
                'Server certificate mismatch detected! Expected from truststore "%s"',
                self.server_truststore.unique_name,
            )

            self.logger.error(
                'Expected certificate:\n  Subject: %s\n  Issuer: %s\n  Serial: %s\n  SHA256: %s\n  Valid: %s to %s',
                expected_cert.subject.rfc4514_string(),
                expected_cert.issuer.rfc4514_string(),
                hex(expected_cert.serial_number),
                expected_cert.fingerprint(hashes.SHA256()).hex().upper(),
                expected_cert.not_valid_before_utc.isoformat(),
                expected_cert.not_valid_after_utc.isoformat(),
            )

            actual_cert_der = None
            if hasattr(client, 'uaclient') and hasattr(client.uaclient, 'security_policy'):
                security_policy = client.uaclient.security_policy
                if hasattr(security_policy, 'server_certificate') and security_policy.server_certificate:
                    actual_cert_der = security_policy.server_certificate

            if actual_cert_der:
                try:
                    actual_cert = x509.load_der_x509_certificate(actual_cert_der)
                    self.logger.error(
                        'Actual certificate presented by server:\n'
                        '  Subject: %s\n'
                        '  Issuer: %s\n'
                        '  Serial: %s\n'
                        '  SHA256: %s\n'
                        '  Valid: %s to %s',
                        actual_cert.subject.rfc4514_string(),
                        actual_cert.issuer.rfc4514_string(),
                        hex(actual_cert.serial_number),
                        actual_cert.fingerprint(hashes.SHA256()).hex().upper(),
                        actual_cert.not_valid_before_utc.isoformat(),
                        actual_cert.not_valid_after_utc.isoformat(),
                    )

                    if len(expected_cert_der) == len(actual_cert_der):
                        for i, (e_byte, a_byte) in enumerate(zip(expected_cert_der, actual_cert_der, strict=True)):
                            if e_byte != a_byte:
                                self.logger.error(
                                    'Certificates differ at byte %d: expected 0x%02X, got 0x%02X', i, e_byte, a_byte
                                )
                                break
                    else:
                        self.logger.error(
                            'Certificate lengths differ: expected %d bytes, got %d bytes',
                            len(expected_cert_der),
                            len(actual_cert_der),
                        )

                except Exception:
                    self.logger.exception('Could not parse actual server certificate')
            else:
                self.logger.error('No actual certificate captured from server')

        except Exception as log_error:  # noqa: BLE001
            self.logger.warning('Failed to log certificate mismatch details: %s', log_error)

    # ========================================================================
    # Public API - Discovery
    # ========================================================================

    async def discover_server(self) -> tuple[bool, str, dict[str, Any] | None]:
        """Discover OPC UA server information without authentication.

        Returns:
            Tuple of (success: bool, message: str, server_info: dict | None).
        """
        client = None
        try:
            client = self._create_insecure_client()

            server_info = await self._gather_server_info(client)

            if server_info and 'endpoints' in server_info:
                self.logger.info('Server discovery completed successfully')
                self.logger.info('Server name: %s', server_info.get('server_name', 'Unknown'))
                self.logger.info('Found %d endpoints:', len(server_info['endpoints']))

                # Analyze endpoints for logging and message building
                endpoint_analysis = self._analyze_endpoints(server_info['endpoints'])

                for i, endpoint in enumerate(server_info['endpoints'], 1):
                    policy_name = endpoint_analysis['policy_names'][i - 1]
                    self.logger.info(
                        '  Endpoint %d: %s | Security: %s/%s | Server Cert: %s',
                        i,
                        endpoint['url'],
                        policy_name,
                        endpoint['security_mode'].replace('MessageSecurityMode.', ''),
                        'Yes' if endpoint['has_server_cert'] else 'No',
                    )

                if endpoint_analysis['security_policies']:
                    policies_str = ', '.join(sorted(endpoint_analysis['security_policies']))
                    self.logger.info('Available security policies: %s', policies_str)

        except Exception as e:  # noqa: BLE001
            self.logger.warning('Failed to discover server: %s', e)
            return False, f'Discovery failed: {e}', None
        else:
            server_name = server_info.get('server_name', 'Unknown') if server_info else 'Unknown'
            endpoint_count = len(server_info.get('endpoints', [])) if server_info else 0

            # Reuse endpoint analysis if we have server_info
            endpoint_analysis = (
                self._analyze_endpoints(server_info.get('endpoints', []))
                if server_info
                else {
                    'security_policies': set(),
                    'has_secure_endpoints': False,
                    'has_insecure_endpoints': False,
                    'policy_names': [],
                }
            )

            message_parts = [f'Server "{server_name}" discovered with {endpoint_count} endpoint(s)']
            if endpoint_analysis['security_policies']:
                message_parts.append(f'Secure policies: {", ".join(sorted(endpoint_analysis["security_policies"]))}')
            if endpoint_analysis['has_secure_endpoints'] or endpoint_analysis['has_insecure_endpoints']:
                if endpoint_analysis['has_secure_endpoints'] and endpoint_analysis['has_insecure_endpoints']:
                    desc = 'mixed secure/insecure endpoints'
                else:
                    desc = f'{"secure" if endpoint_analysis["has_secure_endpoints"] else "insecure"} endpoints only'
                message_parts.append(f'({desc})')

            success_message = ' | '.join(message_parts)
            return True, success_message, server_info

    def _analyze_endpoints(self, endpoints: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze endpoints to extract security policies and endpoint types.

        Args:
            endpoints: List of endpoint dictionaries.

        Returns:
            Dictionary with analysis results.
        """
        security_policies = set()
        has_secure_endpoints = False
        has_insecure_endpoints = False
        policy_names = []

        for endpoint in endpoints:
            policy_uri = endpoint['security_policy']
            policy_name = next(
                (p for p in ['Basic256Sha256', 'Basic128Rsa15', 'Basic256', 'None'] if p in policy_uri),
                policy_uri.split('/')[-1] if '/' in policy_uri else policy_uri,
            )
            policy_names.append(policy_name)

            if 'None' in policy_uri:
                has_insecure_endpoints = True
            else:
                has_secure_endpoints = True

            for policy in ['Basic256Sha256', 'Basic128Rsa15', 'Basic256']:
                if policy in policy_uri:
                    security_policies.add(policy)

        return {
            'security_policies': security_policies,
            'has_secure_endpoints': has_secure_endpoints,
            'has_insecure_endpoints': has_insecure_endpoints,
            'policy_names': policy_names,
        }

    async def _gather_server_info(self, client: Client) -> dict[str, Any]:
        """Discover endpoints without creating or activating a session.

        Args:
            client: OPC UA discovery client; no session or user credentials required.

        Returns:
            Dictionary with server information.
        """
        server_info: dict[str, Any] = {}

        endpoints = await client.connect_and_get_server_endpoints()
        server_info['endpoints'] = []
        server_info['server_certificate'] = None
        server_info['server_certificate_available'] = False
        for endpoint in endpoints:
            certificate = endpoint.ServerCertificate
            has_certificate = isinstance(certificate, (bytes, bytearray)) and bool(certificate)
            if has_certificate:
                try:
                    certificate = self._first_der_certificate(bytes(certificate))
                except GdsPushError:
                    has_certificate = False
            endpoint_info = {
                'url': endpoint.EndpointUrl,
                'security_policy': endpoint.SecurityPolicyUri,
                'security_mode': str(endpoint.SecurityMode),
                'has_server_cert': has_certificate,
            }
            server_info['endpoints'].append(endpoint_info)
            if has_certificate and not server_info['server_certificate_available']:
                server_info['server_certificate'] = base64.b64encode(certificate).decode('ascii')
                server_info['server_certificate_available'] = True

        server_info['server_name'] = (endpoints[0].Server.ApplicationName.Text or 'Unknown') if endpoints else 'Unknown'

        return server_info

    # ========================================================================
    # Public API - Update TrustList
    # ========================================================================

    async def update_trustlist(self) -> tuple[bool, str]:  # noqa: C901
        """Update server trustlist with CA chain and CRLs.

        Implements OPC UA Part 12 Section 7.7.3 UpdateTrustList workflow.

        Returns:
            Tuple of (success: bool, message: str).
        """
        self._apply_changes_attempted = False
        client = None
        try:
            trustlist = await self._build_trustlist_for_server()

            client = await self._create_secure_client()

            try:
                async with client:
                    await self._read_server_capabilities(client)
                    self._apply_changes_required = False
                    trustlist_nodes = await self._discover_trustlist_nodes(client)
                    if not trustlist_nodes:
                        return False, 'No TrustList nodes found on server'

                    rejected = await self._read_rejected_certificates(client)
                    if rejected:
                        self.logger.warning(
                            'Server reports %d rejected certificate(s); review them before trusting',
                            len(rejected),
                        )

                    success_count = 0
                    messages = []

                    for node_info in trustlist_nodes:
                        group_name = node_info['group_name']
                        trustlist_node = node_info['trustlist_node']

                        success = await self._update_single_trustlist(trustlist_node, trustlist, defer_apply=True)

                        if success:
                            success_count += 1
                            messages.append(f'✓ {group_name}')
                        else:
                            messages.append(f'✗ {group_name}')

                    if success_count == len(trustlist_nodes) and self._apply_changes_required:
                        await self._apply_changes(client)
                    elif success_count != len(trustlist_nodes):
                        await self._cancel_changes(client)

            except Exception:
                app_uri = 'unknown'
                with contextlib.suppress(Exception):
                    if self.domain_credential and self.domain_credential.credential.certificate:
                        cert = self.domain_credential.credential.certificate.get_certificate_serializer().as_crypto()
                        app_uri = self._extract_application_uri(cert)

                self.logger.exception(
                    'Connection failed.\n'
                    'Common causes:\n'
                    '  - Server does not trust the client certificate CA chain\n'
                    '  - Application URI mismatch between certificate and server expectation\n'
                    '  - Server certificate has changed (update truststore)\n'
                    '  - Wrong security policy or mode\n'
                    '  - Server not configured for GDS Push\n'
                    '\n'
                    'Server-side checks needed:\n'
                    '  1. Verify ALL CA certificates from the chain are in server trust store\n'
                    '  2. Check server logs for specific rejection reason\n'
                    '  3. Verify Application URI "%s" is allowed by server\n'
                    '  4. Ensure server accepts Basic256Sha256 security policy\n'
                    '  5. Check if server requires the client cert to be pre-registered',
                    app_uri,
                )
                raise

            if success_count == len(trustlist_nodes):
                await self._record_managed_trustlist(trustlist)
                rejected_note = f'; {len(rejected)} rejected certificate(s) on server' if rejected else ''
                verified, verification_error = await self._verify_server_connection()
                verification_note = (
                    '; reconnect verified' if verified else f'; reconnect verification failed: {verification_error}'
                )
                msg = (
                    f'Successfully updated {success_count}/{len(trustlist_nodes)} trustlist(s): '
                    f'{", ".join(messages)}{rejected_note}{verification_note}'
                )
                return True, msg

            msg = (
                f'Failed to update {len(trustlist_nodes) - success_count}/{len(trustlist_nodes)} '
                f'trustlist(s): {", ".join(messages)}'
            )
            return False, msg

        except Exception as e:
            self.logger.exception('Failed to update trustlist')
            return False, self._status_error(e, 'Trustlist update')
        else:
            return False, 'Failed to update any trustlist'

    @staticmethod
    def _node_id_int(node_id: Any) -> int | None:
        """Return the numeric identifier of a namespace-0 NodeId, or None for anything else."""
        if isinstance(node_id, ua.NodeId) and node_id.NamespaceIndex == 0 and isinstance(node_id.Identifier, int):
            return node_id.Identifier
        return None

    def _is_application_group(
        self,
        group_name: str,
        purpose: ua.NodeId | None,
        certificate_types: list[ua.NodeId],
    ) -> bool:
        """Decide from Purpose/CertificateTypes whether a group holds application certificates."""
        purpose_id = self._node_id_int(purpose)
        if purpose_id in CertificateTypes.APPLICATION_TYPE_IDS:
            return True
        if purpose_id in CertificateTypes.NON_APPLICATION_PURPOSE_IDS:
            return False

        type_ids = {type_id for node_id in certificate_types if (type_id := self._node_id_int(node_id)) is not None}
        if type_ids:
            return bool(type_ids & CertificateTypes.APPLICATION_TYPE_IDS)

        # Some servers expose neither property value. Keep targeting custom groups, but never
        # the well-known HTTPS/TLS/UserToken groups.
        name = group_name.lower()
        return not any(marker in name for marker in ('https', 'tls', 'usertoken'))

    def _select_application_certificate_type(
        self,
        certificate_types: list[ua.NodeId],
    ) -> ua.NodeId | None:
        """Pick a permitted application CertificateType, or None when the group has none."""
        available = {type_id for node_id in certificate_types if (type_id := self._node_id_int(node_id)) is not None}
        if not available:
            return CertificateTypes.APPLICATION_CERTIFICATE
        for preferred_type_id in CertificateTypes.PREFERRED_APPLICATION_TYPE_IDS:
            if preferred_type_id in available:
                return ua.NodeId.from_string(f'ns=0;i={preferred_type_id}')
        return None

    async def _read_group_properties(self, group_node: Node) -> tuple[ua.NodeId | None, list[ua.NodeId]]:
        """Read the optional Purpose and the mandatory CertificateTypes properties."""
        purpose: ua.NodeId | None = None
        certificate_types: list[ua.NodeId] = []

        try:
            value = await (await group_node.get_child('Purpose')).read_value()
        except Exception:  # noqa: BLE001
            self.logger.debug('Certificate group has no readable Purpose')
        else:
            if isinstance(value, ua.NodeId):
                purpose = value

        try:
            value = await (await group_node.get_child('CertificateTypes')).read_value()
        except Exception:  # noqa: BLE001
            self.logger.debug('Certificate group has no readable CertificateTypes')
        else:
            if isinstance(value, (list, tuple)):
                certificate_types = [node_id for node_id in value if isinstance(node_id, ua.NodeId)]
            elif isinstance(value, ua.NodeId):
                certificate_types = [value]

        return purpose, certificate_types

    async def _discover_trustlist_nodes(self, client: Client) -> list[dict[str, Any]]:
        """Discover TrustLists of application certificate groups on the server."""
        trustlist_nodes = []

        for group in await self._discover_certificate_groups(client):
            try:
                trustlist_node = await group['group_node'].get_child('TrustList')
            except Exception as e:  # noqa: BLE001
                self.logger.warning('Failed to get TrustList for group %s: %s', group['name'], e)
                continue

            trustlist_nodes.append(
                {
                    'group_name': group['name'],
                    'group_node': group['group_node'],
                    'trustlist_node': trustlist_node,
                }
            )

        return trustlist_nodes

    _STATUS_HINTS: ClassVar[dict[int, str]] = {
        StatusCodes.BadUserAccessDenied: 'the identity lacks the required SecurityAdmin/certificate-management role',
        StatusCodes.BadIdentityTokenInvalid: 'the configured OPC UA user token is invalid',
        StatusCodes.BadIdentityTokenRejected: 'the server rejected the configured OPC UA user token',
        StatusCodes.BadUserSignatureInvalid: (
            'the client certificate signature was rejected; check the key match and clock'
        ),
        StatusCodes.BadSecurityPolicyRejected: 'the server rejected the negotiated security policy',
        StatusCodes.BadSecurityModeInsufficient: 'the channel is not encrypted/authenticated; use SignAndEncrypt',
        StatusCodes.BadCertificateUntrusted: 'the server does not trust the client certificate chain',
        StatusCodes.BadCertificateInvalid: 'the server rejected the certificate as invalid',
        StatusCodes.BadCertificateRevocationUnknown: 'the server cannot determine revocation; provide the CRL',
        StatusCodes.BadCertificateHostNameInvalid: 'the certificate lacks the host name/IP used to connect',
        StatusCodes.BadCertificateUriInvalid: 'the certificate ApplicationUri does not match the server',
        StatusCodes.BadCertificateUseNotAllowed: 'the certificate key usage/extended key usage is not suitable',
        StatusCodes.BadApplicationSignatureInvalid: 'the application signature or certificate chain was rejected',
        StatusCodes.BadSecurityChecksFailed: (
            'the certificate failed the server security checks (check clock skew, signature chain, '
            'issuer trust and ApplicationUri)'
        ),
        StatusCodes.BadNotSupported: 'the server does not support this key format or operation',
        StatusCodes.BadInvalidArgument: 'check the certificate group/type and request parameters',
        StatusCodes.BadCertificatePolicyCheckFailed: (
            'the server rejected the certificate against its configured key/signature policy'
        ),
        StatusCodes.BadTransactionPending: 'another session has an open transaction; retry later',
    }

    @classmethod
    def _status_error(cls, error: Exception, action: str) -> str:
        """Render an OPC UA status code with an actionable hint."""
        code = getattr(error, 'code', None)
        if code is None:
            return f'{action} failed: {error}'
        name, _doc = get_name_and_doc(code)
        hint = cls._STATUS_HINTS.get(code)
        hint_text = f' - {hint}' if hint else ''
        return f'{action} failed: {name} (0x{code:08X}){hint_text}: {error}'

    @staticmethod
    def _is_server_halted(error: Exception) -> bool:
        """Return True for the expected ApplyChanges response when the server restarts."""
        return getattr(error, 'code', None) == StatusCodes.BadServerHalted or 'BadServerHalted' in str(error)

    @staticmethod
    def _merge_byte_lists(existing: list[bytes], incoming: list[bytes]) -> list[bytes]:
        """Append incoming entries that are not already present, preserving order."""
        merged = list(existing)
        seen = set(merged)
        for item in incoming:
            if item not in seen:
                seen.add(item)
                merged.append(item)
        return merged

    @staticmethod
    def _crl_issuer_key(crl_der: bytes) -> bytes | None:
        """Return the DER-encoded issuer name of a CRL, or None when it cannot be parsed."""
        try:
            return x509.load_der_x509_crl(crl_der).issuer.public_bytes()
        except Exception:  # noqa: BLE001
            return None

    def _merge_crls(self, existing: list[bytes], incoming: list[bytes]) -> list[bytes]:
        """Keep CRLs for other issuers and replace CRLs from the incoming issuers."""
        replaced = {issuer for crl in incoming if (issuer := self._crl_issuer_key(crl)) is not None}
        kept = [crl for crl in existing if self._crl_issuer_key(crl) not in replaced]
        return self._merge_byte_lists(kept, incoming)

    def _merge_trustlists(
        self,
        current: ua.TrustListDataType,
        new: ua.TrustListDataType,
    ) -> ua.TrustListDataType:
        """Merge server-side trust entries with the Trustpoint-managed list."""
        merged = ua.TrustListDataType()
        merged.SpecifiedLists = int(ua.TrustListMasks.All)
        merged.TrustedCertificates = self._merge_byte_lists(
            current.TrustedCertificates or [], new.TrustedCertificates or []
        )
        merged.TrustedCrls = self._merge_crls(current.TrustedCrls or [], new.TrustedCrls or [])

        trusted = set(merged.TrustedCertificates)
        merged.IssuerCertificates = [
            cert
            for cert in self._merge_byte_lists(current.IssuerCertificates or [], new.IssuerCertificates or [])
            if cert not in trusted
        ]
        merged.IssuerCrls = self._merge_crls(current.IssuerCrls or [], new.IssuerCrls or [])
        return merged

    def _validate_trustlist_limits(self, trustlist: ua.TrustListDataType, serialized_size: int = 0) -> None:
        """Reject a trust list that exceeds configured or server-advertised limits."""
        device = getattr(self, 'device', None)
        config = getattr(device, 'opc_ua_gds_push_config', None) if device is not None else None
        max_entries = getattr(config, 'opc_gds_push_max_trustlist_entries', 0) or 0
        max_element_size = getattr(config, 'opc_gds_push_max_trustlist_element_size', 0) or 0
        capabilities = getattr(self, '_capabilities', {}) or {}
        max_total_size = capabilities.get('MaxTrustListSize', 0) or 0
        if not max_entries and not max_element_size and not max_total_size:
            return

        # Count unique DER objects: a certificate shared between lists consumes one slot.
        entries = {
            *trustlist.TrustedCertificates,
            *trustlist.TrustedCrls,
            *trustlist.IssuerCertificates,
            *trustlist.IssuerCrls,
        }
        if max_entries and len(entries) > max_entries:
            msg = (
                f'TrustList has {len(entries)} unique entries, exceeding the device limit of {max_entries}. '
                'Reduce the CA chain/CRLs or configure a device with more capacity.'
            )
            self._raise_gds_push_error(msg)

        if max_element_size:
            oversized = next((entry for entry in entries if len(entry) > max_element_size), None)
            if oversized is not None:
                msg = (
                    f'TrustList entry of {len(oversized)} bytes exceeds the device element limit '
                    f'of {max_element_size} bytes.'
                )
                self._raise_gds_push_error(msg)

        if max_total_size and serialized_size > max_total_size:
            msg = (
                f'TrustList is {serialized_size} bytes, exceeding the server MaxTrustListSize '
                f'of {max_total_size} bytes.'
            )
            self._raise_gds_push_error(msg)

    @staticmethod
    def _is_file_api_retryable(error: Exception) -> bool:
        """Return whether a TrustList file operation is worth retrying after a short backoff."""
        retryable = ('BadInvalidState', 'BadBusy', 'BadTimeout', 'BadTransactionPending', 'BadCommunicationError')
        return any(name in str(error) for name in retryable)

    async def _read_trustlist(self, trustlist_node: Node) -> ua.TrustListDataType | None:
        """Read the server's current TrustList, returning None when it cannot be read."""
        for attempt in range(3):
            file_handle = None
            try:
                open_method = await trustlist_node.get_child('Open')
                mode = ua.Variant(int(ua.OpenFileMode.Read), ua.VariantType.Byte)
                file_handle = await trustlist_node.call_method(open_method.nodeid, mode)

                read_method = await trustlist_node.get_child('Read')
                chunks = []
                while True:
                    chunk = await trustlist_node.call_method(read_method.nodeid, file_handle, 8192)
                    if not chunk:
                        break
                    chunks.append(bytes(chunk))

                if not chunks:
                    return None
                return struct_from_binary(ua.TrustListDataType, io.BytesIO(b''.join(chunks)))
            except Exception as e:  # noqa: BLE001
                if attempt < 2 and self._is_file_api_retryable(e):  # noqa: PLR2004
                    self.logger.warning('TrustList read busy (attempt %d/3); backing off: %s', attempt + 1, e)
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                self.logger.warning('Could not read the current TrustList; replacing it: %s', e)
                return None
            finally:
                if file_handle is not None:
                    with contextlib.suppress(Exception):
                        close_method = await trustlist_node.get_child('Close')
                        await trustlist_node.call_method(close_method.nodeid, file_handle)
        return None

    async def verify_connection(self) -> tuple[bool, str]:
        """Public reconnect check used to validate a replacement client identity."""
        return await self._verify_server_connection()

    async def _verify_server_connection(self) -> tuple[bool, str]:
        """Reconnect with the current truststore to verify the applied identity."""
        try:
            client = await self._create_secure_client()
            async with client:
                pass
        except Exception as e:  # noqa: BLE001
            return False, str(e)
        return True, ''

    async def _read_server_capabilities(self, client: Client) -> dict[str, Any]:
        """Read the ServerConfiguration capabilities relevant to push management."""
        capabilities: dict[str, Any] = {}
        try:
            server_node = client.get_node('ns=0;i=2253')
            server_config = await server_node.get_child('ServerConfiguration')
        except Exception as e:  # noqa: BLE001
            self.logger.debug('Could not browse ServerConfiguration: %s', e)
            self._capabilities = capabilities
            return capabilities

        for name in (
            'MaxTrustListSize',
            'SupportedPrivateKeyFormats',
            'SupportsTransactions',
            'InApplicationSetup',
            'HasSecureElement',
            'ServerCapabilities',
        ):
            try:
                value = await (await server_config.get_child(name)).read_value()
            except Exception as e:  # noqa: BLE001
                self.logger.debug('ServerConfiguration.%s unavailable: %s', name, e)
                continue
            capabilities[name] = value

        try:
            capabilities['MaxByteStringLength'] = await client.get_node('ns=0;i=12911').read_value()
        except Exception as e:  # noqa: BLE001
            self.logger.debug('Server MaxByteStringLength unavailable: %s', e)

        self._capabilities = capabilities
        if capabilities:
            self.logger.info('Server capabilities: %s', capabilities)
        if capabilities.get('InApplicationSetup'):
            self.logger.warning(
                'Server reports InApplicationSetup=true; it may trust clients more permissively until setup completes'
            )
        if capabilities.get('HasSecureElement'):
            self.logger.info('Server uses a secure element or hardware-backed private keys')
        return capabilities

    async def _read_group_certificates(self, client: Client, certificate_group_id: ua.NodeId) -> dict[ua.NodeId, bytes]:
        """Return the currently assigned certificates of a group (type -> DER)."""
        try:
            server_node = client.get_node('ns=0;i=2253')
            server_config = await server_node.get_child('ServerConfiguration')
            method = await server_config.get_child('GetCertificates')
            result = await server_config.call_method(method.nodeid, certificate_group_id)
        except Exception as e:  # noqa: BLE001
            self.logger.debug('GetCertificates unavailable for %s: %s', certificate_group_id, e)
            return {}

        if not isinstance(result, (list, tuple)) or len(result) < 2:  # noqa: PLR2004
            return {}
        type_ids, certificates = result[0], result[1]
        if not isinstance(type_ids, (list, tuple)) or not isinstance(certificates, (list, tuple)):
            return {}
        return {
            type_id: bytes(certificate)
            for type_id, certificate in zip(type_ids, certificates, strict=False)
            if isinstance(type_id, ua.NodeId) and isinstance(certificate, (bytes, bytearray))
        }

    async def _read_rejected_certificates(self, client: Client) -> list[bytes]:
        """Read the server's rejected-certificate list, if available."""
        try:
            server_node = client.get_node('ns=0;i=2253')
            server_config = await server_node.get_child('ServerConfiguration')
            method = await server_config.get_child('GetRejectedList')
            result = await server_config.call_method(method.nodeid)
        except Exception as e:  # noqa: BLE001
            self.logger.debug('GetRejectedList unavailable: %s', e)
            return []
        if not isinstance(result, (list, tuple)):
            return []
        return [bytes(cert) for cert in result if isinstance(cert, (bytes, bytearray))]

    def _supports_transactions(self) -> bool:
        """Return whether the server applies updates through an explicit transaction."""
        return bool((getattr(self, '_capabilities', {}) or {}).get('SupportsTransactions', True))

    async def _cancel_changes(self, client: Client) -> None:
        """Discard any pending transaction changes."""
        if not self._supports_transactions():
            self.logger.info('Server does not support transactions; no pending changes to cancel')
            return
        try:
            server_node = client.get_node('ns=0;i=2253')
            server_config = await server_node.get_child('ServerConfiguration')
            method = await server_config.get_child('CancelChanges')
            await server_config.call_method(method.nodeid)
        except Exception as e:  # noqa: BLE001
            self.logger.debug('Could not cancel pending changes: %s', e)

    async def _read_transaction_diagnostics(self, client: Client) -> str:
        """Format the server's TransactionDiagnostics for error reporting."""
        try:
            server_node = client.get_node('ns=0;i=2253')
            server_config = await server_node.get_child('ServerConfiguration')
            diagnostics = await server_config.get_child('TransactionDiagnostics')
            parts = []
            for name in (
                'Result',
                'StartTime',
                'EndTime',
                'AffectedTrustLists',
                'AffectedCertificateGroups',
                'Errors',
            ):
                try:
                    value = await (await diagnostics.get_child(name)).read_value()
                except Exception as e:  # noqa: BLE001
                    self.logger.debug('TransactionDiagnostics.%s unavailable: %s', name, e)
                    continue
                parts.append(f'{name}={value!r}')
            return ', '.join(parts)
        except Exception as e:  # noqa: BLE001
            self.logger.debug('TransactionDiagnostics unavailable: %s', e)
            return ''

    async def _apply_changes(self, client: Client) -> None:
        """Apply the pending transaction once for the current workflow."""
        if not self._supports_transactions():
            self.logger.info('Server does not support transactions; updates apply immediately')
            return
        server_node = client.get_node('ns=0;i=2253')
        server_config = await server_node.get_child('ServerConfiguration')
        method = await server_config.get_child('ApplyChanges')
        self._apply_changes_attempted = True
        try:
            await server_config.call_method(method.nodeid)
        except Exception as e:
            if self._is_server_halted(e):
                self.logger.info('Server halted to apply changes; reconnect required')
                return
            diagnostics = await self._read_transaction_diagnostics(client)
            message = f'ApplyChanges failed: {e}'
            if diagnostics:
                message = f'{message}; transaction diagnostics: {diagnostics}'
            raise GdsPushError(message) from e

    def _effective_chunk_size(self, requested: int) -> int:
        """Clamp the write block size to the server's MaxByteStringLength."""
        limit = (getattr(self, '_capabilities', {}) or {}).get('MaxByteStringLength', 0) or 0
        if limit > 0:
            return max(1, min(requested, int(limit)))
        return requested

    @staticmethod
    def _trustlist_fingerprints(trustlist: ua.TrustListDataType) -> set[str]:
        """Return SHA-256 fingerprints for every element in a trust list."""
        return {
            hashlib.sha256(der).hexdigest()
            for attribute in ('TrustedCertificates', 'TrustedCrls', 'IssuerCertificates', 'IssuerCrls')
            for der in (getattr(trustlist, attribute, None) or [])
        }

    def _prune_stale_managed_entries(
        self,
        current: ua.TrustListDataType,
        desired: ua.TrustListDataType,
    ) -> ua.TrustListDataType:
        """Remove previously managed entries that are no longer in the desired list."""
        config = getattr(self.device, 'opc_ua_gds_push_config', None)
        managed = set(getattr(config, 'opc_gds_push_managed_trustlist_fingerprints', None) or [])
        if not managed:
            return current
        stale = managed - self._trustlist_fingerprints(desired)
        if not stale:
            return current

        pruned = ua.TrustListDataType()
        pruned.SpecifiedLists = current.SpecifiedLists
        for attribute in ('TrustedCertificates', 'TrustedCrls', 'IssuerCertificates', 'IssuerCrls'):
            setattr(
                pruned,
                attribute,
                [
                    der
                    for der in (getattr(current, attribute, None) or [])
                    if hashlib.sha256(der).hexdigest() not in stale
                ],
            )
        return pruned

    def _effective_trustlist(
        self,
        current: ua.TrustListDataType | None,
        desired: ua.TrustListDataType,
    ) -> ua.TrustListDataType:
        """Merge the desired trust list with the current one after pruning stale managed entries."""
        if current is None:
            return desired
        return self._merge_trustlists(self._prune_stale_managed_entries(current, desired), desired)

    @staticmethod
    def _trustlists_equal(current: ua.TrustListDataType | None, desired: ua.TrustListDataType) -> bool:
        """Compare trust lists as sets, ignoring entry order."""
        if current is None:
            return False
        if int(getattr(current, 'SpecifiedLists', 0)) != int(getattr(desired, 'SpecifiedLists', 0)):
            return False
        return all(
            set(getattr(current, attribute, None) or []) == set(getattr(desired, attribute, None) or [])
            for attribute in ('TrustedCertificates', 'TrustedCrls', 'IssuerCertificates', 'IssuerCrls')
        )

    async def _record_managed_trustlist(self, desired: ua.TrustListDataType) -> None:
        """Remember which trust-list entries Trustpoint manages so removed CAs can be pruned."""
        config = getattr(self.device, 'opc_ua_gds_push_config', None)
        if config is None:
            return
        fingerprints = sorted(self._trustlist_fingerprints(desired))
        try:
            await sync_to_async(
                lambda: (
                    type(config)
                    .objects.filter(pk=config.pk)
                    .update(opc_gds_push_managed_trustlist_fingerprints=fingerprints)
                )
            )()
        except Exception as e:  # noqa: BLE001
            self.logger.warning('Could not persist managed trust-list fingerprints: %s', e)

    async def _update_single_trustlist(
        self,
        trustlist_node: Node,
        trustlist_data: ua.TrustListDataType,
        max_chunk_size: int = 1024,
        *,
        defer_apply: bool = False,
    ) -> bool:
        """Update a single TrustList node.

        Args:
            trustlist_node: The TrustList node to update.
            trustlist_data: TrustListDataType containing certificates and CRLs.
            max_chunk_size: Maximum size of each write chunk.
            defer_apply: Mark the transaction for a single ApplyChanges by the caller.

        Returns:
            True if successful, False otherwise.
        """
        current_trustlist = await self._read_trustlist(trustlist_node)
        effective_trustlist = self._effective_trustlist(current_trustlist, trustlist_data)
        return await self._write_trustlist(trustlist_node, effective_trustlist, max_chunk_size, defer_apply=defer_apply)

    async def _write_trustlist(
        self,
        trustlist_node: Node,
        effective_trustlist: ua.TrustListDataType,
        max_chunk_size: int = 1024,
        *,
        defer_apply: bool = False,
    ) -> bool:
        """Write a prepared TrustList and optionally defer ApplyChanges."""
        try:
            serialized_trustlist = struct_to_binary(effective_trustlist)
            self._validate_trustlist_limits(effective_trustlist, serialized_size=len(serialized_trustlist))
            max_chunk_size = self._effective_chunk_size(max_chunk_size)

            # Step 1: Open
            mode = ua.Variant(int(ua.OpenFileMode.Write | ua.OpenFileMode.EraseExisting), ua.VariantType.Byte)
            open_method = await trustlist_node.get_child('Open')
            file_handle = await trustlist_node.call_method(open_method.nodeid, mode)
            self.logger.debug('Opened TrustList, handle: %s', file_handle)

            # Step 2: Write in chunks
            write_method = await trustlist_node.get_child('Write')
            offset = 0
            chunk_count = 0

            while offset < len(serialized_trustlist):
                chunk = serialized_trustlist[offset : offset + max_chunk_size]
                await trustlist_node.call_method(write_method.nodeid, file_handle, chunk)
                offset += len(chunk)
                chunk_count += 1

            self.logger.debug('Wrote %d bytes in %d chunks', len(serialized_trustlist), chunk_count)

            # Step 3: CloseAndUpdate
            close_and_update_method = await trustlist_node.get_child('CloseAndUpdate')
            apply_changes_required = await trustlist_node.call_method(close_and_update_method.nodeid, file_handle)
            self.logger.debug('Closed TrustList, ApplyChanges required: %s', apply_changes_required)

            # Step 4: ApplyChanges if required
            if apply_changes_required:
                if defer_apply:
                    self._apply_changes_required = True
                else:
                    server_config_node = trustlist_node
                    for _ in range(3):
                        parent = await server_config_node.get_parent()
                        if parent is None:
                            msg = 'TrustList node is missing its ServerConfiguration parent.'
                            self._raise_gds_push_error(msg)
                        server_config_node = parent

                    apply_changes = await server_config_node.get_child('ApplyChanges')
                    try:
                        await server_config_node.call_method(apply_changes.nodeid)
                    except Exception as e:
                        if not self._is_server_halted(e):
                            raise
                        self.logger.info('Server halted to apply TrustList changes; reconnect required')

        except Exception:
            self.logger.exception('Failed to update trustlist')
            return False
        else:
            return True

    # ========================================================================
    # Public API - Update Server Certificate
    # ========================================================================

    async def update_server_certificate(self) -> tuple[bool, str, bytes | None]:  # noqa: C901, PLR0912
        """Update server certificate using CSR-based workflow.

        Implements OPC UA Part 12 Section 7.7.4 UpdateCertificate workflow.

        Returns:
            Tuple of (success: bool, message: str, certificate: bytes | None).
        """
        self._apply_changes_attempted = False
        client = None
        try:
            client = await self._create_secure_client()

            try:
                async with client:
                    await self._read_server_capabilities(client)
                    self._apply_changes_required = False
                    cert_groups = await self._discover_certificate_groups(client)
                    if not cert_groups:
                        return False, 'No certificate groups found on server', None

                    success_count = 0
                    messages = []
                    issued_cert = None
                    issuer_chain = None
                    config = getattr(self.device, 'opc_ua_gds_push_config', None)
                    regenerate_private_key = bool(getattr(config, 'opc_gds_push_regenerate_server_key', False))

                    for group in cert_groups:
                        group_name = group['name']

                        success, cert_bytes, chain_bytes = await self._update_single_certificate(
                            client=client,
                            certificate_group_id=group['node_id'],
                            certificate_type_id=group.get('certificate_type_id'),
                            regenerate_private_key=regenerate_private_key,
                            defer_apply=True,
                        )

                        if success:
                            success_count += 1
                            messages.append(f'✓ {group_name}')
                            if not issued_cert:
                                issued_cert = cert_bytes
                                issuer_chain = chain_bytes
                        else:
                            messages.append(f'✗ {group_name}')

                    if success_count == len(cert_groups) and self._apply_changes_required:
                        await self._apply_changes(client)
                    elif success_count != len(cert_groups):
                        await self._cancel_changes(client)

            except Exception as connect_error:
                if 'certificate mismatch' in str(connect_error).lower():
                    await self._log_certificate_mismatch_details(client)
                    self.logger.exception('Certificate mismatch detected - server truststore may need updating')
                raise

            if success_count == len(cert_groups):
                if issued_cert and issuer_chain:
                    await self._update_truststore_with_new_certificate(issued_cert, issuer_chain)

                verified, verification_error = await self._verify_server_connection()
                verification_note = (
                    '; reconnect verified' if verified else f'; reconnect verification failed: {verification_error}'
                )
                msg = (
                    f'Successfully updated {success_count}/{len(cert_groups)} certificate(s): '
                    f'{", ".join(messages)}{verification_note}'
                )
                return True, msg, issued_cert

            if success_count:
                msg = f'Updated only {success_count}/{len(cert_groups)} certificate(s): {", ".join(messages)}'
                return False, msg, None

        except Exception as e:
            self.logger.exception('Failed to update server certificate')
            return False, self._status_error(e, 'Server certificate update'), None
        else:
            return False, 'Failed to update any certificate', None

    async def update_trustlist_and_certificate(self) -> tuple[bool, str, bytes | None]:  # noqa: C901
        """Apply the trust list and server certificate in one transaction (Section 7.7.2)."""
        issued_cert: bytes | None = None
        issuer_chain: list[bytes] | None = None
        messages: list[str] = []
        self._apply_changes_attempted = False

        try:
            client = await self._create_secure_client()
            async with client:
                await self._read_server_capabilities(client)
                self._apply_changes_required = False

                trustlist_nodes = await self._discover_trustlist_nodes(client)
                if not trustlist_nodes:
                    return False, 'No TrustList nodes found on server', None
                cert_groups = await self._discover_certificate_groups(client)
                if not cert_groups:
                    return False, 'No certificate groups found on server', None

                trustlist = await self._build_trustlist_for_server()
                rejected = await self._read_rejected_certificates(client)

                trustlist_success = 0
                for node_info in trustlist_nodes:
                    group_name = node_info['group_name']
                    success = await self._update_single_trustlist(
                        node_info['trustlist_node'], trustlist, defer_apply=True
                    )
                    trustlist_success += int(success)
                    messages.append(f'{"✓" if success else "✗"} trustlist {group_name}')
                if trustlist_success != len(trustlist_nodes):
                    await self._cancel_changes(client)
                    return False, f'Trustlist update failed before certificate update: {", ".join(messages)}', None

                config = getattr(self.device, 'opc_ua_gds_push_config', None)
                regenerate_private_key = bool(getattr(config, 'opc_gds_push_regenerate_server_key', False))

                certificate_success = 0
                for group in cert_groups:
                    group_name = group['name']
                    success, cert_bytes, chain_bytes = await self._update_single_certificate(
                        client=client,
                        certificate_group_id=group['node_id'],
                        certificate_type_id=group.get('certificate_type_id'),
                        regenerate_private_key=regenerate_private_key,
                        defer_apply=True,
                    )
                    certificate_success += int(success)
                    messages.append(f'{"✓" if success else "✗"} certificate {group_name}')
                    if success and issued_cert is None:
                        issued_cert = cert_bytes
                        issuer_chain = chain_bytes
                if certificate_success != len(cert_groups):
                    await self._cancel_changes(client)
                    return False, f'Certificate update failed: {", ".join(messages)}', None

                if self._apply_changes_required:
                    await self._apply_changes(client)
        except Exception as e:
            self.logger.exception('Failed to update trustlist and certificate')
            return False, self._status_error(e, 'Combined GDS Push update'), None

        await self._record_managed_trustlist(trustlist)
        if issued_cert and issuer_chain:
            await self._update_truststore_with_new_certificate(issued_cert, issuer_chain)

        verified, verification_error = await self._verify_server_connection()
        verification_note = (
            '; reconnect verified' if verified else f'; reconnect verification failed: {verification_error}'
        )
        rejected_note = f'; {len(rejected)} rejected certificate(s) on server' if rejected else ''
        return (
            True,
            f'Successfully updated trustlist and certificate: {", ".join(messages)}{rejected_note}{verification_note}',
            issued_cert,
        )

    def _certificate_group_due(
        self,
        group: dict[str, Any],
        threshold_days: int,
        now: dt.datetime,
    ) -> bool:
        """Decide from the device's actual certificate whether this group needs renewal."""
        current = group.get('current_certificates') or {}
        if not current:
            return False
        type_id = group.get('certificate_type_id')
        certificate_der = current.get(type_id) if type_id is not None else None
        if certificate_der is None:
            certificate_der = next(iter(current.values()))
        try:
            certificate = x509.load_der_x509_certificate(bytes(certificate_der))
        except Exception as e:  # noqa: BLE001
            self.logger.warning('Could not parse the current certificate for group %s: %s', group.get('name'), e)
            return True
        if threshold_days <= 0:
            return True
        return certificate.not_valid_after_utc <= now + dt.timedelta(days=threshold_days)

    async def reconcile(self) -> tuple[bool, str, bytes | None]:  # noqa: C901, PLR0911, PLR0912, PLR0915
        """Reconcile the device trust lists and certificate groups with the desired state.

        The periodic task uses this as its single entry point. Trust-list changes and
        certificate renewals are evaluated independently from the device's actual
        inventory; unchanged trust lists are not written and no ApplyChanges is sent
        when neither side needs an update.
        """
        self._apply_changes_attempted = False
        config = getattr(self.device, 'opc_ua_gds_push_config', None)
        threshold_days = getattr(config, 'opc_gds_push_renewal_threshold_days', 30) or 0
        now = dt.datetime.now(dt.UTC)
        issued_cert: bytes | None = None
        issuer_chain: list[bytes] | None = None
        messages: list[str] = []

        try:
            client = await self._create_secure_client()
            async with client:
                await self._read_server_capabilities(client)
                self._apply_changes_required = False

                cert_groups = await self._discover_certificate_groups(client)
                if not cert_groups:
                    return False, 'No certificate groups found on server', None
                trustlist_nodes = await self._discover_trustlist_nodes(client)

                desired: ua.TrustListDataType | None = None
                trustlist_writes: list[tuple[dict[str, Any], ua.TrustListDataType]] = []
                if trustlist_nodes:
                    desired = await self._build_trustlist_for_server()
                    for node_info in trustlist_nodes:
                        current = await self._read_trustlist(node_info['trustlist_node'])
                        effective = self._effective_trustlist(current, desired)
                        if not self._trustlists_equal(current, effective):
                            trustlist_writes.append((node_info, effective))

                due_groups = [group for group in cert_groups if self._certificate_group_due(group, threshold_days, now)]

                if not trustlist_writes and not due_groups:
                    if desired is not None:
                        await self._record_managed_trustlist(desired)
                    return True, 'No certificate or trust list update required', None

                if due_groups and not trustlist_nodes:
                    return (
                        False,
                        'No TrustList nodes found; cannot ensure issuer certificates and CRLs before renewal',
                        None,
                    )

                for node_info, effective in trustlist_writes:
                    group_name = node_info['group_name']
                    success = await self._write_trustlist(node_info['trustlist_node'], effective, defer_apply=True)
                    messages.append(f'{"✓" if success else "✗"} trustlist {group_name}')
                    if not success:
                        await self._cancel_changes(client)
                        return False, f'Trust list update failed: {", ".join(messages)}', None

                regenerate_private_key = bool(getattr(config, 'opc_gds_push_regenerate_server_key', False))
                for group in due_groups:
                    group_name = group['name']
                    success, cert_bytes, chain_bytes = await self._update_single_certificate(
                        client=client,
                        certificate_group_id=group['node_id'],
                        certificate_type_id=group.get('certificate_type_id'),
                        regenerate_private_key=regenerate_private_key,
                        defer_apply=True,
                    )
                    messages.append(f'{"✓" if success else "✗"} certificate {group_name}')
                    if not success:
                        await self._cancel_changes(client)
                        return False, f'Certificate renewal failed: {", ".join(messages)}', None
                    if issued_cert is None:
                        issued_cert = cert_bytes
                        issuer_chain = chain_bytes

                if self._apply_changes_required:
                    await self._apply_changes(client)
                if desired is not None:
                    await self._record_managed_trustlist(desired)
        except Exception as e:
            self.logger.exception('GDS Push reconciliation failed')
            return False, self._status_error(e, 'GDS Push reconciliation'), None

        if issued_cert and issuer_chain:
            await self._update_truststore_with_new_certificate(issued_cert, issuer_chain)

        verified, verification_error = await self._verify_server_connection()
        verification_note = (
            '; reconnect verified' if verified else f'; reconnect verification failed: {verification_error}'
        )
        summary = ', '.join(messages) if messages else 'trust list and certificates already current'
        return True, f'Reconciliation complete: {summary}{verification_note}', issued_cert

    async def _discover_certificate_groups(self, client: Client) -> list[dict[str, Any]]:
        """Discover application certificate groups and the permitted certificate type.

        Only groups whose Purpose/CertificateTypes identify application certificates are
        returned (Section 7.7.2). HTTPS and UserToken groups are excluded so their trust
        lists and certificate slots are not overwritten.
        """
        groups = []

        try:
            server_node = client.get_node('ns=0;i=2253')
            server_config = await server_node.get_child('ServerConfiguration')
            cert_groups_node = await server_config.get_child('CertificateGroups')

            group_nodes = await cert_groups_node.get_children()

            for group_node in group_nodes:
                try:
                    name = await group_node.read_browse_name()
                    group_name = name.Name
                    purpose, certificate_types = await self._read_group_properties(group_node)

                    if not self._is_application_group(group_name, purpose, certificate_types):
                        self.logger.info('Skipping non-application certificate group: %s', group_name)
                        continue

                    certificate_type_id = self._select_application_certificate_type(certificate_types)
                    if certificate_type_id is None:
                        self.logger.warning('Certificate group %s permits no application certificate type', group_name)
                        continue

                    current_certificates = await self._read_group_certificates(client, group_node.nodeid)
                    current_type = next(
                        (type_id for type_id in certificate_types if type_id in current_certificates),
                        None,
                    )
                    if current_type is not None:
                        certificate_type_id = current_type

                    groups.append(
                        {
                            'name': group_name,
                            'node_id': group_node.nodeid,
                            'group_node': group_node,
                            'certificate_type_id': certificate_type_id,
                            'current_certificates': current_certificates,
                        }
                    )

                except Exception as e:  # noqa: BLE001
                    self.logger.warning('Failed to process group: %s', e)
                    continue

        except Exception:
            self.logger.exception('Failed to discover certificate groups')

        return groups

    @staticmethod
    def _describe_certificate(certificate_der: bytes) -> dict[str, Any]:
        """Return a JSON-safe summary of a DER certificate."""
        summary: dict[str, Any] = {'sha256': hashlib.sha256(certificate_der).hexdigest()}
        try:
            certificate = x509.load_der_x509_certificate(certificate_der)
        except Exception:  # noqa: BLE001
            return summary
        summary.update(
            {
                'subject': certificate.subject.rfc4514_string(),
                'issuer': certificate.issuer.rfc4514_string(),
                'serial': format(certificate.serial_number, 'x'),
                'not_after': certificate.not_valid_after_utc.isoformat(),
            }
        )
        return summary

    async def refresh_certificate_inventory(self) -> tuple[bool, str, dict[str, Any]]:
        """Read the server's certificate groups, trust lists and rejected certificates."""
        inventory: dict[str, Any] = {
            'certificate_groups': [],
            'trust_lists': [],
            'rejected': [],
            'capabilities': {},
        }
        try:
            client = await self._create_secure_client()
            async with client:
                capabilities = await self._read_server_capabilities(client)
                inventory['capabilities'] = {name: str(value) for name, value in capabilities.items()}

                for group in await self._discover_certificate_groups(client):
                    inventory['certificate_groups'].append(
                        {
                            'name': group['name'],
                            'certificate_type': str(group.get('certificate_type_id') or ''),
                            'certificates': [
                                {'type': str(type_id), **self._describe_certificate(der)}
                                for type_id, der in (group.get('current_certificates') or {}).items()
                            ],
                        }
                    )

                for node_info in await self._discover_trustlist_nodes(client):
                    trustlist = await self._read_trustlist(node_info['trustlist_node'])
                    inventory['trust_lists'].append(
                        {
                            'group': node_info['group_name'],
                            'certificates': (
                                len(trustlist.TrustedCertificates or []) + len(trustlist.IssuerCertificates or [])
                                if trustlist is not None
                                else 0
                            ),
                            'crls': (
                                len(trustlist.TrustedCrls or []) + len(trustlist.IssuerCrls or [])
                                if trustlist is not None
                                else 0
                            ),
                        }
                    )

                inventory['rejected'] = [
                    self._describe_certificate(der) for der in await self._read_rejected_certificates(client)
                ]
        except Exception as e:
            self.logger.exception('Failed to read certificate inventory')
            return False, self._status_error(e, 'Certificate inventory'), {}

        self.logger.info('Read certificate inventory from server')
        return True, 'Certificate inventory read from server', inventory

    async def _generate_server_key_and_csr(  # noqa: C901, PLR0912
        self, certificate_type_id: ua.NodeId
    ) -> tuple[bytes, Any]:
        """Generate a key and CSR locally when the server cannot generate a key."""
        type_identifier = certificate_type_id.Identifier if isinstance(certificate_type_id, ua.NodeId) else None
        key: Any
        if type_identifier in {
            CertificateTypes.ECC_APPLICATION_TYPE_ID,
            CertificateTypes.ECC_NIST_P256_TYPE_ID,
        }:
            key = ec.generate_private_key(ec.SECP256R1())
        elif type_identifier == CertificateTypes.ECC_NIST_P384_TYPE_ID:
            key = ec.generate_private_key(ec.SECP384R1())
        elif type_identifier == CertificateTypes.ECC_BRAINPOOL_P256_TYPE_ID:
            key = ec.generate_private_key(ec.BrainpoolP256R1())
        elif type_identifier == CertificateTypes.ECC_BRAINPOOL_P384_TYPE_ID:
            key = ec.generate_private_key(ec.BrainpoolP384R1())
        elif type_identifier in {
            CertificateTypes.ECC_CURVE25519_TYPE_ID,
            CertificateTypes.ECC_CURVE448_TYPE_ID,
        }:
            msg = 'Locally generated Curve25519/Curve448 keys are not supported for OPC UA certificates.'
            self._raise_gds_push_error(msg)
        else:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        common_name = self.device.common_name or 'trustpoint-managed-server'
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        application_uri = f'urn:trustpoint:opcua:{getattr(self.device, "rfc_4122_uuid", common_name)}'
        san_values: list[x509.GeneralName] = [x509.UniformResourceIdentifier(application_uri)]
        if self.device.ip_address:
            with contextlib.suppress(ValueError):
                san_values.append(x509.IPAddress(ipaddress.ip_address(self.device.ip_address)))
        if common_name:
            san_values.append(x509.DNSName(common_name))

        if self.server_truststore is not None:
            try:
                current = x509.load_der_x509_certificate(await self._get_server_certificate())
            except GdsPushError:
                current = None
            if current is not None:
                subject = current.subject
                try:
                    san = current.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                except x509.ExtensionNotFound:
                    pass
                else:
                    san_values = list(san)

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(x509.SubjectAlternativeName(san_values), critical=False)
            .sign(key, hashes.SHA256())
        )
        return csr.public_bytes(serialization.Encoding.DER), key

    def _encode_private_key(self, key: Any, certificate_der: bytes) -> tuple[str, bytes]:
        """Encode a generated private key in a format advertised by the server."""
        formats = {str(value).upper() for value in (self._capabilities.get('SupportedPrivateKeyFormats') or [])}
        if 'PFX' in formats:
            certificate = x509.load_der_x509_certificate(certificate_der)
            encoded = pkcs12.serialize_key_and_certificates(
                None,
                key,
                certificate,
                None,
                serialization.NoEncryption(),
            )
            return 'PFX', encoded
        if 'PEM' in formats:
            encoded = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            return 'PEM', encoded
        if 'PKCS8' in formats:
            encoded = key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            return 'PKCS8', base64.b64encode(encoded)
        msg = 'Server advertises no supported private key format (PEM, PFX or PKCS8).'
        raise GdsPushError(msg)

    async def _update_single_certificate(  # noqa: C901, PLR0912
        self,
        client: Client,
        certificate_group_id: ua.NodeId,
        certificate_type_id: ua.NodeId | None = None,
        *,
        regenerate_private_key: bool = False,
        defer_apply: bool = False,
    ) -> tuple[bool, bytes | None, list[bytes] | None]:
        """Update certificate for a single certificate group.

        Args:
            client: Connected OPC UA client.
            certificate_group_id: NodeId of the certificate group.
            certificate_type_id: NodeId of certificate type.
            regenerate_private_key: Ask the server for a new key pair instead of reusing its key.
            defer_apply: Mark the transaction for a single ApplyChanges by the caller.

        Returns:
            Tuple of (success: bool, certificate: bytes | None, issuer_chain: list[bytes] | None).
        """
        if certificate_type_id is None:
            certificate_type_id = CertificateTypes.APPLICATION_CERTIFICATE

        try:
            server_node = client.get_node('ns=0;i=2253')
            server_config = await server_node.get_child('ServerConfiguration')

            # Step 1: CreateSigningRequest
            create_signing_request = await server_config.get_child('CreateSigningRequest')

            # Section 7.10.10: the nonce is required only when a new key is generated.
            nonce = os.urandom(32) if regenerate_private_key else b''
            generated_key = None
            try:
                csr = await server_config.call_method(
                    create_signing_request.nodeid,
                    certificate_group_id,
                    certificate_type_id,
                    None,  # subjectName
                    regenerate_private_key,
                    nonce,
                )
            except Exception as e:
                if getattr(e, 'code', None) not in (
                    StatusCodes.BadNotSupported,
                    StatusCodes.BadInvalidState,
                ):
                    raise
                if not (self._capabilities.get('SupportedPrivateKeyFormats') or []):
                    raise
                self.logger.warning(
                    'Server cannot generate a private key; generating one in Trustpoint and uploading it'
                )
                csr, generated_key = await self._generate_server_key_and_csr(certificate_type_id)
            self.logger.info('CSR generated (%d bytes)', len(csr))

            # Step 2: Sign the CSR
            self.logger.info('Signing CSR with domain issuing CA')
            try:
                signed_cert, issuer_chain, _ = await self._sign_csr(
                    csr, expect_new_key=regenerate_private_key or generated_key is not None
                )
            except GdsPushError as e:
                if (
                    generated_key is not None
                    or not regenerate_private_key
                    or 'ignored RegeneratePrivateKey' not in str(e)
                    or not (self._capabilities.get('SupportedPrivateKeyFormats') or [])
                ):
                    raise
                self.logger.warning('Server ignored rollover; generating and uploading a new key')
                csr, generated_key = await self._generate_server_key_and_csr(certificate_type_id)
                signed_cert, issuer_chain, _ = await self._sign_csr(csr, expect_new_key=True)

            # Step 3: UpdateCertificate
            self.logger.info('Uploading signed certificate via UpdateCertificate')
            update_certificate = await server_config.get_child('UpdateCertificate')

            key_format = ''
            key_bytes = b''
            if generated_key is not None:
                key_format, key_bytes = self._encode_private_key(generated_key, signed_cert)

            apply_changes_required = await server_config.call_method(
                update_certificate.nodeid,
                certificate_group_id,
                certificate_type_id,
                signed_cert,
                issuer_chain,
                key_format,
                key_bytes,
            )
            self.logger.info('Certificate uploaded, ApplyChanges required: %s', apply_changes_required)

            # Step 4: ApplyChanges if required
            if apply_changes_required:
                if defer_apply:
                    self._apply_changes_required = True
                else:
                    apply_changes = await server_config.get_child('ApplyChanges')
                    try:
                        await server_config.call_method(apply_changes.nodeid)
                    except Exception as e:
                        if not self._is_server_halted(e):
                            raise
                        self.logger.info('Server halted to apply certificate changes; reconnect required')

        except Exception:
            self.logger.exception('Failed to update certificate')
            return False, None, None
        else:
            return True, signed_cert, issuer_chain

    def _raise_gds_push_error(self, msg: str) -> NoReturn:
        """Raise a GdsPushError with the given message."""
        raise GdsPushError(msg)

    async def _sign_csr(
        self, csr_der: bytes, *, expect_new_key: bool = False
    ) -> tuple[bytes, list[bytes], CertificateModel]:
        """Sign a Certificate Signing Request using the standardized certificate issuance workflow.

        This method uses the same CertificateIssueProcessor workflow as EST to ensure
        consistent certificate issuance across all protocols.

        Args:
            csr_der: DER-encoded CSR from OPC UA server.
            expect_new_key: Require the CSR to use a key different from the current certificate.

        Returns:
            Tuple of (signed certificate DER, issuer chain as list of DER certs, issued certificate model).

        Raises:
            GdsPushError: If signing fails.
        """
        try:
            csr = parse_csr(csr_der, encoding='der')

            self.logger.info('Signing CSR from OPC UA server: %s', csr.subject.rfc4514_string())

            device = await sync_to_async(lambda: self.device)()
            domain = await sync_to_async(lambda: device.domain)()

            context = await sync_to_async(BaseCertificateRequestContext)(
                device=device,
                domain=domain,
                cert_requested=csr,
                cert_profile_str='opc_ua',
                protocol='opc_gds_push',
                operation='update_certificate',
            )

            if not context.domain:
                msg = 'Device has no domain configured'
                self._raise_gds_push_error(msg)

            domain = context.domain

            certificate_profile_model = await sync_to_async(domain.get_allowed_cert_profile)('opc_ua')
            if not certificate_profile_model:
                msg = f'Certificate profile "opc_ua" not found or not allowed for domain "{domain.unique_name}"'
                self._raise_gds_push_error(msg)

            context.certificate_profile_model = certificate_profile_model

            await self._validate_csr_identity(csr, expect_new_key=expect_new_key)

            await sync_to_async(ProfileValidator.validate)(context)

            processor = CertificateIssueProcessor()
            await sync_to_async(processor.process_operation)(context)

            if context.issued_certificate is None:
                msg = 'Certificate issuance failed: No certificate was issued'
                self._raise_gds_push_error(msg)

            issued_cert = context.issued_certificate
            self._validate_issued_certificate_policy(issued_cert)

            cert_der = issued_cert.public_bytes(serialization.Encoding.DER)

            self.logger.info('Certificate issued successfully (%d bytes)', len(cert_der))

            ca_chain = await self._build_ca_chain()
            issuer_chain = []

            for ca in ca_chain:
                ca_cert_model = await sync_to_async(lambda ca=ca: ca.ca_certificate_model)()
                ca_cert = await sync_to_async(ca_cert_model.get_certificate_serializer().as_crypto)()
                issuer_chain.append(ca_cert.public_bytes(encoding=serialization.Encoding.DER))

            self.logger.info('Issuer chain includes %d CA certificate(s)', len(issuer_chain))

        except Exception as e:
            msg = f'Failed to sign CSR: {e}'
            raise GdsPushError(msg) from e
        else:
            return cert_der, issuer_chain, context.issued_certificate  # type: ignore[return-value]

    async def _update_truststore_with_new_certificate(
        self,
        server_cert_der: bytes,
        issuer_chain: list[bytes],
    ) -> None:
        """Update the server truststore with the newly issued certificate and CA chain.

        This ensures that the truststore contains the complete certificate chain
        (server certificate + CA certificates) that the OPC UA server will present
        during the TLS handshake.

        Args:
            server_cert_der: DER-encoded server certificate.
            issuer_chain: List of DER-encoded CA certificates.

        Raises:
            GdsPushError: If truststore update fails.
        """
        if self.server_truststore is None:
            msg = 'No server truststore configured'
            raise GdsPushError(msg)

        try:
            await sync_to_async(self._replace_truststore_certificates)(
                self.server_truststore, server_cert_der, issuer_chain
            )
        except Exception as e:
            msg = f'Failed to update truststore: {e}'
            raise GdsPushError(msg) from e

    @transaction.atomic
    def _replace_truststore_certificates(
        self,
        server_truststore: TruststoreModel,
        server_cert_der: bytes,
        issuer_chain: list[bytes],
    ) -> None:
        """Resolve every replacement before atomically revoking and replacing the old entries."""
        self.logger.info(
            'Updating truststore "%s" with new server certificate + %d CA cert(s)',
            server_truststore.unique_name,
            len(issuer_chain),
        )
        certificates = []
        for idx, certificate_der in enumerate([server_cert_der, *issuer_chain]):
            certificate = x509.load_der_x509_certificate(certificate_der)
            fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
            certificate_model = CertificateModel.get_cert_by_sha256_fingerprint(fingerprint)
            if certificate_model is None:
                label = 'Server' if idx == 0 else 'CA'
                msg = f'{label} certificate not found in database (fingerprint: {fingerprint})'
                self._raise_gds_push_error(msg)
            certificates.append(certificate_model)

        domain = self.device.domain
        if domain is None:
            msg = 'Device has no domain'
            self._raise_gds_push_error(msg)
        ca = domain.issuing_ca

        try:
            old_server_cert = server_truststore.truststoreordermodel_set.get(order=0).certificate
            revoked = revoke_certificate(
                old_server_cert,
                reason=RevokedCertificateModel.ReasonCode.SUPERSEDED,
                ca=ca,
            )
            if revoked:
                self.logger.info('Revoked old server certificate: %s', old_server_cert.common_name)
            else:
                self.logger.info('Old server certificate already revoked: %s', old_server_cert.common_name)
        except TruststoreOrderModel.DoesNotExist:
            self.logger.debug('No old server certificate found in truststore to revoke')

        server_truststore.truststoreordermodel_set.all().delete()
        for idx, certificate_model in enumerate(certificates):
            TruststoreOrderModel.objects.create(
                trust_store=server_truststore,
                certificate=certificate_model,
                order=idx,
            )
        self.logger.info(
            'Updated truststore "%s" with %d certificate(s)',
            server_truststore.unique_name,
            len(certificates),
        )
