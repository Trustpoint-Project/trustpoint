"""Service for OPC UA GDS Push operations."""

from __future__ import annotations

import contextlib
import datetime
import tempfile
from typing import TYPE_CHECKING, Any

from asgiref.sync import sync_to_async
from asyncua import Client, ua  # type: ignore[import-untyped]
from asyncua.crypto import security_policies  # type: ignore[import-untyped]
from asyncua.ua.ua_binary import struct_to_binary  # type: ignore[import-untyped]
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import KeyUsage
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID
from django.db import IntegrityError

from devices.models import IssuedCredentialModel
from pki.models import CertificateModel, TruststoreOrderModel
from pki.models.certificate import RevokedCertificateModel
from request.operation_processor import CertificateIssueProcessor
from request.profile_validator import ProfileValidator
from request.request_context import BaseCertificateRequestContext
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from devices.models import DeviceModel
    from pki.models import CaModel
    from pki.models.truststore import TruststoreModel

__all__ = ['GdsPushError', 'GdsPushService']


class GdsPushError(Exception):
    """Exception raised for GDS Push operation failures."""


class CertificateTypes:
    """OPC UA GDS Certificate Types (Section 7.8.4)."""

    APPLICATION_CERTIFICATE = ua.NodeId.from_string('ns=0;i=12557')
    HTTPS_CERTIFICATE = ua.NodeId.from_string('ns=0;i=12558')
    RSA_MIN_APPLICATION_CERTIFICATE = ua.NodeId.from_string('ns=0;i=12559')
    RSA_SHA256_APPLICATION_CERTIFICATE = ua.NodeId.from_string('ns=0;i=12560')
    ECC_NIST_P256_APPLICATION_CERTIFICATE = ua.NodeId.from_string('ns=0;i=23538')
    ECC_NIST_P384_APPLICATION_CERTIFICATE = ua.NodeId.from_string('ns=0;i=23539')
    ECC_BRAINPOOL_P256R1_APPLICATION_CERTIFICATE = ua.NodeId.from_string('ns=0;i=23540')
    ECC_BRAINPOOL_P384R1_APPLICATION_CERTIFICATE = ua.NodeId.from_string('ns=0;i=23541')


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
                   - Onboarding config with opc_trust_store (for secure operations)
            insecure: If True, skip authentication setup for discovery operations.

        Raises:
            GdsPushError: If device configuration is invalid.
        """
        self.device = device
        self._validate_device_config()

        self.server_url = f'opc.tcp://{device.ip_address}:{device.opc_server_port}'

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
        if not self.device.ip_address or not self.device.opc_server_port:
            msg = f'Device "{self.device.common_name}" must have IP address and OPC server port configured'
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
            device=self.device,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL
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
            Truststore from device's onboarding config.

        Raises:
            GdsPushError: If truststore not configured or empty.
        """
        if not self.device.onboarding_config:
            msg = f'Device "{self.device.common_name}" has no onboarding config'
            raise GdsPushError(msg)

        if not self.device.onboarding_config.opc_trust_store:
            msg = (
                f'Device "{self.device.common_name}" onboarding config has no OPC UA '
                f'server truststore (opc_trust_store) configured'
            )
            raise GdsPushError(msg)

        truststore = self.device.onboarding_config.opc_trust_store

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


    async def _build_trustlist_for_server(self) -> ua.TrustListDataType:
        """Build OPC UA TrustList to push to server.

        The TrustList tells the OPC UA server which CAs to trust for client
        certificate validation. It includes:
        - All CA certificates in the chain (issuing CA to root)
        - Valid CRLs from all CAs in the chain (mandatory)

        Returns:
            TrustListDataType ready to push to server.

        Raises:
            GdsPushError: If trustlist cannot be built, any CA is missing a CRL,
                         or any CRL is expired.
        """
        ca_chain = await self._build_ca_chain()

        trusted_certs = []
        trusted_crls = []
        issuer_certs = []
        issuer_crls = []

        for ca in ca_chain:
            ca_cert_model = await sync_to_async(lambda ca=ca: ca.ca_certificate_model)()

            ca_cert_crypto = await sync_to_async(ca_cert_model.get_certificate_serializer().as_crypto)()
            ca_cert_der = ca_cert_crypto.public_bytes(encoding=serialization.Encoding.DER)

            trusted_certs.append(ca_cert_der)
            issuer_certs.append(ca_cert_der)



            crl_pem = await sync_to_async(lambda ca=ca: ca.crl_pem)()
            if not crl_pem:
                msg = (
                    f'CA "{ca.unique_name}" has no CRL configured. '
                    f'CRL is mandatory for OPC UA GDS Push trustlist.'
                )
                raise GdsPushError(msg)

            try:
                crl_crypto = x509.load_pem_x509_crl(crl_pem.encode())
            except Exception as e:
                msg = f'Failed to load CRL for CA "{ca.unique_name}": {e}'
                raise GdsPushError(msg) from e

            now = datetime.datetime.now(tz=datetime.UTC)
            if crl_crypto.next_update_utc and crl_crypto.next_update_utc < now:
                msg = (
                    f'CRL for CA "{ca.unique_name}" has expired. '
                    f'Next update was: {crl_crypto.next_update_utc.isoformat()}, '
                    f'Current time: {now.isoformat()}'
                )
                raise GdsPushError(msg)

            crl_der = crl_crypto.public_bytes(encoding=serialization.Encoding.DER)

            trusted_crls.append(crl_der)
            issuer_crls.append(crl_der)



        trustlist = ua.TrustListDataType()
        trustlist.SpecifiedLists = ua.TrustListMasks.All
        trustlist.TrustedCertificates = trusted_certs
        trustlist.TrustedCrls = trusted_crls
        trustlist.IssuerCertificates = issuer_certs
        trustlist.IssuerCrls = issuer_crls

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
            encryption_algorithm=serialization.NoEncryption()
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
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_public_bytes = private_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
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

        now = datetime.datetime.now(tz=datetime.UTC)
        if cert.not_valid_before_utc > now:
            issues.append(f'Certificate not yet valid (valid from: {cert.not_valid_before_utc.isoformat()})')
        if cert.not_valid_after_utc < now:
            issues.append(f'Certificate expired (valid until: {cert.not_valid_after_utc.isoformat()})')

        try:
            key_usage_value = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            if isinstance(key_usage_value, KeyUsage):
                required_usages = {
                    'digital_signature': key_usage_value.digital_signature,
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
            if (isinstance(ext_key_usage_value, frozenset) and
                    ExtendedKeyUsageOID.CLIENT_AUTH not in ext_key_usage_value):
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
        """Get OPC UA server certificate from truststore.

        The truststore may contain multiple certificates (server cert + CA chain),
        but python-opcua's set_security() expects only the server certificate.
        The complete chain verification happens during the TLS handshake.

        Returns:
            Server certificate in DER format (first certificate with order=0).

        Raises:
            GdsPushError: If truststore is empty or misconfigured.
        """
        if self.server_truststore is None:
            msg = 'No server truststore configured'
            raise GdsPushError(msg)

        server_truststore = self.server_truststore

        try:
            truststore_order = await sync_to_async(
                lambda: server_truststore.truststoreordermodel_set.get(order=0)
            )()
        except Exception as e:
            msg = f'Server truststore "{self.server_truststore.unique_name}" has no certificate at order 0: {e}'
            raise GdsPushError(msg) from e

        cert_model = await sync_to_async(lambda: truststore_order.certificate)()
        cert_crypto = await sync_to_async(cert_model.get_certificate_serializer().as_crypto)()
        cert_der = cert_crypto.public_bytes(encoding=serialization.Encoding.DER)

        is_ca = False
        try:
            basic_constraints = cert_crypto.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            is_ca = basic_constraints.value.ca  # type: ignore[attr-defined]
        except x509.ExtensionNotFound:
            pass

        if is_ca:
            self.logger.warning(
                'Certificate at order 0 appears to be a CA certificate. '
                'Server certificate should be at order 0, followed by CA certificates.'
            )

        self.logger.info(
            'Using server certificate: %s (%d bytes)',
            cert_crypto.subject.rfc4514_string(),
            len(cert_der)
        )

        return cert_der

    async def _create_secure_client(self) -> Client:
        """Create OPC UA client with secure connection.

        Returns:
            Configured OPC UA client ready to connect.

        Raises:
            GdsPushError: If client creation fails.
        """
        try:
            client_cert_crypto, client_key_pem = await self._get_client_credentials()
            server_cert_der = await self._get_server_certificate()

            application_uri = self._extract_application_uri(client_cert_crypto)

            client_cert_chain_pem = await self._build_client_certificate_chain()

            with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as f:
                f.write(client_cert_chain_pem)
                client_cert_path = f.name

            with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as f:
                f.write(client_key_pem)
                client_key_path = f.name

            with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', delete=False) as f:
                f.write(server_cert_der)
                server_cert_path = f.name

            client = Client(self.server_url)
            client.application_uri = application_uri

            self.logger.info('Setting security policy: Basic256Sha256')

            await client.set_security(
                security_policies.SecurityPolicyBasic256Sha256,
                certificate=client_cert_path,
                private_key=client_key_path,
                server_certificate=server_cert_path,
                mode=ua.MessageSecurityMode.SignAndEncrypt
            )

            if self.device.onboarding_config:
                opc_user = self.device.onboarding_config.opc_user
                opc_password = self.device.onboarding_config.opc_password
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
        client.secure_channel_timeout = 10000  # 10 seconds
        client.session_timeout = 20000  # 20 seconds
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
                self.server_truststore.unique_name
            )

            self.logger.error(
                'Expected certificate:\n'
                '  Subject: %s\n'
                '  Issuer: %s\n'
                '  Serial: %s\n'
                '  SHA256: %s\n'
                '  Valid: %s to %s',
                expected_cert.subject.rfc4514_string(),
                expected_cert.issuer.rfc4514_string(),
                hex(expected_cert.serial_number),
                expected_cert.fingerprint(hashes.SHA256()).hex().upper(),
                expected_cert.not_valid_before_utc.isoformat(),
                expected_cert.not_valid_after_utc.isoformat()
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
                        actual_cert.not_valid_after_utc.isoformat()
                    )

                    if len(expected_cert_der) == len(actual_cert_der):
                        for i, (e_byte, a_byte) in enumerate(zip(expected_cert_der, actual_cert_der, strict=True)):
                            if e_byte != a_byte:
                                self.logger.error(
                                    'Certificates differ at byte %d: expected 0x%02X, got 0x%02X',
                                    i, e_byte, a_byte
                                )
                                break
                    else:
                        self.logger.error(
                            'Certificate lengths differ: expected %d bytes, got %d bytes',
                            len(expected_cert_der), len(actual_cert_der)
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

            async with client:
                server_info = await self._gather_server_info(client)

                if server_info and 'endpoints' in server_info:
                    self.logger.info('Server discovery completed successfully')
                    self.logger.info('Server name: %s', server_info.get('server_name', 'Unknown'))
                    self.logger.info('Found %d endpoints:', len(server_info['endpoints']))

                    # Analyze endpoints for logging and message building
                    endpoint_analysis = self._analyze_endpoints(server_info['endpoints'])

                    for i, endpoint in enumerate(server_info['endpoints'], 1):
                        policy_name = endpoint_analysis['policy_names'][i-1]
                        self.logger.info(
                            '  Endpoint %d: %s | Security: %s/%s | Server Cert: %s',
                            i,
                            endpoint['url'],
                            policy_name,
                            endpoint['security_mode'].replace('MessageSecurityMode.', ''),
                            'Yes' if endpoint['has_server_cert'] else 'No'
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
            endpoint_analysis = self._analyze_endpoints(server_info.get('endpoints', [])) if server_info else {
                'security_policies': set(),
                'has_secure_endpoints': False,
                'has_insecure_endpoints': False,
                'policy_names': []
            }

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
                policy_uri.split('/')[-1] if '/' in policy_uri else policy_uri
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
        """Gather server information from connected client.

        Args:
            client: Connected OPC UA client.

        Returns:
            Dictionary with server information.
        """
        server_info: dict[str, Any] = {}

        endpoints = await client.get_endpoints()
        server_info['endpoints'] = []
        for endpoint in endpoints:
            endpoint_info = {
                'url': endpoint.EndpointUrl,
                'security_policy': endpoint.SecurityPolicyUri,
                'security_mode': str(endpoint.SecurityMode),
                'has_server_cert': bool(endpoint.ServerCertificate),
            }
            server_info['endpoints'].append(endpoint_info)

        try:
            server_name_node = client.get_node('ns=0;i=2254')  # Server.ServerName property
            server_name = await server_name_node.read_value()
            if isinstance(server_name, list) and server_name:
                server_name = server_name[0]
            server_info['server_name'] = str(server_name)
        except Exception:  # noqa: BLE001
            server_info['server_name'] = 'Unknown'

        return server_info

    # ========================================================================
    # Public API - Update TrustList
    # ========================================================================

    async def update_trustlist(self) -> tuple[bool, str]:
        """Update server trustlist with CA chain and CRLs.

        Implements OPC UA Part 12 Section 7.7.3 UpdateTrustList workflow.

        Returns:
            Tuple of (success: bool, message: str).
        """
        client = None
        try:
            trustlist = await self._build_trustlist_for_server()

            client = await self._create_secure_client()

            try:
                async with client:

                    trustlist_nodes = await self._discover_trustlist_nodes(client)
                    if not trustlist_nodes:
                        return False, 'No TrustList nodes found on server'

                    success_count = 0
                    messages = []

                    for node_info in trustlist_nodes:
                        group_name = node_info['group_name']
                        trustlist_node = node_info['trustlist_node']

                        success = await self._update_single_trustlist(trustlist_node, trustlist)

                        if success:
                            success_count += 1
                            messages.append(f'✓ {group_name}')
                        else:
                            messages.append(f'✗ {group_name}')

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
                    app_uri
                )
                raise

            if success_count > 0:
                msg = (
                    f'Successfully updated {success_count}/{len(trustlist_nodes)} '
                    f'trustlist(s): {", ".join(messages)}'
                )
                return True, msg

        except Exception as e:
            self.logger.exception('Failed to update trustlist')
            return False, f'Update failed: {e}'
        else:
            return False, 'Failed to update any trustlist'

    async def _discover_trustlist_nodes(self, client: Client) -> list[dict[str, Any]]:
        """Discover TrustList nodes on server.

        Args:
            client: Connected OPC UA client.

        Returns:
            List of dictionaries with group and trustlist node information.
        """
        trustlist_nodes = []

        try:
            server_node = client.get_node('ns=0;i=2253')
            server_config = await server_node.get_child('ServerConfiguration')
            cert_groups_node = await server_config.get_child('CertificateGroups')

            groups = await cert_groups_node.get_children()
            self.logger.info('Found %d certificate group(s)', len(groups))

            for group_node in groups:
                try:
                    name = await group_node.read_browse_name()
                    group_name = name.Name
                    trustlist_node = await group_node.get_child('TrustList')

                    trustlist_nodes.append({
                        'group_name': group_name,
                        'group_node': group_node,
                        'trustlist_node': trustlist_node,
                    })

                except Exception as e:  # noqa: BLE001
                    self.logger.warning('Failed to get TrustList for group: %s', e)
                    continue

        except Exception:
            self.logger.exception('Failed to discover trustlist nodes')

        return trustlist_nodes

    async def _update_single_trustlist(
        self,
        trustlist_node: ua.Node,
        trustlist_data: ua.TrustListDataType,
        max_chunk_size: int = 1024
    ) -> bool:
        """Update a single TrustList node.

        Args:
            trustlist_node: The TrustList node to update.
            trustlist_data: TrustListDataType containing certificates and CRLs.
            max_chunk_size: Maximum size of each write chunk.

        Returns:
            True if successful, False otherwise.
        """
        try:
            serialized_trustlist = struct_to_binary(trustlist_data)

            # Step 1: Open
            mode = ua.TrustListMasks.All
            open_method = await trustlist_node.get_child('Open')
            file_handle = await trustlist_node.call_method(open_method, mode)
            self.logger.debug('Opened TrustList, handle: %s', file_handle)

            # Step 2: Write in chunks
            write_method = await trustlist_node.get_child('Write')
            offset = 0
            chunk_count = 0

            while offset < len(serialized_trustlist):
                chunk = serialized_trustlist[offset:offset + max_chunk_size]
                await trustlist_node.call_method(write_method, file_handle, chunk)
                offset += len(chunk)
                chunk_count += 1

            self.logger.debug('Wrote %d bytes in %d chunks', len(serialized_trustlist), chunk_count)

            # Step 3: CloseAndUpdate
            close_and_update_method = await trustlist_node.get_child('CloseAndUpdate')
            apply_changes_required = await trustlist_node.call_method(close_and_update_method, file_handle)
            self.logger.debug('Closed TrustList, ApplyChanges required: %s', apply_changes_required)

            # Step 4: ApplyChanges if required
            if apply_changes_required:
                group_node = await trustlist_node.get_parent()
                cert_groups_node = await group_node.get_parent()
                server_config_node = await cert_groups_node.get_parent()

                apply_changes = await server_config_node.get_child('ApplyChanges')
                await server_config_node.call_method(apply_changes)

        except Exception:
            self.logger.exception('Failed to update trustlist')
            return False
        else:
            return True

    # ========================================================================
    # Public API - Update Server Certificate
    # ========================================================================

    async def update_server_certificate(self) -> tuple[bool, str, bytes | None]:  # noqa: C901
        """Update server certificate using CSR-based workflow.

        Implements OPC UA Part 12 Section 7.7.4 UpdateCertificate workflow.

        Returns:
            Tuple of (success: bool, message: str, certificate: bytes | None).
        """
        client = None
        try:
            client = await self._create_secure_client()

            try:
                async with client:

                    cert_groups = await self._discover_certificate_groups(client)
                    if not cert_groups:
                        return False, 'No certificate groups found on server', None

                    success_count = 0
                    messages = []
                    issued_cert = None
                    issuer_chain = None

                    for group in cert_groups:
                        group_name = group['name']

                        if 'UserToken' in group_name:
                            continue

                        success, cert_bytes, chain_bytes = await self._update_single_certificate(
                            client=client,
                            certificate_group_id=group['node_id'],
                        )

                        if success:
                            success_count += 1
                            messages.append(f'✓ {group_name}')
                            if not issued_cert:
                                issued_cert = cert_bytes
                                issuer_chain = chain_bytes
                        else:
                            messages.append(f'✗ {group_name}')

            except Exception as connect_error:
                if 'certificate mismatch' in str(connect_error).lower():
                    await self._log_certificate_mismatch_details(client)
                    self.logger.exception('Certificate mismatch detected - server truststore may need updating')
                raise

            if success_count > 0:
                if issued_cert and issuer_chain:
                    await self._update_truststore_with_new_certificate(issued_cert, issuer_chain)

                msg = (
                    f'Successfully updated {success_count}/{len(cert_groups)} '
                    f'certificate(s): {", ".join(messages)}'
                )
                return True, msg, issued_cert

        except Exception as e:
            self.logger.exception('Failed to update server certificate')
            return False, f'Update failed: {e}', None
        else:
            return False, 'Failed to update any certificate', None


    async def _discover_certificate_groups(self, client: Client) -> list[dict[str, Any]]:
        """Discover certificate groups on server.

        Args:
            client: Connected OPC UA client.

        Returns:
            List of dictionaries with group information.
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
                    groups.append({
                        'name': group_name,
                        'node_id': group_node.nodeid,
                    })

                except Exception as e:  # noqa: BLE001
                    self.logger.warning('Failed to process group: %s', e)
                    continue

        except Exception:
            self.logger.exception('Failed to discover certificate groups')

        return groups

    async def _update_single_certificate(
        self,
        client: Client,
        certificate_group_id: ua.NodeId,
        certificate_type_id: ua.NodeId | None = None,
    ) -> tuple[bool, bytes | None, list[bytes] | None]:
        """Update certificate for a single certificate group.

        Args:
            client: Connected OPC UA client.
            certificate_group_id: NodeId of the certificate group.
            certificate_type_id: NodeId of certificate type.

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


            csr = await server_config.call_method(
                create_signing_request,
                certificate_group_id,
                certificate_type_id,
                None,  # subjectName
                True,  # regeneratePrivateKey  # noqa: FBT003
                None   # nonce
            )
            self.logger.info('CSR generated by server (%d bytes)', len(csr))

            # Step 2: Sign the CSR
            self.logger.info('Signing CSR with domain issuing CA')
            signed_cert, issuer_chain, _ = await self._sign_csr(csr)

            # Step 3: UpdateCertificate
            self.logger.info('Uploading signed certificate via UpdateCertificate')
            update_certificate = await server_config.get_child('UpdateCertificate')

            apply_changes_required = await server_config.call_method(
                update_certificate,
                certificate_group_id,
                certificate_type_id,
                signed_cert,
                issuer_chain,
                '',  # privateKeyFormat
                b''  # privateKey
            )
            self.logger.info('Certificate uploaded, ApplyChanges required: %s', apply_changes_required)

            # Step 4: ApplyChanges if required
            if apply_changes_required:
                apply_changes = await server_config.get_child('ApplyChanges')
                await server_config.call_method(apply_changes)

        except Exception:
            self.logger.exception('Failed to update certificate')
            return False, None, None
        else:
            return True, signed_cert, issuer_chain

    def _raise_gds_push_error(self, msg: str) -> None:
        """Raise a GdsPushError with the given message."""
        raise GdsPushError(msg)

    async def _sign_csr(self, csr_der: bytes) -> tuple[bytes, list[bytes], CertificateModel]:
        """Sign a Certificate Signing Request using the standardized certificate issuance workflow.

        This method uses the same CertificateIssueProcessor workflow as EST to ensure
        consistent certificate issuance across all protocols.

        Args:
            csr_der: DER-encoded CSR from OPC UA server.

        Returns:
            Tuple of (signed certificate DER, issuer chain as list of DER certs, issued certificate model).

        Raises:
            GdsPushError: If signing fails.
        """
        try:
            csr = x509.load_der_x509_csr(csr_der)

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

            certificate_profile_model = await sync_to_async(domain.get_allowed_cert_profile)('opc_ua')  # type: ignore[union-attr]
            if not certificate_profile_model:
                msg = (
                    'Certificate profile "opc_ua" not found or not allowed for domain '
                    f'"{domain.unique_name}"'  # type: ignore[union-attr]
                )
                self._raise_gds_push_error(msg)

            context.certificate_profile_model = certificate_profile_model

            await sync_to_async(ProfileValidator.validate)(context)

            processor = CertificateIssueProcessor()
            await sync_to_async(processor.process_operation)(context)

            if context.issued_certificate is None:
                msg = 'Certificate issuance failed: No certificate was issued'
                self._raise_gds_push_error(msg)

            issued_cert = context.issued_certificate

            cert_der = issued_cert.public_bytes(serialization.Encoding.DER)  # type: ignore[union-attr]

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
            self.logger.info(
                'Updating truststore "%s" with new server certificate + %d CA cert(s)',
                self.server_truststore.unique_name,
                len(issuer_chain)
            )

            server_truststore = self.server_truststore

            device = await sync_to_async(lambda: self.device)()
            domain = await sync_to_async(lambda: device.domain)()
            if domain is None:
                msg = 'Device has no domain'
                self._raise_gds_push_error(msg)
            ca = await sync_to_async(lambda: domain.issuing_ca)()  # type: ignore[union-attr]

            try:
                old_server_order = await sync_to_async(
                    lambda: server_truststore.truststoreordermodel_set.get(order=0)
                )()
                old_server_cert = await sync_to_async(lambda: old_server_order.certificate)()

                try:
                    await sync_to_async(
                        lambda: RevokedCertificateModel.objects.create(
                            certificate=old_server_cert,
                            revocation_reason=RevokedCertificateModel.ReasonCode.SUPERSEDED,
                            ca=ca
                        )
                    )()
                    self.logger.info('Revoked old server certificate: %s', old_server_cert.common_name)
                except IntegrityError:
                    self.logger.info('Old server certificate already revoked: %s', old_server_cert.common_name)
            except TruststoreOrderModel.DoesNotExist:
                self.logger.debug('No old server certificate found in truststore to revoke')


            await sync_to_async(self.server_truststore.truststoreordermodel_set.all().delete)()
            self.logger.debug('Cleared existing certificates from truststore')

            server_cert_crypto = x509.load_der_x509_certificate(server_cert_der)
            server_cert_fingerprint = server_cert_crypto.fingerprint(hashes.SHA256()).hex()

            server_cert_model = await sync_to_async(
                CertificateModel.get_cert_by_sha256_fingerprint
            )(server_cert_fingerprint)
            if server_cert_model is None:
                msg = f'Server certificate not found in database (fingerprint: {server_cert_fingerprint})'
                self._raise_gds_push_error(msg)

            await sync_to_async(TruststoreOrderModel.objects.create)(
                trust_store=self.server_truststore,
                certificate=server_cert_model,
                order=0
            )
            self.logger.debug('Added server certificate to truststore')

            for idx, ca_cert_der in enumerate(issuer_chain, start=1):
                ca_cert_crypto = x509.load_der_x509_certificate(ca_cert_der)
                ca_cert_fingerprint = ca_cert_crypto.fingerprint(hashes.SHA256()).hex()

                ca_cert_model = await sync_to_async(
                    CertificateModel.get_cert_by_sha256_fingerprint
                )(ca_cert_fingerprint)
                if ca_cert_model is None:
                    msg = f'CA certificate not found in database (fingerprint: {ca_cert_fingerprint})'
                    self._raise_gds_push_error(msg)

                await sync_to_async(TruststoreOrderModel.objects.create)(
                    trust_store=self.server_truststore,
                    certificate=ca_cert_model,
                    order=idx
                )
                self.logger.debug('Added CA certificate %d to truststore', idx)

            self.logger.info(
                'Updated truststore "%s" with %d certificate(s)',
                self.server_truststore.unique_name,
                1 + len(issuer_chain)
            )

        except Exception as e:
            msg = f'Failed to update truststore: {e}'
            raise GdsPushError(msg) from e
