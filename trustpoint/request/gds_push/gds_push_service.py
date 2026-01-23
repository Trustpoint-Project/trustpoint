"""Service for OPC UA GDS Push operations.

This module implements the GDS Push protocol for OPC UA servers, providing:
1. UpdateTrustList workflow (OPC UA Part 12 Section 7.7.3)
2. UpdateCertificate workflow (OPC UA Part 12 Section 7.7.4)

Key concepts:
- Truststore: Contains OPC UA server certificate for validating the server
- TrustList: CA chain + CRLs pushed to server for validating client certificates
"""

from __future__ import annotations

import contextlib
import datetime
import tempfile
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID
from opcua import Client, ua  # type: ignore[import-untyped]
from opcua.crypto import security_policies  # type: ignore[import-untyped]
from opcua.ua.ua_binary import struct_to_binary  # type: ignore[import-untyped]

from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from devices.models import DeviceModel, IssuedCredentialModel
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
            self.logger.info('Initializing for insecure operations (no authentication)')
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
            raise GdsPushError(msg)

    def _setup_secure_mode(self) -> None:
        """Setup credentials and truststore for secure operations.

        Raises:
            GdsPushError: If secure configuration is incomplete.
        """
        self.domain_credential = self._get_domain_credential()

        self.server_truststore = self._get_server_truststore()

        self.logger.info(
            'Initialized secure GDS Push for device "%s" (server truststore: "%s", %d cert(s))',
            self.device.common_name,
            self.server_truststore.unique_name,
            self.server_truststore.truststoreordermodel_set.count()
        )

    def _get_domain_credential(self) -> IssuedCredentialModel:
        """Get domain credential from device for client authentication.

        Returns:
            The most recent valid domain credential.

        Raises:
            GdsPushError: If no valid domain credential found.
        """
        from devices.models import IssuedCredentialModel  # noqa: PLC0415

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

        self.logger.info(
            'Using domain credential "%s" for device "%s"',
            credential.common_name,
            self.device.common_name
        )
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

    def _build_ca_chain(self) -> list[CaModel]:
        """Build CA certificate chain from device's domain issuing CA to root.

        Returns:
            List of CA models from issuing CA to root CA.

        Raises:
            GdsPushError: If chain is incomplete or invalid.
        """
        if not self.device.domain:
            msg = f'Device "{self.device.common_name}" has no domain configured'
            raise GdsPushError(msg)

        if not self.device.domain.issuing_ca:
            msg = f'Domain "{self.device.domain.unique_name}" has no issuing CA configured'
            raise GdsPushError(msg)

        issuing_ca = self.device.domain.issuing_ca

        return issuing_ca.get_ca_chain_from_truststore()


    def _build_trustlist_for_server(self) -> ua.TrustListDataType:
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
        ca_chain = self._build_ca_chain()

        trusted_certs = []
        trusted_crls = []
        issuer_certs = []
        issuer_crls = []

        for ca in ca_chain:
            ca_cert_crypto = ca.ca_certificate_model.get_certificate_serializer().as_crypto()
            ca_cert_der = ca_cert_crypto.public_bytes(encoding=serialization.Encoding.DER)

            trusted_certs.append(ca_cert_der)
            issuer_certs.append(ca_cert_der)

            self.logger.debug(
                'Added CA "%s" certificate to trustlist (%s)',
                ca.unique_name,
                ca_cert_crypto.subject.rfc4514_string()
            )

            # CRL is mandatory for OPC UA GDS Push
            if not ca.crl_pem:
                msg = (
                    f'CA "{ca.unique_name}" has no CRL configured. '
                    f'CRL is mandatory for OPC UA GDS Push trustlist.'
                )
                raise GdsPushError(msg)

            # Load and validate CRL
            try:
                crl_crypto = x509.load_pem_x509_crl(ca.crl_pem.encode())
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

            self.logger.debug(
                'Added valid CRL from CA "%s" (next update: %s)',
                ca.unique_name,
                crl_crypto.next_update_utc.isoformat() if crl_crypto.next_update_utc else 'N/A'
            )

        trustlist = ua.TrustListDataType()
        trustlist.SpecifiedLists = ua.TrustListMasks.All
        trustlist.TrustedCertificates = trusted_certs
        trustlist.TrustedCrls = trusted_crls
        trustlist.IssuerCertificates = issuer_certs
        trustlist.IssuerCrls = issuer_crls

        self.logger.info(
            'Built trustlist: %d trusted certs, %d issuer certs, %d trusted CRLs, %d issuer CRLs',
            len(trusted_certs),
            len(issuer_certs),
            len(trusted_crls),
            len(issuer_crls)
        )

        return trustlist

    # ========================================================================
    # OPC UA Client Creation & Connection
    # ========================================================================

    def _get_client_credentials(self) -> tuple[x509.Certificate, bytes]:
        """Get client certificate and private key from domain credential.

        Returns:
            Tuple of (certificate crypto object, private key PEM bytes).

        Raises:
            GdsPushError: If credentials are invalid.
        """
        if self.domain_credential is None:
            msg = 'No domain credential available'
            raise GdsPushError(msg)

        is_valid, reason = self.domain_credential.is_valid_domain_credential()
        if not is_valid:
            msg = f'Invalid domain credential: {reason}'
            raise GdsPushError(msg)

        cert_model = self.domain_credential.credential.certificate
        if not cert_model:
            msg = 'Domain credential has no certificate'
            raise GdsPushError(msg)

        cert_crypto = cert_model.get_certificate_serializer().as_crypto()

        # Validate certificate for OPC UA usage
        self._validate_client_certificate(cert_crypto)

        try:
            key_crypto = self.domain_credential.credential.get_private_key()
        except RuntimeError as e:
            msg = f'Failed to get private key: {e}'
            raise GdsPushError(msg) from e

        # Verify certificate and key match
        self._verify_certificate_key_match(cert_crypto, key_crypto)

        key_pem = key_crypto.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        return cert_crypto, key_pem

    def _build_client_certificate_chain(self) -> bytes:
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

        cert_model = self.domain_credential.credential.certificate
        if not cert_model:
            msg = 'Domain credential has no certificate'
            raise GdsPushError(msg)

        # Start with the client certificate
        client_cert = cert_model.get_certificate_serializer().as_crypto()

        # Build PEM chain with client cert + CA chain
        chain_pems = [client_cert.public_bytes(encoding=serialization.Encoding.PEM)]

        # Add CA chain (issuing CA to root)
        ca_chain = self._build_ca_chain()
        for ca in ca_chain:
            ca_cert = ca.ca_certificate_model.get_certificate_serializer().as_crypto()
            chain_pems.append(ca_cert.public_bytes(encoding=serialization.Encoding.PEM))

        self.logger.info(
            'Built client certificate chain: 1 client cert + %d CA cert(s) = %d total',
            len(ca_chain),
            len(chain_pems)
        )

        # Log details of each certificate in chain for debugging
        self.logger.debug('Certificate chain details:')
        self.logger.debug('  [0] Client: %s', client_cert.subject.rfc4514_string())
        for idx, ca in enumerate(ca_chain, start=1):
            ca_cert = ca.ca_certificate_model.get_certificate_serializer().as_crypto()
            self.logger.debug('  [%d] CA: %s', idx, ca_cert.subject.rfc4514_string())

        return b''.join(chain_pems)

    def _verify_certificate_key_match(
        self,
        cert: x509.Certificate,
        private_key: Any,  # RSA, EC, or other key types
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

        # Compare public key bytes
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

        self.logger.debug('Certificate and private key match verified ✓')

    def _validate_client_certificate(self, cert: x509.Certificate) -> None:
        """Validate client certificate meets OPC UA requirements.

        Args:
            cert: The client certificate to validate.

        Raises:
            GdsPushError: If certificate doesn't meet OPC UA requirements.
        """
        issues = []

        # Check validity period
        now = datetime.datetime.now(tz=datetime.UTC)
        if cert.not_valid_before_utc > now:
            issues.append(f'Certificate not yet valid (valid from: {cert.not_valid_before_utc.isoformat()})')
        if cert.not_valid_after_utc < now:
            issues.append(f'Certificate expired (valid until: {cert.not_valid_after_utc.isoformat()})')

        # Check Key Usage (required for OPC UA)
        try:
            key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            required_usages = {
                'digital_signature': key_usage.digital_signature,
                'key_encipherment': key_usage.key_encipherment,
                'data_encipherment': key_usage.data_encipherment,
            }
            missing_usages = [name for name, present in required_usages.items() if not present]
            if missing_usages:
                issues.append(f'Missing required key usages: {", ".join(missing_usages)}')
        except x509.ExtensionNotFound:
            issues.append('Key Usage extension is missing (required for OPC UA)')

        # Check Extended Key Usage (should have client auth)
        try:
            ext_key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            if ExtendedKeyUsageOID.CLIENT_AUTH not in ext_key_usage:
                issues.append('Certificate missing CLIENT_AUTH extended key usage')
        except x509.ExtensionNotFound:
            issues.append('Extended Key Usage extension is missing (should have CLIENT_AUTH)')

        # Check Subject Alternative Name (must have URI)
        try:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            has_uri = any(isinstance(gn, x509.UniformResourceIdentifier) for gn in san.value)
            if not has_uri:
                issues.append('Certificate SAN has no URI (application URI required for OPC UA)')
        except x509.ExtensionNotFound:
            issues.append('Subject Alternative Name extension is missing (required for OPC UA)')

        # Log validation results
        if issues:
            self.logger.warning(
                'Client certificate validation issues:\n  - %s',
                '\n  - '.join(issues)
            )
            msg = (
                f'Client certificate does not meet OPC UA requirements:\n'
                f'{chr(10).join(f"  - {issue}" for issue in issues)}'
            )
            raise GdsPushError(msg)

        self.logger.info(
            'Client certificate validation passed:\n'
            '  ✓ Validity period: %s to %s\n'
            '  ✓ Key Usage: digital_signature, key_encipherment, data_encipherment\n'
            '  ✓ Extended Key Usage: CLIENT_AUTH\n'
            '  ✓ Subject Alternative Name: URI present',
            cert.not_valid_before_utc.isoformat(),
            cert.not_valid_after_utc.isoformat()
        )

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
            for general_name in san.value:
                if isinstance(general_name, x509.UniformResourceIdentifier):
                    return general_name.value
        except x509.ExtensionNotFound:
            pass

        msg = 'No application URI found in domain credential certificate'
        raise GdsPushError(msg)

    def _get_server_certificate(self) -> bytes:
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

        # Get the first certificate (order=0) which should be the server certificate
        try:
            truststore_order = self.server_truststore.truststoreordermodel_set.get(order=0)
        except Exception as e:
            msg = f'Server truststore "{self.server_truststore.unique_name}" has no certificate at order 0: {e}'
            raise GdsPushError(msg) from e

        cert_crypto = truststore_order.certificate.get_certificate_serializer().as_crypto()
        cert_der = cert_crypto.public_bytes(encoding=serialization.Encoding.DER)

        # Check if this is actually a server certificate (not a CA)
        is_ca = False
        try:
            basic_constraints = cert_crypto.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            is_ca = basic_constraints.value.ca
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

    def _create_secure_client(self) -> Client:
        """Create OPC UA client with secure connection.

        Returns:
            Configured OPC UA client ready to connect.

        Raises:
            GdsPushError: If client creation fails.
        """
        try:
            client_cert_crypto, client_key_pem = self._get_client_credentials()
            server_cert_der = self._get_server_certificate()

            application_uri = self._extract_application_uri(client_cert_crypto)

            # Build complete certificate chain (client + CA chain) in PEM format
            client_cert_chain_pem = self._build_client_certificate_chain()

            self.logger.info(
                'Setting up secure client with:'
                '\n  Application URI: %s'
                '\n  Client cert subject: %s'
                '\n  Client cert SAN: %s'
                '\n  Server URL: %s',
                application_uri,
                client_cert_crypto.subject.rfc4514_string(),
                ', '.join(str(san.value) for san in client_cert_crypto.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                ).value) if client_cert_crypto.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                ) else 'None',
                self.server_url
            )

            # Write client certificate chain in PEM format (includes client + CA chain)
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as f:
                f.write(client_cert_chain_pem)
                client_cert_path = f.name

            with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as f:
                f.write(client_key_pem)
                client_key_path = f.name

            # Write server certificate in DER format (as expected by python-opcua)
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', delete=False) as f:
                f.write(server_cert_der)
                server_cert_path = f.name

            # Log the certificate we're expecting
            # server_cert_crypto = x509.load_der_x509_certificate(server_cert_der)
            # self.logger.debug(
            #     'Expected server cert (from truststore): %d bytes DER, SHA256: %s',
            #     len(server_cert_der),
            #     server_cert_crypto.fingerprint(hashes.SHA256()).hex().upper()
            # )
            # self.logger.debug('Server cert DER (first 64 bytes): %s', server_cert_der[:64].hex().upper())
            
            # # Verify what was actually written to the file
            # with open(server_cert_path, 'rb') as f:
            #     server_cert_from_file = f.read()
            # self.logger.debug(
            #     'Server cert from file: %d bytes, SHA256: %s',
            #     len(server_cert_from_file),
            #     x509.load_der_x509_certificate(server_cert_from_file).fingerprint(hashes.SHA256()).hex().upper()
            # )
            # if server_cert_der != server_cert_from_file:
            #     self.logger.error('MISMATCH: Certificate written to file differs from in-memory cert!')
            # else:
            #     self.logger.debug('✓ Certificate file matches in-memory certificate')

            # self.logger.debug('Created temporary credential files for OPC UA client')
            # self.logger.debug('  Client cert: %s', client_cert_path)
            # self.logger.debug('  Client key: %s', client_key_path)
            # self.logger.debug('  Server cert: %s', server_cert_path)

            client = Client(self.server_url)
            client.application_uri = application_uri
            client.secure_channel_timeout = 30000  # 30 seconds
            client.session_timeout = 60000  # 60 seconds

            self.logger.info(
                'Setting security policy: Basic256Sha256, mode: SignAndEncrypt'
            )

            client.set_security(
                security_policies.SecurityPolicyBasic256Sha256,
                certificate_path=client_cert_path,
                private_key_path=client_key_path,
                server_certificate_path=server_cert_path,
                mode=ua.MessageSecurityMode.SignAndEncrypt
            )
            
            # CRITICAL FIX: Override the server_certificate with our exact DER bytes
            # Python-opcua re-encodes the certificate when loading from file, which can
            # cause byte-level differences even though the certificates are logically identical.
            # We must use the EXACT bytes to match what's in the truststore.
            #self.logger.debug('Overriding security_policy.server_certificate with exact DER bytes from truststore')
            #original_cert_from_policy = client.uaclient.security_policy.server_certificate
            #self.logger.debug('Original (re-encoded by opcua): %d bytes, first 32: %s',
            #                len(original_cert_from_policy), original_cert_from_policy[:32].hex().upper())
            #self.logger.debug('Our exact DER: %d bytes, first 32: %s',
            #                len(server_cert_der), server_cert_der[:32].hex().upper())
            
            # Replace with our exact bytes
            #client.uaclient.security_policy.server_certificate = server_cert_der
            self.logger.debug('✓ Replaced with exact DER bytes from truststore')
            
            # Verify the replacement worked
            self.logger.debug('Verifying replacement...')
            # if hasattr(client, 'uaclient') and hasattr(client.uaclient, 'security_policy'):
            #     loaded_cert = client.uaclient.security_policy.server_certificate
            #     if loaded_cert:
            #         self.logger.debug(
            #             'Python-opcua loaded cert - Type: %s, Length: %d',
            #             type(loaded_cert).__name__,
            #             len(loaded_cert)
            #         )
            #         loaded_cert_crypto = x509.load_der_x509_certificate(loaded_cert)
            #         self.logger.debug(
            #             'Python-opcua loaded server cert: SHA256: %s',
            #             loaded_cert_crypto.fingerprint(hashes.SHA256()).hex().upper()
            #         )
            #         self.logger.debug('Loaded cert (first 64 bytes): %s', loaded_cert[:64].hex().upper())
                    
            #         # Check type of our server_cert_der
            #         self.logger.debug(
            #             'Our server_cert_der - Type: %s, Length: %d',
            #             type(server_cert_der).__name__,
            #             len(server_cert_der)
            #         )
                    
            #         # Test different comparison methods
            #         self.logger.debug('Comparison tests:')
            #         self.logger.debug('  loaded_cert == server_cert_der: %s', loaded_cert == server_cert_der)
            #         self.logger.debug('  loaded_cert != server_cert_der: %s', loaded_cert != server_cert_der)
            #         self.logger.debug('  bytes(loaded_cert) == bytes(server_cert_der): %s', 
            #                         bytes(loaded_cert) == bytes(server_cert_der))
                    
            #         if loaded_cert != server_cert_der:
            #             self.logger.error('MISMATCH: Python-opcua loaded different certificate than we provided!')
            #             self.logger.error('  Type comparison: %s vs %s', 
            #                             type(loaded_cert).__name__, type(server_cert_der).__name__)
            #         else:
            #             self.logger.debug('✓ Python-opcua loaded the correct certificate')
            #     else:
            #         self.logger.warning('Python-opcua security_policy has no server_certificate loaded')

            if self.device.onboarding_config:
                opc_user = self.device.onboarding_config.opc_user
                opc_password = self.device.onboarding_config.opc_password
                if opc_user:
                    client.set_user(opc_user)
                    if opc_password:
                        client.set_password(opc_password)
                    self.logger.debug('Set username/password authentication')

        except Exception as e:
            msg = f'Failed to create secure client: {e}'
            raise GdsPushError(msg) from e
        else:
            # Final verification before returning
            # final_cert = client.uaclient.security_policy.server_certificate
            # self.logger.info(
            #     'Successfully created secure client with certificate: %d bytes, SHA256: %s',
            #     len(final_cert),
            #     x509.load_der_x509_certificate(final_cert).fingerprint(hashes.SHA256()).hex().upper()
            # )
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

    def _log_certificate_mismatch_details(self, client: Client) -> None:
        """Log detailed information about certificate mismatch.

        Args:
            client: The OPC UA client that failed to connect.
        """
        try:
            # Get the expected certificate from truststore
            expected_cert_der = self._get_server_certificate()
            expected_cert = x509.load_der_x509_certificate(expected_cert_der)

            self.logger.error(
                'Server certificate mismatch detected!'
                '\n'
                '\n=== EXPECTED (from truststore "%s") ===',
                self.server_truststore.unique_name
            )
            
            # Check what python-opcua loaded
            self.logger.error('\n=== PYTHON-OPCUA LOADED CERTIFICATE ===')
            if hasattr(client, 'uaclient'):
                self.logger.error('  client.uaclient exists: True')
                if hasattr(client.uaclient, 'security_policy'):
                    self.logger.error('  client.uaclient.security_policy exists: True')
                    loaded_cert = client.uaclient.security_policy.server_certificate
                    if loaded_cert:
                        self.logger.error('  Loaded cert type: %s', type(loaded_cert).__name__)
                        self.logger.error('  Loaded cert length: %d', len(loaded_cert))
                        self.logger.error('  Expected cert type: %s', type(expected_cert_der).__name__)
                        self.logger.error('  Expected cert length: %d', len(expected_cert_der))
                        self.logger.error('  Are they equal (==)? %s', loaded_cert == expected_cert_der)
                        self.logger.error('  Are they not equal (!=)? %s', loaded_cert != expected_cert_der)
                        self.logger.error('  Are they identical (is)? %s', loaded_cert is expected_cert_der)
                        self.logger.error('  bytes() comparison: %s', bytes(loaded_cert) == bytes(expected_cert_der))
                    else:
                        self.logger.error('  Loaded cert is None/empty')
                else:
                    self.logger.error('  client.uaclient.security_policy does NOT exist')
            else:
                self.logger.error('  client.uaclient does NOT exist')
            self.logger.error(
                '  Subject: %s'
                '\n  Issuer: %s'
                '\n  Serial: %s'
                '\n  Not Before: %s'
                '\n  Not After: %s'
                '\n  SHA256: %s'
                '\n  DER size: %d bytes'
                '\n  DER (first 64 bytes): %s',
                expected_cert.subject.rfc4514_string(),
                expected_cert.issuer.rfc4514_string(),
                hex(expected_cert.serial_number),
                expected_cert.not_valid_before_utc,
                expected_cert.not_valid_after_utc,
                expected_cert.fingerprint(hashes.SHA256()).hex().upper(),
                len(expected_cert_der),
                expected_cert_der[:64].hex().upper()
            )

            # Try to get the actual server certificate
            # The python-opcua library may have cached it during the failed connection attempt
            if hasattr(client, 'uaclient') and hasattr(client.uaclient, 'security_policy'):
                security_policy = client.uaclient.security_policy
                if hasattr(security_policy, 'server_certificate') and security_policy.server_certificate:
                    try:
                        actual_cert_der = security_policy.server_certificate
                        actual_cert = x509.load_der_x509_certificate(actual_cert_der)
                        self.logger.error(
                            '\n=== ACTUAL (presented by server) ==='
                            '\n  Subject: %s'
                            '\n  Issuer: %s'
                            '\n  Serial: %s'
                            '\n  Not Before: %s'
                            '\n  Not After: %s'
                            '\n  SHA256: %s'
                            '\n  DER size: %d bytes'
                            '\n  DER (first 64 bytes): %s',
                            actual_cert.subject.rfc4514_string(),
                            actual_cert.issuer.rfc4514_string(),
                            hex(actual_cert.serial_number),
                            actual_cert.not_valid_before_utc,
                            actual_cert.not_valid_after_utc,
                            actual_cert.fingerprint(hashes.SHA256()).hex().upper(),
                            len(actual_cert_der),
                            actual_cert_der[:64].hex().upper()
                        )
                        
                        # Compare byte-by-byte
                        if len(expected_cert_der) != len(actual_cert_der):
                            self.logger.error(
                                '\n=== BYTE COMPARISON ==='
                                '\n  Expected length: %d bytes'
                                '\n  Actual length: %d bytes'
                                '\n  Length difference: %d bytes',
                                len(expected_cert_der),
                                len(actual_cert_der),
                                abs(len(expected_cert_der) - len(actual_cert_der))
                            )
                        else:
                            # Find first differing byte
                            for i, (e_byte, a_byte) in enumerate(zip(expected_cert_der, actual_cert_der)):
                                if e_byte != a_byte:
                                    self.logger.error(
                                        '\n=== BYTE COMPARISON ==='
                                        '\n  Certificates are same length (%d bytes) but differ'
                                        '\n  First difference at byte %d:'
                                        '\n    Expected: 0x%02X'
                                        '\n    Actual: 0x%02X',
                                        len(expected_cert_der),
                                        i,
                                        e_byte,
                                        a_byte
                                    )
                                    break

                    except Exception as cert_parse_error:
                        self.logger.error('Could not parse actual server certificate: %s', cert_parse_error)
                else:
                    self.logger.error('\n=== ACTUAL (presented by server) ===\n  (Certificate not captured)')
            else:
                self.logger.error('\n=== ACTUAL (presented by server) ===\n  (Certificate not accessible)')

        except Exception as log_error:
            self.logger.warning('Failed to log certificate mismatch details: %s', log_error)

    # ========================================================================
    # Public API - Discovery
    # ========================================================================

    def discover_server(self) -> tuple[bool, str, dict[str, Any] | None]:
        """Discover OPC UA server information without authentication.

        Returns:
            Tuple of (success: bool, message: str, server_info: dict | None).
        """
        client = None
        try:
            client = self._create_insecure_client()

            self.logger.info('Connecting to OPC UA server without security for discovery...')
            client.connect()

            server_info = self._gather_server_info(client)

            client.disconnect()

        except Exception as e:  # noqa: BLE001
            self.logger.warning('Failed to discover server: %s', e)
            return False, f'Discovery failed: {e}', None
        else:
            self.logger.info('Successfully discovered server information')
            return True, 'Server discovered successfully', server_info
        finally:
            if client:
                with contextlib.suppress(Exception):
                    client.disconnect()

    def _gather_server_info(self, client: Client) -> dict[str, Any]:
        """Gather server information from connected client.

        Args:
            client: Connected OPC UA client.

        Returns:
            Dictionary with server information.
        """
        server_info: dict[str, Any] = {}

        endpoints = client.get_endpoints()
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
            server_node = client.get_node('ns=0;i=2253')
            server_info['server_name'] = str(server_node.get_browse_name().Name)
        except Exception as e:  # noqa: BLE001 - OPC UA operations can throw various errors
            self.logger.debug('Failed to get server name: %s', e)
            server_info['server_name'] = 'Unknown'

        return server_info

    # ========================================================================
    # Public API - Update TrustList
    # ========================================================================

    def update_trustlist(self) -> tuple[bool, str]:
        """Update server trustlist with CA chain and CRLs.

        Implements OPC UA Part 12 Section 7.7.3 UpdateTrustList workflow.

        Returns:
            Tuple of (success: bool, message: str).
        """
        client = None
        try:
            trustlist = self._build_trustlist_for_server()

            client = self._create_secure_client()
            self.logger.info('Connecting to OPC UA server at %s', self.server_url)

            try:
                client.connect()
                self.logger.info('Connected successfully')
            except Exception:
                # Get application URI for error message
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

            trustlist_nodes = self._discover_trustlist_nodes(client)
            if not trustlist_nodes:
                return False, 'No TrustList nodes found on server'

            success_count = 0
            messages = []

            for node_info in trustlist_nodes:
                group_name = node_info['group_name']
                trustlist_node = node_info['trustlist_node']

                self.logger.info('Updating trustlist for group: %s', group_name)
                success = self._update_single_trustlist(trustlist_node, trustlist)

                if success:
                    success_count += 1
                    messages.append(f'✓ {group_name}')
                else:
                    messages.append(f'✗ {group_name}')

            client.disconnect()

            if success_count > 0:
                msg = (
                    f'Successfully updated {success_count}/{len(trustlist_nodes)} '
                    f'trustlist(s): {", ".join(messages)}'
                )
                return True, msg

        except Exception as e:
            self.logger.exception('Failed to update trustlist')
            if client:
                with contextlib.suppress(Exception):
                    client.disconnect()
            return False, f'Update failed: {e}'
        else:
            return False, 'Failed to update any trustlist'

    def _discover_trustlist_nodes(self, client: Client) -> list[dict[str, Any]]:
        """Discover TrustList nodes on server.

        Args:
            client: Connected OPC UA client.

        Returns:
            List of dictionaries with group and trustlist node information.
        """
        trustlist_nodes = []

        try:
            server_node = client.get_node('ns=0;i=2253')
            server_config = server_node.get_child('ServerConfiguration')
            cert_groups_node = server_config.get_child('CertificateGroups')

            groups = cert_groups_node.get_children()
            self.logger.info('Found %d certificate group(s)', len(groups))

            for group_node in groups:
                try:
                    group_name = group_node.get_browse_name().Name
                    trustlist_node = group_node.get_child('TrustList')

                    trustlist_nodes.append({
                        'group_name': group_name,
                        'group_node': group_node,
                        'trustlist_node': trustlist_node,
                    })
                    self.logger.info('Discovered TrustList for group: %s', group_name)

                except Exception as e:  # noqa: BLE001 - OPC UA node access can fail in various ways
                    self.logger.warning('Failed to get TrustList for group: %s', e)
                    continue

        except Exception:
            self.logger.exception('Failed to discover trustlist nodes')

        return trustlist_nodes

    def _update_single_trustlist(
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
            self.logger.info('Serialized TrustList: %d bytes', len(serialized_trustlist))

            # Step 1: Open
            mode = ua.TrustListMasks.All
            open_method = trustlist_node.get_child('Open')
            file_handle = trustlist_node.call_method(open_method, mode)
            self.logger.debug('Opened TrustList, handle: %s', file_handle)

            # Step 2: Write in chunks
            write_method = trustlist_node.get_child('Write')
            offset = 0
            chunk_count = 0

            while offset < len(serialized_trustlist):
                chunk = serialized_trustlist[offset:offset + max_chunk_size]
                trustlist_node.call_method(write_method, file_handle, chunk)
                offset += len(chunk)
                chunk_count += 1

            self.logger.debug('Wrote %d bytes in %d chunks', len(serialized_trustlist), chunk_count)

            # Step 3: CloseAndUpdate
            close_and_update_method = trustlist_node.get_child('CloseAndUpdate')
            apply_changes_required = trustlist_node.call_method(close_and_update_method, file_handle)
            self.logger.debug('Closed TrustList, ApplyChanges required: %s', apply_changes_required)

            # Step 4: ApplyChanges if required
            if apply_changes_required:
                self.logger.info('Applying changes server-wide')
                server_node = trustlist_node.get_parent().get_parent()
                apply_changes = server_node.get_child('ApplyChanges')
                server_node.call_method(apply_changes)

        except Exception:
            self.logger.exception('Failed to update trustlist')
            return False
        else:
            return True

    # ========================================================================
    # Public API - Update Server Certificate
    # ========================================================================

    def update_server_certificate(self) -> tuple[bool, str, bytes | None]:
        """Update server certificate using CSR-based workflow.

        Implements OPC UA Part 12 Section 7.7.4 UpdateCertificate workflow.

        Returns:
            Tuple of (success: bool, message: str, certificate: bytes | None).
        """
        client = None
        try:
            # Create secure client and connect
            client = self._create_secure_client()
            self.logger.info('Connecting to OPC UA server at %s', self.server_url)
            
            try:
                client.connect()
                self.logger.info('Connected successfully')
            except Exception as connect_error:
                # If connection fails due to certificate mismatch, log details
                if 'certificate mismatch' in str(connect_error).lower():
                    self._log_certificate_mismatch_details(client)
                    self.logger.error(
                        '\n'
                        '═══════════════════════════════════════════════════════════════\n'
                        '  SOLUTION: Update the truststore with server certificate chain\n'
                        '═══════════════════════════════════════════════════════════════\n'
                        '\n'
                        'The server certificate chain has changed or is incomplete.\n'
                        '\n'
                        'To fix this:\n'
                        '  1. Download the complete certificate chain from the OPC UA server\n'
                        '     (server certificate + any intermediate CA certificates)\n'
                        '  2. Update truststore "%s" with all certificates in the chain\n'
                        '  3. Ensure certificates are in the correct order:\n'
                        '     - Order 0: Server certificate (end-entity)\n'
                        '     - Order 1+: CA certificates (if any)\n'
                        '\n'
                        'The truststore must contain the exact chain that the server\n'
                        'presents during the TLS handshake.\n',
                        self.server_truststore.unique_name if self.server_truststore else 'unknown'
                    )
                raise

            # Discover certificate groups
            cert_groups = self._discover_certificate_groups(client)
            if not cert_groups:
                return False, 'No certificate groups found on server', None

            # Update certificate for each group (skip UserToken groups)
            success_count = 0
            messages = []
            issued_cert = None
            issuer_chain = None

            for group in cert_groups:
                group_name = group['name']

                # Skip UserToken groups
                if 'UserToken' in group_name:
                    self.logger.info('Skipping %s (user token group)', group_name)
                    continue

                self.logger.info('Updating certificate for group: %s', group_name)
                success, cert_bytes, chain_bytes = self._update_single_certificate(
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

            client.disconnect()

            if success_count > 0:
                # Update the truststore with the new server certificate + CA chain
                if issued_cert and issuer_chain:
                    self._update_truststore_with_new_certificate(issued_cert, issuer_chain)
                
                msg = (
                    f'Successfully updated {success_count}/{len(cert_groups)} '
                    f'certificate(s): {", ".join(messages)}'
                )
                return True, msg, issued_cert

        except Exception as e:
            self.logger.exception('Failed to update server certificate')
            if client:
                with contextlib.suppress(Exception):
                    client.disconnect()
            return False, f'Update failed: {e}', None
        else:
            return False, 'Failed to update any certificate', None


    def _discover_certificate_groups(self, client: Client) -> list[dict[str, Any]]:
        """Discover certificate groups on server.

        Args:
            client: Connected OPC UA client.

        Returns:
            List of dictionaries with group information.
        """
        groups = []

        try:
            server_node = client.get_node('ns=0;i=2253')
            server_config = server_node.get_child('ServerConfiguration')
            cert_groups_node = server_config.get_child('CertificateGroups')

            group_nodes = cert_groups_node.get_children()
            self.logger.info('Found %d certificate group(s)', len(group_nodes))

            for group_node in group_nodes:
                try:
                    group_name = group_node.get_browse_name().Name
                    groups.append({
                        'name': group_name,
                        'node_id': group_node.nodeid,
                    })
                    self.logger.info('Discovered certificate group: %s', group_name)

                except Exception as e:  # noqa: BLE001 - OPC UA operations can fail in various ways
                    self.logger.warning('Failed to process group: %s', e)
                    continue

        except Exception:
            self.logger.exception('Failed to discover certificate groups')

        return groups

    def _update_single_certificate(
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
            server_config = server_node.get_child('ServerConfiguration')

            # Step 1: CreateSigningRequest
            self.logger.info('Server generating CSR via CreateSigningRequest')
            create_signing_request = server_config.get_child('CreateSigningRequest')

            csr = server_config.call_method(
                create_signing_request,
                certificate_group_id,
                certificate_type_id,
                None,  # Let server generate subject
                True,  # Regenerate private key  # noqa: FBT003 - OPC UA library API requirement
                None   # No nonce
            )
            self.logger.info('CSR generated by server (%d bytes)', len(csr))

            # Step 2: Sign the CSR
            self.logger.info('Signing CSR with domain issuing CA')
            signed_cert, issuer_chain = self._sign_csr(csr)

            # Step 3: UpdateCertificate
            self.logger.info('Uploading signed certificate via UpdateCertificate')
            update_certificate = server_config.get_child('UpdateCertificate')

            apply_changes_required = server_config.call_method(
                update_certificate,
                certificate_group_id,
                certificate_type_id,
                signed_cert,
                issuer_chain,
                '',  # No private key format
                b''  # No private key
            )
            self.logger.info('Certificate uploaded, ApplyChanges required: %s', apply_changes_required)

            # Step 4: ApplyChanges if required
            if apply_changes_required:
                self.logger.info('Applying changes server-wide')
                apply_changes = server_config.get_child('ApplyChanges')
                server_config.call_method(apply_changes)

        except Exception:
            self.logger.exception('Failed to update certificate')
            return False, None, None
        else:
            return True, signed_cert, issuer_chain

    def _sign_csr(self, csr_der: bytes) -> tuple[bytes, list[bytes]]:
        """Sign a Certificate Signing Request using the standardized certificate issuance workflow.

        This method uses the same CertificateIssueProcessor workflow as EST to ensure
        consistent certificate issuance across all protocols.

        Args:
            csr_der: DER-encoded CSR from OPC UA server.

        Returns:
            Tuple of (signed certificate DER, issuer chain as list of DER certs).

        Raises:
            GdsPushError: If signing fails.
        """
        try:
            csr = x509.load_der_x509_csr(csr_der)

            self.logger.info(
                'Signing CSR from OPC UA server:\n'
                '  Subject: %s\n'
                '  Public Key: %s',
                csr.subject.rfc4514_string(),
                type(csr.public_key()).__name__
            )

            # Create a minimal context for certificate issuance
            # Similar to EST workflow but for OPC UA GDS Push
            from request.operation_processor import CertificateIssueProcessor
            from request.profile_validator import ProfileValidator
            from request.request_context import BaseCertificateRequestContext

            context = BaseCertificateRequestContext(
                device=self.device,
                domain=self.device.domain,
                cert_requested=csr,
                cert_profile_str='opc_ua',
                protocol='opc_gds_push',
                operation='update_certificate',
            )

            # Load the certificate profile model from the domain
            if not context.domain:
                msg = 'Device has no domain configured'
                raise GdsPushError(msg)

            certificate_profile_model = context.domain.get_allowed_cert_profile('opc_ua')
            if not certificate_profile_model:
                msg = (
                    'Certificate profile "opc_ua" not found or not allowed for domain '
                    f'"{context.domain.unique_name}"'
                )
                raise GdsPushError(msg)

            context.certificate_profile_model = certificate_profile_model

            # Validate certificate profile (OPC UA server certificates use a specific profile)
            ProfileValidator.validate(context)

            # Issue certificate using standard processor
            processor = CertificateIssueProcessor()
            processor.process_operation(context)

            if context.issued_certificate is None:
                msg = 'Certificate issuance failed: No certificate was issued'
                raise GdsPushError(msg)

            # Convert to DER format
            cert_der = context.issued_certificate.public_bytes(serialization.Encoding.DER)

            # Log certificate extensions for debugging
            self.logger.info('Issued certificate extensions:')
            for ext in context.issued_certificate.extensions:
                ext_name = ext.oid._name if hasattr(ext.oid, '_name') else str(ext.oid)
                self.logger.info('  - %s (critical=%s)', ext_name, ext.critical)
                if ext_name == 'extendedKeyUsage':
                    try:
                        eku = ext.value
                        self.logger.info('    Extended Key Usage OIDs: %s', [str(oid) for oid in eku])
                    except Exception as e:
                        self.logger.warning('    Failed to parse Extended Key Usage: %s', e)

            self.logger.info('Certificate issued successfully (%d bytes)', len(cert_der))

            # Build issuer chain from CA hierarchy
            ca_chain = self._build_ca_chain()
            issuer_chain = []

            for ca in ca_chain:
                ca_cert = ca.ca_certificate_model.get_certificate_serializer().as_crypto()
                issuer_chain.append(ca_cert.public_bytes(encoding=serialization.Encoding.DER))

            self.logger.info('Issuer chain includes %d CA certificate(s)', len(issuer_chain))

        except Exception as e:
            msg = f'Failed to sign CSR: {e}'
            raise GdsPushError(msg) from e
        else:
            return cert_der, issuer_chain

    def _update_truststore_with_new_certificate(
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
            from pki.models import CertificateModel, TruststoreOrderModel  # noqa: PLC0415

            self.logger.info(
                'Updating truststore "%s" with new server certificate + %d CA cert(s)',
                self.server_truststore.unique_name,
                len(issuer_chain)
            )

            # Delete all existing certificates from the truststore
            self.server_truststore.truststoreordermodel_set.all().delete()
            self.logger.debug('Cleared existing certificates from truststore')

            # Add the server certificate (order 0)
            server_cert_crypto = x509.load_der_x509_certificate(server_cert_der)
            server_cert_fingerprint = server_cert_crypto.fingerprint(hashes.SHA256()).hex()
            
            server_cert_model = CertificateModel.get_cert_by_sha256_fingerprint(server_cert_fingerprint)
            if server_cert_model is None:
                msg = f'Server certificate not found in database (fingerprint: {server_cert_fingerprint})'
                raise GdsPushError(msg)
            
            TruststoreOrderModel.objects.create(
                trust_store=self.server_truststore,
                certificate=server_cert_model,
                order=0
            )
            self.logger.info(
                '[0] Added server certificate: %s',
                server_cert_crypto.subject.rfc4514_string()
            )

            # Add CA certificates (order 1, 2, 3, ...)
            for idx, ca_cert_der in enumerate(issuer_chain, start=1):
                ca_cert_crypto = x509.load_der_x509_certificate(ca_cert_der)
                ca_cert_fingerprint = ca_cert_crypto.fingerprint(hashes.SHA256()).hex()
                
                ca_cert_model = CertificateModel.get_cert_by_sha256_fingerprint(ca_cert_fingerprint)
                if ca_cert_model is None:
                    msg = f'CA certificate not found in database (fingerprint: {ca_cert_fingerprint})'
                    raise GdsPushError(msg)
                
                TruststoreOrderModel.objects.create(
                    trust_store=self.server_truststore,
                    certificate=ca_cert_model,
                    order=idx
                )
                self.logger.info(
                    '[%d] Added CA certificate: %s',
                    idx,
                    ca_cert_crypto.subject.rfc4514_string()
                )

            total_certs = 1 + len(issuer_chain)
            self.logger.info(
                'Truststore "%s" updated successfully with %d certificate(s)',
                self.server_truststore.unique_name,
                total_certs
            )

        except Exception as e:
            msg = f'Failed to update truststore: {e}'
            raise GdsPushError(msg) from e
