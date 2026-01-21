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
import logging
import tempfile
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID
from opcua import Client, ua  # type: ignore[import-untyped]
from opcua.crypto import security_policies  # type: ignore[import-untyped]
from opcua.ua.ua_binary import struct_to_binary  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from devices.models import DeviceModel, IssuedCredentialModel
    from pki.models import CaModel
    from pki.models.truststore import TruststoreModel

__all__ = ['GdsPushError', 'GdsPushService']

logger = logging.getLogger(__name__)


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


class GdsPushService:
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

        self.server_url = f'opc.tcp://{device.ip_address}:{device.port}'

        if insecure:
            logger.info('Initializing for insecure operations (no authentication)')
            self.domain_credential = None
            self.server_truststore = None
            return

        self._setup_secure_mode()

    def _validate_device_config(self) -> None:
        """Validate device has required configuration.

        Raises:
            GdsPushError: If device configuration is invalid.
        """
        if not self.device.ip_address or not self.device.port:
            msg = f'Device "{self.device.common_name}" must have IP address and port configured'
            raise GdsPushError(msg)

    def _setup_secure_mode(self) -> None:
        """Setup credentials and truststore for secure operations.

        Raises:
            GdsPushError: If secure configuration is incomplete.
        """
        self.domain_credential = self._get_domain_credential()

        self.server_truststore = self._get_server_truststore()

        logger.info(
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

        logger.info(
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

            logger.debug(
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

            logger.debug(
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

        logger.info(
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

        try:
            key_crypto = self.domain_credential.credential.get_private_key()
        except RuntimeError as e:
            msg = f'Failed to get private key: {e}'
            raise GdsPushError(msg) from e

        key_pem = key_crypto.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        return cert_crypto, key_pem

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

        Returns:
            Server certificate in DER format.

        Raises:
            GdsPushError: If server certificate not found.
        """
        if self.server_truststore is None:
            msg = 'No server truststore configured'
            raise GdsPushError(msg)


        truststore_order = self.server_truststore.truststoreordermodel_set.order_by('order').first()
        if not truststore_order:
            msg = f'Server truststore "{self.server_truststore.unique_name}" contains no certificates'
            raise GdsPushError(msg)

        cert_crypto = truststore_order.certificate.get_certificate_serializer().as_crypto()
        return cert_crypto.public_bytes(encoding=serialization.Encoding.DER)

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

            client_cert_der = client_cert_crypto.public_bytes(encoding=serialization.Encoding.DER)

            with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', delete=False) as f:
                f.write(client_cert_der)
                client_cert_path = f.name

            with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as f:
                f.write(client_key_pem)
                client_key_path = f.name

            with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', delete=False) as f:
                f.write(server_cert_der)
                server_cert_path = f.name

            logger.debug('Created temporary credential files for OPC UA client')

            client = Client(self.server_url)
            client.application_uri = application_uri
            client.secure_channel_timeout = 30000  # 30 seconds
            client.session_timeout = 60000  # 60 seconds

            client.set_security(
                security_policies.SecurityPolicyBasic256Sha256,
                certificate_path=client_cert_path,
                private_key_path=client_key_path,
                server_certificate_path=server_cert_path,
                mode=ua.MessageSecurityMode.SignAndEncrypt
            )

            if self.device.onboarding_config:
                opc_user = self.device.onboarding_config.opc_user
                opc_password = self.device.onboarding_config.opc_password
                if opc_user:
                    client.set_user(opc_user)
                    if opc_password:
                        client.set_password(opc_password)
                    logger.debug('Set username/password authentication')

        except Exception as e:
            msg = f'Failed to create secure client: {e}'
            raise GdsPushError(msg) from e
        else:
            logger.info('Successfully created secure client')
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

            logger.info('Connecting to OPC UA server without security for discovery...')
            client.connect()

            server_info = self._gather_server_info(client)

            client.disconnect()

        except Exception as e:  # noqa: BLE001
            logger.warning('Failed to discover server: %s', e)
            return False, f'Discovery failed: {e}', None
        else:
            logger.info('Successfully discovered server information')
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
            logger.debug('Failed to get server name: %s', e)
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
            logger.info('Connecting to OPC UA server at %s', self.server_url)
            client.connect()
            logger.info('Connected successfully')

            trustlist_nodes = self._discover_trustlist_nodes(client)
            if not trustlist_nodes:
                return False, 'No TrustList nodes found on server'

            success_count = 0
            messages = []

            for node_info in trustlist_nodes:
                group_name = node_info['group_name']
                trustlist_node = node_info['trustlist_node']

                logger.info('Updating trustlist for group: %s', group_name)
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
            logger.exception('Failed to update trustlist')
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
            logger.info('Found %d certificate group(s)', len(groups))

            for group_node in groups:
                try:
                    group_name = group_node.get_browse_name().Name
                    trustlist_node = group_node.get_child('TrustList')

                    trustlist_nodes.append({
                        'group_name': group_name,
                        'group_node': group_node,
                        'trustlist_node': trustlist_node,
                    })
                    logger.info('Discovered TrustList for group: %s', group_name)

                except Exception as e:  # noqa: BLE001 - OPC UA node access can fail in various ways
                    logger.warning('Failed to get TrustList for group: %s', e)
                    continue

        except Exception:
            logger.exception('Failed to discover trustlist nodes')

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
            logger.info('Serialized TrustList: %d bytes', len(serialized_trustlist))

            # Step 1: Open
            mode = ua.TrustListMasks.All
            open_method = trustlist_node.get_child('Open')
            file_handle = trustlist_node.call_method(open_method, mode)
            logger.debug('Opened TrustList, handle: %s', file_handle)

            # Step 2: Write in chunks
            write_method = trustlist_node.get_child('Write')
            offset = 0
            chunk_count = 0

            while offset < len(serialized_trustlist):
                chunk = serialized_trustlist[offset:offset + max_chunk_size]
                trustlist_node.call_method(write_method, file_handle, chunk)
                offset += len(chunk)
                chunk_count += 1

            logger.debug('Wrote %d bytes in %d chunks', len(serialized_trustlist), chunk_count)

            # Step 3: CloseAndUpdate
            close_and_update_method = trustlist_node.get_child('CloseAndUpdate')
            apply_changes_required = trustlist_node.call_method(close_and_update_method, file_handle)
            logger.debug('Closed TrustList, ApplyChanges required: %s', apply_changes_required)

            # Step 4: ApplyChanges if required
            if apply_changes_required:
                logger.info('Applying changes server-wide')
                server_node = trustlist_node.get_parent().get_parent()
                apply_changes = server_node.get_child('ApplyChanges')
                server_node.call_method(apply_changes)

        except Exception:
            logger.exception('Failed to update trustlist')
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
            logger.info('Connecting to OPC UA server at %s', self.server_url)
            client.connect()
            logger.info('Connected successfully')

            # Discover certificate groups
            cert_groups = self._discover_certificate_groups(client)
            if not cert_groups:
                return False, 'No certificate groups found on server', None

            # Update certificate for each group (skip UserToken groups)
            success_count = 0
            messages = []
            issued_cert = None

            for group in cert_groups:
                group_name = group['name']

                # Skip UserToken groups
                if 'UserToken' in group_name:
                    logger.info('Skipping %s (user token group)', group_name)
                    continue

                logger.info('Updating certificate for group: %s', group_name)
                success, cert_bytes = self._update_single_certificate(
                    client=client,
                    certificate_group_id=group['node_id'],
                )

                if success:
                    success_count += 1
                    messages.append(f'✓ {group_name}')
                    if not issued_cert:
                        issued_cert = cert_bytes
                else:
                    messages.append(f'✗ {group_name}')

            client.disconnect()

            if success_count > 0:
                msg = (
                    f'Successfully updated {success_count}/{len(cert_groups)} '
                    f'certificate(s): {", ".join(messages)}'
                )
                return True, msg, issued_cert

        except Exception as e:
            logger.exception('Failed to update server certificate')
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
            logger.info('Found %d certificate group(s)', len(group_nodes))

            for group_node in group_nodes:
                try:
                    group_name = group_node.get_browse_name().Name
                    groups.append({
                        'name': group_name,
                        'node_id': group_node.nodeid,
                    })
                    logger.info('Discovered certificate group: %s', group_name)

                except Exception as e:  # noqa: BLE001 - OPC UA operations can fail in various ways
                    logger.warning('Failed to process group: %s', e)
                    continue

        except Exception:
            logger.exception('Failed to discover certificate groups')

        return groups

    def _update_single_certificate(
        self,
        client: Client,
        certificate_group_id: ua.NodeId,
        certificate_type_id: ua.NodeId | None = None,
    ) -> tuple[bool, bytes | None]:
        """Update certificate for a single certificate group.

        Args:
            client: Connected OPC UA client.
            certificate_group_id: NodeId of the certificate group.
            certificate_type_id: NodeId of certificate type.

        Returns:
            Tuple of (success: bool, certificate: bytes | None).
        """
        if certificate_type_id is None:
            certificate_type_id = CertificateTypes.APPLICATION_CERTIFICATE

        try:
            server_node = client.get_node('ns=0;i=2253')
            server_config = server_node.get_child('ServerConfiguration')

            # Step 1: CreateSigningRequest
            logger.info('Server generating CSR via CreateSigningRequest')
            create_signing_request = server_config.get_child('CreateSigningRequest')

            csr = server_config.call_method(
                create_signing_request,
                certificate_group_id,
                certificate_type_id,
                None,  # Let server generate subject
                True,  # Regenerate private key  # noqa: FBT003 - OPC UA library API requirement
                None   # No nonce
            )
            logger.info('CSR generated by server (%d bytes)', len(csr))

            # Step 2: Sign the CSR
            logger.info('Signing CSR with domain issuing CA')
            signed_cert, issuer_chain = self._sign_csr(csr)

            # Step 3: UpdateCertificate
            logger.info('Uploading signed certificate via UpdateCertificate')
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
            logger.info('Certificate uploaded, ApplyChanges required: %s', apply_changes_required)

            # Step 4: ApplyChanges if required
            if apply_changes_required:
                logger.info('Applying changes server-wide')
                apply_changes = server_config.get_child('ApplyChanges')
                server_config.call_method(apply_changes)

        except Exception:
            logger.exception('Failed to update certificate')
            return False, None
        else:
            return True, signed_cert

    def _sign_csr(self, csr_der: bytes) -> tuple[bytes, list[bytes]]:
        """Sign a Certificate Signing Request with domain's issuing CA.

        Args:
            csr_der: DER-encoded CSR.

        Returns:
            Tuple of (signed certificate DER, issuer chain as list of DER certs).

        Raises:
            GdsPushError: If signing fails.
        """
        try:
            # Load CSR
            csr = x509.load_der_x509_csr(csr_der)
            logger.info('CSR Subject: %s', csr.subject)

            # Get issuing CA
            if not self.device.domain:
                msg = 'Device has no domain configured'
                raise GdsPushError(msg)  # noqa: TRY301 - Validation error, not refactorable

            domain = self.device.domain
            issuing_ca = domain.issuing_ca
            if not issuing_ca:
                msg = 'Domain has no issuing CA configured'
                raise GdsPushError(msg)  # noqa: TRY301 - Validation error, not refactorable

            # Get CA certificate and key
            ca_cert_model = issuing_ca.ca_certificate_model
            ca_cert_crypto = ca_cert_model.get_certificate_serializer().as_crypto()

            credential = issuing_ca.credential
            if credential is None:
                msg = 'Issuing CA has no credential'
                raise GdsPushError(msg)  # noqa: TRY301 - Validation error, not refactorable

            ca_key = credential.get_private_key()

            logger.info('CA Issuer: %s', ca_cert_crypto.subject)

            # Build certificate
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(csr.subject)
            builder = builder.issuer_name(ca_cert_crypto.subject)
            builder = builder.public_key(csr.public_key())
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.not_valid_before(datetime.datetime.now(tz=datetime.UTC))
            builder = builder.not_valid_after(
                datetime.datetime.now(tz=datetime.UTC) + datetime.timedelta(days=365)
            )

            # Copy extensions from CSR
            for ext in csr.extensions:
                builder = builder.add_extension(ext.value, ext.critical)

            # Add BasicConstraints if not present
            try:
                csr.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            except x509.ExtensionNotFound:
                builder = builder.add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True
                )

            # Add KeyUsage if not present
            try:
                csr.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            except x509.ExtensionNotFound:
                builder = builder.add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=True,
                        content_commitment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False
                    ),
                    critical=True
                )

            # Sign certificate
            certificate = builder.sign(ca_key, hashes.SHA256())
            cert_der = certificate.public_bytes(serialization.Encoding.DER)

            logger.info('Certificate issued successfully (%d bytes)', len(cert_der))

            # Build issuer chain from CA hierarchy
            ca_chain = self._build_ca_chain()
            issuer_chain = []

            for ca in ca_chain:
                ca_cert = ca.ca_certificate_model.get_certificate_serializer().as_crypto()
                issuer_chain.append(ca_cert.public_bytes(encoding=serialization.Encoding.DER))

            logger.info('Issuer chain includes %d CA certificate(s)', len(issuer_chain))

        except Exception as e:
            msg = f'Failed to sign CSR: {e}'
            raise GdsPushError(msg) from e
        else:
            return cert_der, issuer_chain
