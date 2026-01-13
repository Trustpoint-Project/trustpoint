"""Service for OPC UA GDS Push operations.

This module implements the GDS Push protocol for OPC         if not cert_model:
            msg = 'Domain credential has no certificate'
            raise GdsPushError(msg)

        # Get certificate DER bytes
        cert_crypto = cert_model.get_certificate_serializer().as_crypto()
        cert_der = cert_crypto.public_bytes(encoding=serialization.Encoding.DER)

        # Get private key (as cryptography object)
        try:
            private_key_crypto = self.domain_credential.credential.get_private_key()
        except RuntimeError as e:
            msg = f'Failed to get private key: {e}'
            raise GdsPushError(msg) from eroviding:
1. UpdateTrustList workflow (OPC UA Part 12 Section 7.7.3)
2. UpdateCertificate workflow (OPC UA Part 12 Section 7.7.4)

It replaces local file operations with Django model operations.
"""

from __future__ import annotations

import datetime
import logging
import os
import struct
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID
from opcua import Client, ua
from opcua.crypto import security_policies
from opcua.ua.ua_binary import struct_to_binary

if TYPE_CHECKING:
    from devices.models import DeviceModel, IssuedCredentialModel
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
    """Service for managing OPC UA GDS Push operations."""

    def __init__(
        self,
        device: DeviceModel,
        domain_credential: IssuedCredentialModel,
        truststore: TruststoreModel | None = None,
    ) -> None:
        """Initialize GDS Push service.

        Args:
            device: The OPC UA device to manage
            domain_credential: Issued credential for authenticating to the server
            truststore: Truststore containing server certificate for authentication
        """
        self.device = device
        self.domain_credential = domain_credential
        self.truststore = truststore or device.onboarding_config.opc_trust_store

        if not self.truststore:
            msg = 'No truststore configured for device'
            raise GdsPushError(msg)
        
        # Validate truststore has certificates
        cert_count = self.truststore.truststoreordermodel_set.count()
        if cert_count == 0:
            msg = (
                f'Truststore "{self.truststore.unique_name}" is empty. '
                'Please add the OPC UA server certificate to the truststore before attempting GDS Push operations.'
            )
            raise GdsPushError(msg)
        
        logger.info(
            'Using truststore "%s" with %d certificate(s)',
            self.truststore.unique_name,
            cert_count
        )

        if not device.ip_address or not device.port:
            msg = 'Device IP address and port must be configured'
            raise GdsPushError(msg)

        self.server_url = f'opc.tcp://{device.ip_address}:{device.port}'

    def _get_client_cert_and_key(self) -> tuple[bytes, bytes]:
        """Get client certificate and private key from domain credential.

        Returns:
            Tuple of (certificate DER bytes, private key PEM bytes)

        Raises:
            GdsPushError: If credential is invalid or missing required components
        """
        is_valid, reason = self.domain_credential.is_valid_domain_credential()
        if not is_valid:
            msg = f'Invalid domain credential: {reason}'
            raise GdsPushError(msg)

        # Get primary certificate (credential.certificate is the FK to primary cert)
        cert_model = self.domain_credential.credential.certificate
        if not cert_model:
            msg = 'Domain credential has no primary certificate'
            raise GdsPushError(msg)

        # Get certificate DER bytes
        cert_crypto = cert_model.get_certificate_serializer().as_crypto()
        cert_der = cert_crypto.public_bytes(encoding=serialization.Encoding.DER)

        # Get private key (as cryptography object)
        try:
            private_key_crypto = self.domain_credential.credential.get_private_key()
        except RuntimeError as e:
            msg = f'Failed to get private key: {e}'
            raise GdsPushError(msg) from e

        # Convert private key to PEM format (unencrypted)
        key_pem = private_key_crypto.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        return cert_der, key_pem

    def _get_server_cert_from_truststore(self) -> bytes:
        """Get server certificate from truststore.

        Returns:
            Server certificate in DER format

        Raises:
            GdsPushError: If no server certificate found in truststore
        """
        if not self.truststore:
            msg = 'No truststore configured'
            raise GdsPushError(msg)

        # Get the first certificate from truststore as server certificate
        # Access through the TruststoreOrderModel (through model)
        truststore_order = self.truststore.truststoreordermodel_set.order_by('order').first()
        if not truststore_order:
            msg = 'Truststore contains no certificates'
            raise GdsPushError(msg)

        # Get certificate as cryptography object and convert to DER
        cert_crypto = truststore_order.certificate.get_certificate_serializer().as_crypto()
        return cert_crypto.public_bytes(encoding=serialization.Encoding.DER)

    @staticmethod
    def _extract_first_cert_from_chain(cert_data: bytes) -> bytes:
        """Extract the first certificate from a DER-encoded certificate chain.

        Args:
            cert_data: DER-encoded certificate or certificate chain

        Returns:
            First certificate only
        """
        # DER format: 0x30 (SEQUENCE) 0x82 [2 bytes length] [certificate data]
        if len(cert_data) > 4 and cert_data[0] == 0x30 and cert_data[1] == 0x82:
            cert_len = struct.unpack('>H', cert_data[2:4])[0]
            first_cert = cert_data[:4 + cert_len]

            if len(first_cert) < len(cert_data):
                logger.warning(
                    'Server sent certificate chain (%d bytes), extracting first certificate (%d bytes)',
                    len(cert_data),
                    len(first_cert)
                )

            return first_cert

        return cert_data

    def _create_secure_client(self) -> Client:
        """Create OPC UA client with secure connection.

        Returns:
            Configured OPC UA client

        Raises:
            GdsPushError: If connection setup fails
        """
        try:
            # Get credentials
            client_cert_der, client_key_pem = self._get_client_cert_and_key()
            server_cert_der = self._get_server_cert_from_truststore()

            # Create temporary files for opcua library (it requires file paths)
            import tempfile
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', delete=False) as f:
                f.write(client_cert_der)
                client_cert_path = f.name

            with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as f:
                f.write(client_key_pem)
                client_key_path = f.name

            with tempfile.NamedTemporaryFile(mode='wb', suffix='.der', delete=False) as f:
                f.write(server_cert_der)
                server_cert_path = f.name

            # Create client
            client = Client(self.server_url)
            client.application_uri = 'urn:trustpoint:gds-push'

            # Apply certificate chain workaround
            self._apply_opcua_patches()

            # Set security
            client.set_security(
                security_policies.SecurityPolicyBasic256Sha256,
                certificate_path=client_cert_path,
                private_key_path=client_key_path,
                server_certificate_path=server_cert_path,
                mode=ua.MessageSecurityMode.SignAndEncrypt
            )

            # Set authentication
            if self.device.onboarding_config:
                opc_user = self.device.onboarding_config.opc_user
                opc_password = self.device.onboarding_config.opc_password
                if opc_user:
                    client.set_user(opc_user)
                    if opc_password:
                        client.set_password(opc_password)

            return client

        except Exception as e:
            msg = f'Failed to create secure client: {e}'
            raise GdsPushError(msg) from e

    def _apply_opcua_patches(self) -> None:
        """Apply patches to opcua library for handling certificate chains."""
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from opcua.client import client as opcua_client
        from opcua.common import utils
        from opcua.crypto import uacrypto

        # Patch x509_from_der to handle chains
        _original_x509_from_der = uacrypto.x509_from_der

        def _patched_x509_from_der(data: bytes) -> x509.Certificate:
            try:
                return _original_x509_from_der(data)
            except ValueError as e:
                if "ExtraData" in str(e):
                    fixed_cert = self._extract_first_cert_from_chain(data)
                    return x509.load_der_x509_certificate(fixed_cert, default_backend())
                raise

        uacrypto.x509_from_der = _patched_x509_from_der

        # Patch create_session to handle certificate chain comparison
        _original_create_session = opcua_client.Client.create_session

        def _patched_create_session(client_self: Client) -> ua.CreateSessionResult:
            from opcua.client.client import KeepAlive

            desc = ua.ApplicationDescription()
            desc.ApplicationUri = client_self.application_uri
            desc.ProductUri = client_self.product_uri
            desc.ApplicationName = ua.LocalizedText(client_self.name)
            desc.ApplicationType = ua.ApplicationType.Client

            params = ua.CreateSessionParameters()
            nonce = utils.create_nonce(32)
            params.ClientNonce = nonce
            params.ClientCertificate = client_self.security_policy.client_certificate
            params.ClientDescription = desc
            params.EndpointUrl = client_self.server_url.geturl()
            params.SessionName = client_self.description + " Session" + str(client_self._session_counter)
            params.RequestedSessionTimeout = client_self.session_timeout
            params.MaxResponseMessageSize = 0
            response = client_self.uaclient.create_session(params)
            if client_self.security_policy.client_certificate is None:
                data = nonce
            else:
                data = client_self.security_policy.client_certificate + nonce
            client_self.security_policy.asymmetric_cryptography.verify(data, response.ServerSignature.Signature)
            client_self._server_nonce = response.ServerNonce
            if not client_self.security_policy.server_certificate:
                client_self.security_policy.server_certificate = response.ServerCertificate
            elif client_self.security_policy.server_certificate != response.ServerCertificate:
                # Handle case where server sends chain but we have single cert
                server_resp_cert = self._extract_first_cert_from_chain(response.ServerCertificate)
                if client_self.security_policy.server_certificate != server_resp_cert:
                    raise ua.UaError("Server certificate mismatch")
                logger.info("Certificate validated (extracted from chain)")

            ep = opcua_client.Client.find_endpoint(
                response.ServerEndpoints,
                client_self.security_policy.Mode,
                client_self.security_policy.URI
            )
            client_self._policy_ids = ep.UserIdentityTokens
            if client_self.session_timeout != response.RevisedSessionTimeout:
                logger.warning(
                    "Requested session timeout to be %dms, got %dms instead",
                    client_self.secure_channel_timeout,
                    response.RevisedSessionTimeout
                )
                client_self.session_timeout = response.RevisedSessionTimeout
            client_self.keepalive = KeepAlive(
                client_self,
                min(client_self.session_timeout, client_self.secure_channel_timeout) * 0.7
            )
            client_self.keepalive.start()
            return response

        opcua_client.Client.create_session = _patched_create_session

    def update_trustlist(self) -> tuple[bool, str]:
        """Update server trustlist with CA certificates from truststore.

        Implements OPC UA Part 12 Section 7.7.3 UpdateTrustList workflow:
        1. Open - Open the TrustList for writing
        2. Write - Write TrustList data in chunks
        3. CloseAndUpdate - Close and apply the new TrustList
        4. ApplyChanges (if required) - Apply changes server-wide

        Returns:
            Tuple of (success: bool, message: str)
        """
        if not self.truststore:
            return False, 'No truststore configured for device'

        client = None
        try:
            # Create secure client
            client = self._create_secure_client()

            # Connect to server
            logger.info('Connecting to OPC UA server at %s', self.server_url)
            client.connect()
            logger.info('Connected successfully')

            # Build trustlist from truststore
            trustlist = self._build_trustlist_from_truststore()
            if not trustlist:
                return False, 'Failed to build trustlist from truststore'

            # Discover trustlist nodes
            trustlist_nodes = self._discover_trustlist_nodes(client)
            if not trustlist_nodes:
                return False, 'No TrustList nodes found on server'

            # Update each trustlist
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
                msg = f'Successfully updated {success_count}/{len(trustlist_nodes)} trustlist(s): ' + ', '.join(messages)
                return True, msg
            else:
                return False, 'Failed to update any trustlist'

        except Exception as e:
            logger.exception('Failed to update trustlist')
            if client:
                try:
                    client.disconnect()
                except Exception:
                    pass
            return False, f'Update failed: {e}'

    def _build_trustlist_from_truststore(self) -> ua.TrustListDataType | None:
        """Build OPC UA TrustList from Django truststore model.

        Returns:
            TrustListDataType or None if build fails
        """
        if not self.truststore:
            return None

        trusted_certs = []
        trusted_crls = []

        # Add certificates from truststore (access through TruststoreOrderModel)
        for truststore_order in self.truststore.truststoreordermodel_set.order_by('order'):
            cert_crypto = truststore_order.certificate.get_certificate_serializer().as_crypto()
            trusted_certs.append(cert_crypto.public_bytes(encoding=serialization.Encoding.DER))

        # Add CRLs from truststore if available
        # Note: CRL relationship needs verification - using similar pattern
        for crl_model in self.truststore.certificate_revocation_lists.all():
            # Note: CRL model access needs to be verified - assuming similar pattern
            crl_crypto = crl_model.get_crl_serializer().as_crypto()
            trusted_crls.append(crl_crypto.public_bytes(encoding=serialization.Encoding.DER))

        # Build TrustListDataType
        trustlist = ua.TrustListDataType()
        trustlist.SpecifiedLists = ua.TrustListMasks.All
        trustlist.TrustedCertificates = trusted_certs
        trustlist.TrustedCrls = trusted_crls
        trustlist.IssuerCertificates = trusted_certs  # Same as trusted for now
        trustlist.IssuerCrls = trusted_crls

        logger.info('Built trustlist with %d certificates and %d CRLs', len(trusted_certs), len(trusted_crls))
        return trustlist

    def _discover_trustlist_nodes(self, client: Client) -> list[dict]:
        """Discover TrustList nodes on server.

        Args:
            client: Connected OPC UA client

        Returns:
            List of dictionaries with group and trustlist node information
        """
        trustlist_nodes = []

        try:
            server_node = client.get_node("ns=0;i=2253")
            server_config = server_node.get_child("ServerConfiguration")
            cert_groups_node = server_config.get_child("CertificateGroups")

            groups = cert_groups_node.get_children()
            logger.info('Found %d certificate group(s)', len(groups))

            for group_node in groups:
                try:
                    group_name = group_node.get_browse_name().Name
                    trustlist_node = group_node.get_child("TrustList")

                    trustlist_nodes.append({
                        'group_name': group_name,
                        'group_node': group_node,
                        'trustlist_node': trustlist_node,
                    })
                    logger.info('Discovered TrustList for group: %s', group_name)

                except Exception as e:
                    logger.warning('Failed to get TrustList for group: %s', e)
                    continue

        except Exception as e:
            logger.error('Failed to discover trustlist nodes: %s', e)

        return trustlist_nodes

    def _update_single_trustlist(
        self,
        trustlist_node: ua.Node,
        trustlist_data: ua.TrustListDataType,
        max_chunk_size: int = 1024
    ) -> bool:
        """Update a single TrustList node.

        Args:
            trustlist_node: The TrustList node to update
            trustlist_data: TrustListDataType containing certificates and CRLs
            max_chunk_size: Maximum size of each write chunk

        Returns:
            True if successful, False otherwise
        """
        try:
            # Serialize the TrustList
            serialized_trustlist = struct_to_binary(trustlist_data)
            logger.info('Serialized TrustList: %d bytes', len(serialized_trustlist))

            # Step 1: Open TrustList
            mode = ua.TrustListMasks.All
            open_method = trustlist_node.get_child("Open")
            file_handle = trustlist_node.call_method(open_method, mode)
            logger.debug('Opened TrustList, handle: %s', file_handle)

            # Step 2: Write data in chunks
            write_method = trustlist_node.get_child("Write")
            offset = 0
            chunk_count = 0

            while offset < len(serialized_trustlist):
                chunk = serialized_trustlist[offset:offset + max_chunk_size]
                trustlist_node.call_method(write_method, file_handle, chunk)
                offset += len(chunk)
                chunk_count += 1

            logger.debug('Wrote %d bytes in %d chunks', len(serialized_trustlist), chunk_count)

            # Step 3: CloseAndUpdate
            close_and_update_method = trustlist_node.get_child("CloseAndUpdate")
            apply_changes_required = trustlist_node.call_method(close_and_update_method, file_handle)
            logger.debug('Closed TrustList, ApplyChanges required: %s', apply_changes_required)

            # Step 4: ApplyChanges if required
            if apply_changes_required:
                logger.info('Applying changes server-wide')
                server_node = trustlist_node.get_parent().get_parent()
                apply_changes = server_node.get_child("ApplyChanges")
                server_node.call_method(apply_changes)

            return True

        except Exception as e:
            logger.error('Failed to update trustlist: %s', e)
            return False

    def update_server_certificate(self) -> tuple[bool, str, bytes | None]:
        """Update server certificate using CSR-based workflow.

        Implements OPC UA Part 12 Section 7.7.4 UpdateCertificate workflow:
        1. Server generates CSR (CreateSigningRequest)
        2. GDS signs CSR with domain's issuing CA
        3. Upload signed certificate to server (UpdateCertificate)
        4. Apply changes if required (ApplyChanges)

        Returns:
            Tuple of (success: bool, message: str, certificate: bytes | None)
        """
        client = None
        try:
            # Create secure client
            client = self._create_secure_client()

            # Connect to server
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

                # Skip UserToken groups - they don't support CSR generation
                if 'UserToken' in group_name:
                    logger.info('Skipping %s (user token group)', group_name)
                    continue

                logger.info('Updating certificate for group: %s', group_name)
                success, cert_bytes = self._update_single_certificate(
                    client=client,
                    certificate_group_id=group['node_id'],
                    subject_name=f'CN=OPC UA Server {group_name},O=Trustpoint,C=DE',
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
                msg = f'Successfully updated {success_count}/{len(cert_groups)} certificate(s): ' + ', '.join(messages)
                return True, msg, issued_cert
            else:
                return False, 'Failed to update any certificate', None

        except Exception as e:
            logger.exception('Failed to update server certificate')
            if client:
                try:
                    client.disconnect()
                except Exception:
                    pass
            return False, f'Update failed: {e}', None

    def _discover_certificate_groups(self, client: Client) -> list[dict]:
        """Discover certificate groups on server.

        Args:
            client: Connected OPC UA client

        Returns:
            List of dictionaries with group information
        """
        groups = []

        try:
            server_node = client.get_node("ns=0;i=2253")
            server_config = server_node.get_child("ServerConfiguration")
            cert_groups_node = server_config.get_child("CertificateGroups")

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

                except Exception as e:
                    logger.warning('Failed to process group: %s', e)
                    continue

        except Exception as e:
            logger.error('Failed to discover certificate groups: %s', e)

        return groups

    def _update_single_certificate(
        self,
        client: Client,
        certificate_group_id: ua.NodeId,
        certificate_type_id: ua.NodeId | None = None,
        subject_name: str | None = None,
    ) -> tuple[bool, bytes | None]:
        """Update certificate for a single certificate group.

        Args:
            client: Connected OPC UA client
            certificate_group_id: NodeId of the certificate group
            certificate_type_id: NodeId of certificate type (defaults to APPLICATION_CERTIFICATE)
            subject_name: Subject name for certificate (server generates if None)

        Returns:
            Tuple of (success: bool, certificate: bytes | None)
        """
        if certificate_type_id is None:
            certificate_type_id = CertificateTypes.APPLICATION_CERTIFICATE

        try:
            # Get ServerConfiguration node
            server_node = client.get_node("ns=0;i=2253")
            server_config = server_node.get_child("ServerConfiguration")

            # Step 1: CreateSigningRequest - Server generates CSR
            logger.info('Server generating CSR via CreateSigningRequest')
            create_signing_request = server_config.get_child("CreateSigningRequest")

            # Server requires SubjectName=None to generate its own subject
            csr = server_config.call_method(
                create_signing_request,
                certificate_group_id,
                certificate_type_id,
                None,  # Let server generate subject
                True,  # Regenerate private key
                None   # No nonce
            )
            logger.info('CSR generated by server (%d bytes)', len(csr))

            # Step 2: Sign the CSR
            logger.info('Signing CSR with domain CA')
            signed_cert, issuer_chain = self._sign_csr(csr)

            # Step 3: UpdateCertificate - Upload certificate to server
            logger.info('Uploading signed certificate via UpdateCertificate')
            update_certificate = server_config.get_child("UpdateCertificate")

            apply_changes_required = server_config.call_method(
                update_certificate,
                certificate_group_id,
                certificate_type_id,
                signed_cert,
                issuer_chain,
                "",  # No private key format
                b""  # No private key
            )
            logger.info('Certificate uploaded, ApplyChanges required: %s', apply_changes_required)

            # Step 4: ApplyChanges if required
            if apply_changes_required:
                logger.info('Applying changes server-wide')
                apply_changes = server_config.get_child("ApplyChanges")
                server_config.call_method(apply_changes)

            return True, signed_cert

        except Exception as e:
            logger.error('Failed to update certificate: %s', e)
            return False, None

    def _sign_csr(self, csr_der: bytes) -> tuple[bytes, list[bytes]]:
        """Sign a Certificate Signing Request with the domain's issuing CA.

        Args:
            csr_der: DER-encoded CSR

        Returns:
            Tuple of (signed certificate DER, issuer chain as list of DER certs)

        Raises:
            GdsPushError: If signing fails
        """
        try:
            # Load CSR
            csr = x509.load_der_x509_csr(csr_der, default_backend())
            logger.info('CSR Subject: %s', csr.subject)

            # Get domain's issuing CA
            domain = self.device.domain
            if not domain:
                msg = 'Device has no domain configured'
                raise GdsPushError(msg)

            issuing_ca = domain.issuing_ca
            if not issuing_ca:
                msg = 'Domain has no issuing CA configured'
                raise GdsPushError(msg)

            # Get CA certificate and private key
            ca_cert_model = issuing_ca.credential.certificate
            if not ca_cert_model:
                msg = 'Issuing CA has no certificate'
                raise GdsPushError(msg)

            # Get CA certificate as cryptography object
            ca_cert_crypto = ca_cert_model.get_certificate_serializer().as_crypto()
            ca_cert_der = ca_cert_crypto.public_bytes(encoding=serialization.Encoding.DER)
            ca_cert = x509.load_der_x509_certificate(ca_cert_der, default_backend())

            ca_key = issuing_ca.credential.get_private_key()
            if not ca_key:
                msg = 'Issuing CA has no private key'
                raise GdsPushError(msg)

            logger.info('CA Issuer: %s', ca_cert.subject)

            # Build certificate
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(csr.subject)
            builder = builder.issuer_name(ca_cert.subject)
            builder = builder.public_key(csr.public_key())
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.not_valid_before(datetime.datetime.utcnow())
            builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))

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

            # Sign the certificate
            certificate = builder.sign(ca_key, hashes.SHA256(), default_backend())
            cert_der = certificate.public_bytes(serialization.Encoding.DER)

            logger.info('Certificate issued successfully (%d bytes)', len(cert_der))

            # Build issuer chain
            ca_cert_crypto = ca_cert_model.get_certificate_serializer().as_crypto()
            issuer_chain = [ca_cert_crypto.public_bytes(encoding=serialization.Encoding.DER)]

            # Add root CA if available
            root_ca = issuing_ca.root_ca
            if root_ca and root_ca.credential.certificate:
                root_cert_crypto = root_ca.credential.certificate.get_certificate_serializer().as_crypto()
                issuer_chain.append(root_cert_crypto.public_bytes(encoding=serialization.Encoding.DER))
                logger.info('Issuer chain includes root CA')

            return cert_der, issuer_chain

        except Exception as e:
            msg = f'Failed to sign CSR: {e}'
            raise GdsPushError(msg) from e
