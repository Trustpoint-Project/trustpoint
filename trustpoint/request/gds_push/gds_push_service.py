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
from django.db import models
from opcua import Client, ua
from opcua.crypto import security_policies
from opcua.ua.ua_binary import struct_to_binary

if TYPE_CHECKING:
    from devices.models import DeviceModel, IssuedCredentialModel
    from pki.models import IssuingCaModel
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
        domain_credential: IssuedCredentialModel | None = None,
        truststore: TruststoreModel | None = None,
    ) -> None:
        """Initialize GDS Push service.

        Args:
            device: The OPC UA device to manage
            domain_credential: Issued credential for authenticating to the server (optional for insecure operations)
            truststore: Truststore containing server certificate for authentication
        """
        self.device = device
        self.domain_credential = domain_credential
        
        # Get truststore from parameter, or from device onboarding config if available
        if truststore is not None:
            self.truststore = truststore
        elif device.onboarding_config and device.onboarding_config.opc_trust_store:
            self.truststore = device.onboarding_config.opc_trust_store
        else:
            self.truststore = None

        # Only require truststore for secure operations
        if domain_credential:
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
        else:
            logger.info('Initializing for insecure operations (no domain credential required)')

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

            # DEBUG: Log certificate details
            logger.info('=== SECURE CONNECTION DEBUG INFO ===')
            
            # Parse and log client certificate
            try:
                client_cert = x509.load_der_x509_certificate(client_cert_der, default_backend())
                logger.info('Client Certificate:')
                logger.info('  Subject: %s', client_cert.subject)
                logger.info('  Issuer: %s', client_cert.issuer)
                logger.info('  Serial: %s', client_cert.serial_number)
                logger.info('  Valid from: %s', client_cert.not_valid_before)
                logger.info('  Valid to: %s', client_cert.not_valid_after)
                logger.info('  Fingerprint (SHA256): %s', client_cert.fingerprint(hashes.SHA256()).hex())
                logger.info('  Size: %d bytes', len(client_cert_der))
                
                # Log certificate extensions (critical for OPC UA)
                logger.info('  Extensions:')
                for ext in client_cert.extensions:
                    logger.info('    - %s (critical=%s)', ext.oid._name, ext.critical)
                    if ext.oid._name == 'keyUsage':
                        ku = ext.value
                        logger.info('      Key Usage: digitalSignature=%s, keyEncipherment=%s, dataEncipherment=%s',
                                  ku.digital_signature, ku.key_encipherment, ku.data_encipherment)
                    elif ext.oid._name == 'extendedKeyUsage':
                        eku = ext.value
                        logger.info('      Extended Key Usage: %s', [oid._name for oid in eku])
                    elif ext.oid._name == 'subjectAltName':
                        san = ext.value
                        logger.info('      Subject Alt Names:')
                        for name in san:
                            logger.info('        %s: %s', type(name).__name__, name.value)
                
                if not any(ext.oid._name == 'subjectAltName' for ext in client_cert.extensions):
                    logger.warning('      ⚠ WARNING: No Subject Alternative Name (SAN) extension found!')
                    logger.warning('      OPC UA requires SAN with URI matching application URI')
                
            except Exception as e:
                logger.error('Failed to parse client certificate: %s', e)
            
            # Log client key info
            try:
                from cryptography.hazmat.primitives.serialization import load_pem_private_key
                client_key = load_pem_private_key(client_key_pem, password=None, backend=default_backend())
                logger.info('Client Private Key:')
                logger.info('  Key type: %s', type(client_key).__name__)
                logger.info('  Key size: %d bits', client_key.key_size)
                logger.info('  Size: %d bytes', len(client_key_pem))
            except Exception as e:
                logger.error('Failed to parse client private key: %s', e)
            
            # Parse and log server certificate from truststore
            try:
                server_cert = x509.load_der_x509_certificate(server_cert_der, default_backend())
                logger.info('Server Certificate (from truststore):')
                logger.info('  Subject: %s', server_cert.subject)
                logger.info('  Issuer: %s', server_cert.issuer)
                logger.info('  Serial: %s', server_cert.serial_number)
                logger.info('  Valid from: %s', server_cert.not_valid_before)
                logger.info('  Valid to: %s', server_cert.not_valid_after)
                logger.info('  Fingerprint (SHA256): %s', server_cert.fingerprint(hashes.SHA256()).hex())
                logger.info('  Size: %d bytes', len(server_cert_der))
            except Exception as e:
                logger.error('Failed to parse server certificate: %s', e)
            
            # Log username/password authentication
            if self.device.onboarding_config:
                opc_user = self.device.onboarding_config.opc_user
                opc_password = self.device.onboarding_config.opc_password
                logger.info('Username/Password Authentication:')
                logger.info('  Username: %s', opc_user if opc_user else '(not set)')
                logger.info('  Password: %s', '***' if opc_password else '(not set)')
            else:
                logger.info('Username/Password Authentication: No onboarding_config')
            
            logger.info('Connection Details:')
            logger.info('  Server URL: %s', self.server_url)
            logger.info('  Application URI: urn:trustpoint:gds-push')
            logger.info('  Security Policy: Basic256Sha256')
            logger.info('  Security Mode: SignAndEncrypt')
            logger.info('====================================')

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

            logger.info('Temporary certificate files created:')
            logger.info('  Client cert: %s', client_cert_path)
            logger.info('  Client key: %s', client_key_path)
            logger.info('  Server cert: %s', server_cert_path)

            # Create client
            client = Client(self.server_url)
            client.application_uri = 'urn:trustpoint:gds-push'
            
            # Set timeouts (in milliseconds)
            client.secure_channel_timeout = 30000  # 30 seconds for secure channel
            client.session_timeout = 60000  # 60 seconds for session

            # Apply certificate chain workaround
            self._apply_opcua_patches()

            # Set security
            logger.info('Setting security policy...')
            client.set_security(
                security_policies.SecurityPolicyBasic256Sha256,
                certificate_path=client_cert_path,
                private_key_path=client_key_path,
                server_certificate_path=server_cert_path,
                mode=ua.MessageSecurityMode.SignAndEncrypt
            )
            logger.info('Security policy set successfully')

            # Set authentication
            if self.device.onboarding_config:
                opc_user = self.device.onboarding_config.opc_user
                opc_password = self.device.onboarding_config.opc_password
                if opc_user:
                    logger.info('Setting username authentication...')
                    client.set_user(opc_user)
                    if opc_password:
                        client.set_password(opc_password)
                        logger.info('Password set')

            return client

        except Exception as e:
            msg = f'Failed to create secure client: {e}'
            raise GdsPushError(msg) from e

    def _get_server_certificate_insecurely(self) -> bytes | None:
        """Get server certificate using insecure connection.

        Returns:
            Server certificate in DER format, or None if failed
        """
        from opcua import ua
        client = None
        try:
            # Create client with no security
            client = Client(self.server_url)
            client.application_uri = 'urn:trustpoint:gds-push'
            
            # Connect without security (don't set any security policy)
            logger.info('Connecting without security to get server certificate...')
            client.connect()
            
            # Get server certificate from endpoints
            endpoints = client.get_endpoints()
            
            # Log all available endpoints for debugging
            logger.info('Found %d endpoint(s)', len(endpoints))
            for i, ep in enumerate(endpoints):
                logger.debug(
                    'Endpoint %d: URL=%s, SecurityPolicy=%s, SecurityMode=%s, HasCert=%s',
                    i, ep.EndpointUrl, ep.SecurityPolicyUri, ep.SecurityMode, bool(ep.ServerCertificate)
                )
            
            # Try to find endpoint with matching URL first
            for endpoint in endpoints:
                if endpoint.EndpointUrl == self.server_url and endpoint.ServerCertificate:
                    logger.info('Found server certificate from matching endpoint URL')
                    return endpoint.ServerCertificate
            
            # If no exact match, try to find any secure endpoint with a certificate
            for endpoint in endpoints:
                if endpoint.ServerCertificate and endpoint.SecurityPolicyUri:
                    # Skip None/unsecured endpoints, look for Basic256Sha256 or similar
                    if 'None' not in endpoint.SecurityPolicyUri:
                        logger.info(
                            'Found server certificate from secure endpoint: %s (Policy: %s)',
                            endpoint.EndpointUrl, endpoint.SecurityPolicyUri
                        )
                        return endpoint.ServerCertificate
            
            # Last resort: return any certificate found
            for endpoint in endpoints:
                if endpoint.ServerCertificate:
                    logger.warning(
                        'Using certificate from endpoint with policy: %s',
                        endpoint.SecurityPolicyUri
                    )
                    return endpoint.ServerCertificate
                        
            logger.warning('Could not get server certificate from endpoints')
            return None
            
        except Exception as e:
            logger.warning('Failed to get server certificate insecurely: %s', e)
        finally:
            if client:
                try:
                    client.disconnect()
                except Exception:
                    pass
        
        return None

    def _update_truststore_server_cert(self, server_cert_der: bytes) -> None:
        """Update the truststore with the correct server certificate.

        Args:
            server_cert_der: Server certificate in DER format
        """
        if not self.truststore:
            return
            
        try:
            # Parse the new certificate to check if it already exists
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            new_cert = x509.load_der_x509_certificate(server_cert_der, default_backend())
            new_cert_fingerprint = new_cert.fingerprint(hashes.SHA256()).hex()
            
            # Check if this certificate already exists in the truststore
            for truststore_order in self.truststore.truststoreordermodel_set.all():
                existing_cert = truststore_order.certificate.get_certificate_serializer().as_crypto()
                existing_fingerprint = existing_cert.fingerprint(hashes.SHA256()).hex()
                
                if existing_fingerprint == new_cert_fingerprint:
                    logger.info('Server certificate already exists in truststore, no update needed')
                    return
            
            # Certificate doesn't exist, add it to the truststore
            from pki.models import CertificateModel
            cert_model = CertificateModel.from_der_bytes(server_cert_der)
            cert_model.save()
            
            # Get the next order number
            max_order = self.truststore.truststoreordermodel_set.aggregate(
                max_order=models.Max('order')
            )['max_order']
            next_order = (max_order or 0) + 1
            
            # Add to truststore
            from pki.models import TruststoreOrderModel
            TruststoreOrderModel.objects.create(
                truststore=self.truststore,
                certificate=cert_model,
                order=next_order
            )
            
            logger.info('Added new server certificate to truststore at order %d', next_order)
            
        except Exception as e:
            logger.error('Failed to update truststore server certificate: %s', e)

    def discover_server_insecurely(self) -> tuple[bool, str, dict | None]:
        """Discover OPC UA server information without authentication.

        Returns:
            Tuple of (success: bool, message: str, server_info: dict | None)
        """
        from opcua import ua
        client = None
        try:
            # Create client with no security
            client = Client(self.server_url)
            client.application_uri = 'urn:trustpoint:gds-push'
            
            # Set timeouts for discovery (shorter timeout since it's just discovery)
            client.secure_channel_timeout = 10000  # 10 seconds
            client.session_timeout = 20000  # 20 seconds
            
            # Connect without security (don't set any security policy)
            logger.info('Connecting to OPC UA server without security for discovery...')
            client.connect()
            
            # Get server information
            server_info = {}
            
            # Get endpoints
            endpoints = client.get_endpoints()
            server_info['endpoints'] = []
            for endpoint in endpoints:
                endpoint_info = {
                    'url': endpoint.EndpointUrl,
                    'security_policy': endpoint.SecurityPolicyUri,
                    'security_mode': str(endpoint.SecurityMode),
                    'transport_profile': endpoint.TransportProfileUri,
                    'has_server_cert': bool(endpoint.ServerCertificate),
                }
                server_info['endpoints'].append(endpoint_info)
            
            # Get server description
            server_node = client.get_node("ns=0;i=2253")  # Server object
            server_info['server_name'] = str(server_node.get_browse_name().Name)
            
            # Get server status
            try:
                server_status_node = server_node.get_child("ServerStatus")
                server_info['server_status'] = 'Available'
            except Exception:
                server_info['server_status'] = 'Unknown'
            
            # Get server certificate if available - use flexible matching
            server_cert = None
            
            # Try exact URL match first
            for endpoint in endpoints:
                if endpoint.EndpointUrl == self.server_url and endpoint.ServerCertificate:
                    server_cert = endpoint.ServerCertificate
                    logger.info('Found certificate from exact URL match')
                    break
            
            # If no exact match, try secure endpoints
            if not server_cert:
                for endpoint in endpoints:
                    if endpoint.ServerCertificate and endpoint.SecurityPolicyUri:
                        if 'None' not in endpoint.SecurityPolicyUri:
                            server_cert = endpoint.ServerCertificate
                            logger.info(
                                'Found certificate from secure endpoint: %s (Policy: %s)',
                                endpoint.EndpointUrl, endpoint.SecurityPolicyUri
                            )
                            break
            
            # Last resort: any certificate
            if not server_cert:
                for endpoint in endpoints:
                    if endpoint.ServerCertificate:
                        server_cert = endpoint.ServerCertificate
                        logger.info('Found certificate from endpoint: %s', endpoint.EndpointUrl)
                        break
            
            if server_cert:
                server_info['server_certificate_available'] = True
                server_info['server_certificate_size'] = len(server_cert)
                
                # Try to parse certificate (handle potential chains)
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    
                    # Extract first cert from potential chain
                    server_cert_single = self._extract_first_cert_from_chain(server_cert)
                    cert = x509.load_der_x509_certificate(server_cert_single, default_backend())
                    
                    server_info['server_certificate_subject'] = str(cert.subject)
                    server_info['server_certificate_issuer'] = str(cert.issuer)
                    server_info['server_certificate_valid_from'] = cert.not_valid_before.isoformat()
                    server_info['server_certificate_valid_to'] = cert.not_valid_after.isoformat()
                    
                    # Indicate if it was a chain
                    if len(server_cert_single) < len(server_cert):
                        server_info['server_certificate_was_chain'] = True
                        server_info['server_certificate_chain_size'] = len(server_cert)
                    
                    # Check if certificate exists in truststore
                    server_cert_fingerprint = cert.fingerprint(hashes.SHA256()).hex()
                    server_info['server_certificate_fingerprint'] = server_cert_fingerprint
                    
                    if self.truststore:
                        truststore_match = False
                        truststore_certs = []
                        
                        for truststore_order in self.truststore.truststoreordermodel_set.all():
                            existing_cert = truststore_order.certificate.get_certificate_serializer().as_crypto()
                            existing_fingerprint = existing_cert.fingerprint(hashes.SHA256()).hex()
                            truststore_certs.append({
                                'order': truststore_order.order,
                                'fingerprint': existing_fingerprint,
                                'subject': str(existing_cert.subject)
                            })
                            
                            if existing_fingerprint == server_cert_fingerprint:
                                truststore_match = True
                                server_info['truststore_match_order'] = truststore_order.order
                        
                        server_info['truststore_contains_server_cert'] = truststore_match
                        server_info['truststore_certificate_count'] = len(truststore_certs)
                        server_info['truststore_certificates'] = truststore_certs
                        
                        if truststore_match:
                            logger.info('✓ Server certificate matches certificate in truststore')
                        else:
                            logger.warning('✗ Server certificate NOT found in truststore - secure connection may fail')
                    else:
                        server_info['truststore_contains_server_cert'] = None
                        server_info['truststore_note'] = 'No truststore configured'
                        
                except Exception as e:
                    logger.warning('Failed to parse server certificate: %s', e)
                    server_info['server_certificate_parse_error'] = str(e)
            else:
                server_info['server_certificate_available'] = False
            
            logger.info('Successfully discovered server information')
            logger.info(server_info)
            return True, 'Server discovered successfully', server_info
            
        except Exception as e:
            logger.warning('Failed to discover server insecurely: %s', e)
            return False, f'Discovery failed: {e}', None
        finally:
            if client:
                try:
                    client.disconnect()
                except Exception:
                    pass

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
            params.EndpointUrl = (
                client_self.server_url.geturl() 
                if hasattr(client_self.server_url, 'geturl') 
                else client_self.server_url
            )
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

            # Try to connect to server
            logger.info('=== ATTEMPTING SECURE CONNECTION ===')
            logger.info('Connecting to OPC UA server at %s', self.server_url)
            try:
                client.connect()
                logger.info('✓ Connected successfully!')
                logger.info('====================================')
            except Exception as connect_error:
                logger.error('✗ Secure connection failed!')
                logger.error('Error type: %s', type(connect_error).__name__)
                logger.error('Error message: %s', connect_error)
                logger.error('====================================')
                
                # Check if it's a security-related error
                error_str = str(connect_error).lower()
                if 'badsecuritychecksfailed' in error_str or 'security' in error_str:
                    logger.error('⚠ SECURITY ERROR DETECTED!')
                    logger.error('This typically means one of the following:')
                    logger.error('  1. Client certificate not trusted by server')
                    logger.error('  2. Server certificate mismatch')
                    logger.error('  3. Username/password incorrect')
                    logger.error('  4. Certificate/key mismatch')
                
                logger.info('Attempting to get server certificate with insecure connection...')
                
                # Try to get server certificate insecurely
                server_cert_der = self._get_server_certificate_insecurely()
                if server_cert_der:
                    # Update truststore with correct server certificate
                    #self._update_truststore_server_cert(server_cert_der)
                    #logger.info('Updated truststore with server certificate, retrying secure connection...')
                    
                    # Clean up old client and create new one with updated cert
                    if client:
                        try:
                            client.disconnect()
                        except:
                            pass
                        client = None
                    
                    client = self._create_secure_client()
                    client.connect()
                    logger.info('Connected successfully after certificate update')
                else:
                    raise connect_error

            # Build trustlist from domain's Issuing CA
            trustlist = self._build_trustlist_from_domain_issuing_ca()
            if not trustlist:
                return False, 'Failed to build trustlist from Issuing CA'

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

    def _build_trustlist_from_domain_issuing_ca(self) -> ua.TrustListDataType | None:
        """Build OPC UA TrustList from the domain's Issuing CA certificate chain and CRLs.
        
        The trustlist tells the OPC UA server which CAs to trust for client authentication.
        It includes:
        - Issuing CA certificate
        - Root CA certificate (chain)
        - CRL from the Issuing CA

        Returns:
            TrustListDataType or None if build fails
        """
        if not self.domain_credential or not self.domain_credential.domain:
            logger.error('Cannot build trustlist: no domain credential or domain')
            return None

        domain = self.domain_credential.domain
        
        # Get the Issuing CA for this domain
        if not hasattr(domain, 'issuing_ca') or not domain.issuing_ca:
            logger.error('Domain %s has no Issuing CA configured', domain.unique_name)
            return None

        issuing_ca = domain.issuing_ca
        logger.info('Building trustlist from Issuing CA: %s', issuing_ca.unique_name)

        trusted_certs = []
        trusted_crls = []
        issuer_certs = []
        issuer_crls = []

        try:
            # Get Issuing CA certificate
            issuing_ca_cert = issuing_ca.credential.certificate.get_certificate_serializer().as_crypto()
            issuing_ca_cert_der = issuing_ca_cert.public_bytes(encoding=serialization.Encoding.DER)
            trusted_certs.append(issuing_ca_cert_der)
            issuer_certs.append(issuing_ca_cert_der)  # Also add to issuer certs
            logger.info('Added Issuing CA certificate: %s', issuing_ca_cert.subject.rfc4514_string())

            # Get complete certificate chain from the Issuing CA's credential
            # This includes Root CA and any intermediate CAs
            certificate_chain = issuing_ca.credential.get_certificate_chain()
            if certificate_chain:
                for chain_cert in certificate_chain:
                    chain_cert_der = chain_cert.public_bytes(encoding=serialization.Encoding.DER)
                    # Add to both trusted and issuer certificates so server has complete chain
                    trusted_certs.append(chain_cert_der)
                    issuer_certs.append(chain_cert_der)
                    logger.info('Added chain certificate: %s', chain_cert.subject.rfc4514_string())
            else:
                logger.warning('Issuing CA has no certificate chain (self-signed root)')

            # Get CRL from Issuing CA
            if issuing_ca.crl_pem:
                crl_crypto = x509.load_pem_x509_crl(issuing_ca.crl_pem.encode(), default_backend())
                crl_der = crl_crypto.public_bytes(encoding=serialization.Encoding.DER)
                trusted_crls.append(crl_der)
                issuer_crls.append(crl_der)
                logger.info('Added CRL from Issuing CA: %s', issuing_ca.unique_name)
            else:
                logger.warning('Issuing CA %s has no CRL', issuing_ca.unique_name)

            # Build TrustListDataType
            trustlist = ua.TrustListDataType()
            trustlist.SpecifiedLists = ua.TrustListMasks.All
            trustlist.TrustedCertificates = trusted_certs
            trustlist.TrustedCrls = trusted_crls
            trustlist.IssuerCertificates = issuer_certs if issuer_certs else trusted_certs
            trustlist.IssuerCrls = issuer_crls if issuer_crls else trusted_crls

            logger.info(
                'Built trustlist with %d trusted certs, %d issuer certs, %d trusted CRLs, %d issuer CRLs',
                len(trusted_certs), len(issuer_certs), len(trusted_crls), len(issuer_crls)
            )
            return trustlist

        except (models.ObjectDoesNotExist, ValueError, AttributeError) as e:
            logger.error('Failed to build trustlist from Issuing CA: %s', e)
            return None

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
