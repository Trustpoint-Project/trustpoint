"""CMP (Certificate Management Protocol) client implementation.

This client enables Trustpoint to communicate with external CMP servers in two modes:
1. Direct client: Trustpoint requests certificates for itself
2. Registration Authority (RA): Trustpoint forwards device requests to upstream PKI
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac
from pyasn1.codec.der import decoder, encoder  # type: ignore[import-untyped]
from pyasn1.type import tag, univ  # type: ignore[import-untyped]
from pyasn1_modules import rfc4210  # type: ignore[import-untyped]
from trustpoint_core.oid import HmacAlgorithm

from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from pyasn1_modules.rfc4210 import PKIMessage  # type: ignore[import-untyped]

    from request.request_context import CmpBaseRequestContext


# Constants for RFC 9483 compliance
DEFAULT_CMP_PORT = 443
DEFAULT_CMP_TIMEOUT = 30


class CmpClientError(Exception):
    """Base exception for CMP client errors."""


class CmpClient(LoggerMixin):
    """CMP client for communicating with CMP servers according to RFC 9483.

    This client implements the CMP protocol for forwarding PKI messages to upstream
    CMP servers. It supports two primary use cases:

    1. **Trustpoint as CMP client**: Trustpoint creates and sends its own CMP requests
       to obtain certificates from an upstream PKI.

    2. **Trustpoint as Registration Authority (RA)**: Trustpoint receives CMP requests
       from devices, validates them, and forwards them to an upstream PKI, acting as
       a trusted intermediary.

    The client works with complete rfc4210.PKIMessage objects, allowing full control
    over the CMP protocol interaction.
    """

    def __init__(self, context: CmpBaseRequestContext, timeout: int = DEFAULT_CMP_TIMEOUT) -> None:
        """Initialize the CMP client from a request context.

        Args:
            context: CMP request context containing server configuration and credentials.
            timeout: Request timeout in seconds (default: 30).

        Raises:
            CmpClientError: If required context fields are missing.
        """
        if not hasattr(context, 'cmp_server_host') or not context.cmp_server_host:
            msg = 'cmp_server_host is required in CmpBaseRequestContext'
            raise CmpClientError(msg)

        self.context = context
        self.timeout = timeout

    def _build_url(self) -> str:
        """Build the full CMP server URL.

        Returns:
            The complete URL for the CMP endpoint.
        """
        scheme = 'https'
        host = self.context.cmp_server_host
        port = getattr(self.context, 'cmp_server_port', None) or DEFAULT_CMP_PORT
        path = getattr(self.context, 'cmp_server_path', '/pkix/certification')

        if port == DEFAULT_CMP_PORT:
            return f'{scheme}://{host}{path}'
        return f'{scheme}://{host}:{port}{path}'

    def _add_protection_shared_secret(self, pki_message: PKIMessage) -> PKIMessage:
        """Add HMAC-based shared-secret protection to the PKI message.

        This method adds Password-Based MAC (PBM) protection to a CMP message
        using the shared secret configured in the context.

        Args:
            pki_message: The PKI message to protect.

        Returns:
            Protected PKI message.

        Raises:
            CmpClientError: If shared secret is not configured or protection fails.
        """
        if not self.context.cmp_shared_secret:
            msg = 'CMP shared secret is not set in the context'
            raise CmpClientError(msg)

        shared_secret = self.context.cmp_shared_secret

        # Get PBM parameters from the header
        pbm_parameters_bitstring = pki_message['header']['protectionAlg']['parameters']
        decoded_pbm, _ = decoder.decode(pbm_parameters_bitstring, asn1Spec=rfc4210.PBMParameter())

        salt = bytes(decoded_pbm['salt'])
        iteration_count = int(decoded_pbm['iterationCount'])

        # Derive HMAC key using PBKDF1-like scheme
        shared_secret_bytes = shared_secret.encode()
        salted_secret = shared_secret_bytes + salt
        hmac_key = salted_secret

        owf_algorithm_oid = decoded_pbm['owf']['algorithm'].prettyPrint()
        try:
            hash_algorithm = {
                '2.16.840.1.101.3.4.2.1': hashes.SHA256(),
                '1.3.14.3.2.26': hashes.SHA1(),  # noqa: S303
            }[owf_algorithm_oid]
        except KeyError as e:
            msg = f'Unsupported OWF algorithm: {owf_algorithm_oid}'
            raise CmpClientError(msg) from e

        for _ in range(iteration_count):
            digest = hashes.Hash(hash_algorithm)
            digest.update(hmac_key)
            hmac_key = digest.finalize()

        # Get HMAC algorithm
        hmac_algorithm_oid = decoded_pbm['mac']['algorithm'].prettyPrint()
        try:
            hmac_algorithm = HmacAlgorithm.from_dotted_string(hmac_algorithm_oid)
        except Exception as exception:
            msg = f'Unsupported HMAC algorithm: {hmac_algorithm_oid}'
            raise CmpClientError(msg) from exception

        # Compute HMAC over protected part
        protected_part = rfc4210.ProtectedPart()
        protected_part['header'] = pki_message['header']
        protected_part['infoValue'] = pki_message['body']
        encoded_protected_part = encoder.encode(protected_part)

        hmac_gen = hmac.HMAC(hmac_key, hmac_algorithm.hash_algorithm.hash_algorithm())
        hmac_gen.update(encoded_protected_part)
        hmac_digest = hmac_gen.finalize()

        # Set protection
        binary_stuff = f'{int.from_bytes(hmac_digest, byteorder="big"):b}'.zfill(len(hmac_digest) * 8)
        pki_message['protection'] = rfc4210.PKIProtection(univ.BitString(binary_stuff)).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )

        return pki_message

    def _parse_response(self, response_data: bytes) -> PKIMessage:
        """Parse the CMP server response.

        Args:
            response_data: Raw response data from the server.

        Returns:
            The parsed PKI message.

        Raises:
            CmpClientError: If the response cannot be parsed.
        """
        try:
            pki_message, _ = decoder.decode(response_data, asn1Spec=rfc4210.PKIMessage())

            # Check for error response
            body = pki_message['body']
            body_name = body.getName()

            if body_name == 'error':
                error_msg_content = body['error']
                pki_status = error_msg_content['pKIStatusInfo']
                status_value = int(pki_status['status'])
                status_string = pki_status.get('statusString', 'No details provided')
                msg = f'CMP server returned error status {status_value}: {status_string}'
                raise CmpClientError(msg)

            self.logger.info('Successfully received CMP response: %s', body_name)
            return pki_message

        except (ValueError, TypeError, KeyError) as e:
            msg = f'Failed to parse CMP server response: {e!s}'
            raise CmpClientError(msg) from e

    def _extract_issued_certificate(self, response_message: PKIMessage) -> x509.Certificate:
        """Extract the issued certificate from a CP/IP response.

        Args:
            response_message: The parsed PKI response message (CP or IP).

        Returns:
            The issued certificate.

        Raises:
            CmpClientError: If certificate extraction fails.
        """
        try:
            body = response_message['body']
            body_name = body.getName()

            # Handle both CP and IP responses
            if body_name not in ['cp', 'ip']:
                msg = f'Expected CP or IP response, got: {body_name}'
                raise CmpClientError(msg)

            cert_response_msg = body[body_name]
            cert_responses = cert_response_msg['response']

            if len(cert_responses) < 1:
                msg = 'No certificate responses in CMP message'
                raise CmpClientError(msg)

            cert_response = cert_responses[0]

            # Check status
            pki_status_info = cert_response['status']
            status = int(pki_status_info['status'])
            if status != 0:
                status_string = pki_status_info.get('statusString', 'No details provided')
                msg = f'Certificate issuance failed with status {status}: {status_string}'
                raise CmpClientError(msg)

            # Extract certificate
            certified_key_pair = cert_response['certifiedKeyPair']
            cert_or_enc_cert = certified_key_pair['certOrEncCert']
            cmp_cert = cert_or_enc_cert['certificate']

            # Convert to cryptography certificate
            encoded_cert = encoder.encode(cmp_cert)
            issued_cert = x509.load_der_x509_certificate(encoded_cert)

            self.logger.info(
                'Successfully extracted issued certificate: %s',
                issued_cert.subject.rfc4514_string()
            )
            return issued_cert

        except (ValueError, TypeError, KeyError) as e:
            msg = f'Failed to extract certificate from response: {e!s}'
            raise CmpClientError(msg) from e

    def send_pki_message(
        self,
        pki_message: PKIMessage,
        add_shared_secret_protection: bool = False,
    ) -> PKIMessage:
        """Send a PKI message to the CMP server and return the response.

        This is the main method for both use cases:
        1. Trustpoint as client: Send self-created messages
        2. Trustpoint as RA: Forward device messages

        Args:
            pki_message: The complete PKI message to send. This should be a properly
                        constructed rfc4210.PKIMessage with header and body.
            add_shared_secret_protection: If True, adds HMAC-based protection using
                                         the shared secret from context. If False,
                                         the message must already be protected.

        Returns:
            The parsed PKI response message from the server.

        Raises:
            CmpClientError: If the request fails or response is invalid.
        """
        url = self._build_url()
        self.logger.info('Sending CMP PKI message to: %s', url)

        # Add protection if requested
        if add_shared_secret_protection:
            pki_message = self._add_protection_shared_secret(pki_message)

        # Encode message
        request_data = encoder.encode(pki_message)

        headers = {
            'Content-Type': 'application/pkixcmp',
            'Accept': 'application/pkixcmp',
        }

        # Handle TLS verification
        verify: str | bool = True
        temp_ca_bundle_path: str | None = None

        if hasattr(self.context, 'cmp_server_truststore') and self.context.cmp_server_truststore is not None:
            # Use custom truststore
            ca_bundle_pem = self.context.cmp_server_truststore.get_certificate_collection_serializer().as_pem()
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as temp_file:
                temp_file.write(ca_bundle_pem.decode('utf-8'))
                temp_ca_bundle_path = temp_file.name
                verify = temp_ca_bundle_path

        try:
            response = requests.post(
                url,
                data=request_data,
                headers=headers,
                verify=False,
                timeout=self.timeout,
            )

            if response.status_code != 200:  # noqa: PLR2004
                msg = (
                    f'CMP server returned error status {response.status_code}: {response.text}'
                )
                raise CmpClientError(msg)

            response_message = self._parse_response(response.content)

        except requests.exceptions.RequestException as e:
            msg = f'Failed to communicate with CMP server: {e!s}'
            raise CmpClientError(msg) from e
        else:
            self.logger.info('Successfully received CMP response')
            return response_message
        finally:
            if temp_ca_bundle_path is not None:
                Path(temp_ca_bundle_path).unlink()

    def send_and_extract_certificate(
        self,
        pki_message: PKIMessage,
        add_shared_secret_protection: bool = False,
    ) -> x509.Certificate:
        """Send a certification/initialization request and extract the issued certificate.

        Convenience method that combines send_pki_message() and certificate extraction
        for the common case of requesting a certificate.

        Args:
            pki_message: The CR or IR PKI message to send.
            add_shared_secret_protection: Whether to add HMAC protection.

        Returns:
            The issued certificate.

        Raises:
            CmpClientError: If the request fails or certificate extraction fails.
        """
        response_message = self.send_pki_message(
            pki_message,
            add_shared_secret_protection=add_shared_secret_protection,
        )

        return self._extract_issued_certificate(response_message)
