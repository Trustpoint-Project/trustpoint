"""EST (Enrollment over Secure Transport) client implementation."""

from __future__ import annotations

import base64
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from cryptography import x509
    from cryptography.x509 import CertificateSigningRequest

    from request.request_context import EstBaseRequestContext


# Constants for RFC 7030 compliance
DEFAULT_EST_PORT = 443
DEFAULT_EST_TIMEOUT = 30


class EstClientError(Exception):
    """Base exception for EST client errors."""


class EstClient(LoggerMixin):
    """EST client for communicating with EST servers according to RFC 7030.

    This client implements the EST protocol for certificate enrollment,
    specifically supporting the simpleenroll operation.

    The client uses an EstBaseRequestContext to configure the connection
    and authentication parameters.
    """

    def __init__(self, context: EstBaseRequestContext, timeout: int = DEFAULT_EST_TIMEOUT) -> None:
        """Initialize the EST client from a request context.

        Args:
            context: EST request context containing server configuration and credentials.
            timeout: Request timeout in seconds (default: 30).

        Raises:
            EstClientError: If required context fields are missing.
        """
        if not context.est_server_host:
            msg = 'est_server_host is required in EstBaseRequestContext'
            raise EstClientError(msg)

        if not context.est_server_truststore:
            msg = 'est_server_truststore is required in EstBaseRequestContext'
            raise EstClientError(msg)

        self.context = context
        self.timeout = timeout

    def _build_url(self, path: str | None = None) -> str:
        """Build the full EST server URL.

        Args:
            path: Optional path override. If not provided, uses context.est_server_path
                  or defaults to /.well-known/est/simpleenroll.

        Returns:
            The complete URL for the EST endpoint.
        """
        scheme = 'https'
        host = self.context.est_server_host
        port = self.context.est_server_port or DEFAULT_EST_PORT

        if path is None:
            path = self.context.est_server_path or '/.well-known/est/simpleenroll'

        if port == DEFAULT_EST_PORT:
            return f'{scheme}://{host}{path}'
        return f'{scheme}://{host}:{port}{path}'

    def _prepare_csr_data(self, csr: CertificateSigningRequest) -> tuple[bytes, str]:
        """Prepare CSR data for transmission according to RFC 7030.

        Args:
            csr: The Certificate Signing Request to send.

        Returns:
            Tuple of (encoded_data, content_type) where encoded_data is the
            base64-encoded DER CSR and content_type is the MIME type.
        """
        csr_der = csr.public_bytes(encoding=serialization.Encoding.DER)
        csr_b64 = base64.b64encode(csr_der)

        content_type = 'application/pkcs10'

        self.logger.debug(
            'Prepared CSR: %d bytes DER, %d bytes base64-encoded',
            len(csr_der),
            len(csr_b64)
        )

        return csr_b64, content_type

    def _parse_response(self, response_data: bytes, content_type: str) -> x509.Certificate:
        """Parse the EST server response containing the issued certificate.

        Args:
            response_data: Raw response data from the server.
            content_type: Content-Type header from the response.

        Returns:
            The issued certificate.

        Raises:
            EstClientError: If the response cannot be parsed.
        """
        if 'application/pkcs7-mime' not in content_type:
            msg = f'Unexpected content type in response: {content_type}'
            raise EstClientError(msg)

        try:
            pkcs7_der = base64.b64decode(response_data)

            certificates = pkcs7.load_der_pkcs7_certificates(pkcs7_der)

            if not certificates:
                msg = 'No certificates found in PKCS#7 response'
                raise EstClientError(msg)

            issued_cert = certificates[0]

        except (ValueError, TypeError) as e:
            msg = f'Failed to parse EST server response: {e!s}'
            raise EstClientError(msg) from e
        else:
            self.logger.info(
                'Successfully parsed issued certificate: %s',
                issued_cert.subject.rfc4514_string()
            )
            return issued_cert

    def simple_enroll(self, csr: CertificateSigningRequest) -> x509.Certificate:
        """Perform simple enrollment by sending a CSR to the EST server.

        This implements the /simpleenroll operation defined in RFC 7030 section 4.2.

        Args:
            csr: The Certificate Signing Request to enroll.

        Returns:
            The issued certificate from the EST server.

        Raises:
            EstClientError: If the enrollment fails.
        """
        url = self._build_url()
        self.logger.info('Enrolling CSR via EST simpleenroll: %s', url)

        csr_data, content_type = self._prepare_csr_data(csr)

        headers = {
            'Content-Type': content_type,
            'Content-Transfer-Encoding': 'base64',
            'Accept': 'application/pkcs7-mime',
        }

        auth = None
        if self.context.est_username and self.context.est_password:
            auth = (self.context.est_username, self.context.est_password)
            self.logger.debug('Using HTTP Basic Authentication for user: %s', self.context.est_username)

        # Create temporary CA bundle file for requests
        if self.context.est_server_truststore is None:
            msg = 'EST server truststore is not configured'
            raise EstClientError(msg)
        ca_bundle_pem = self.context.est_server_truststore.get_certificate_collection_serializer().as_pem()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as temp_file:
            temp_file.write(ca_bundle_pem.decode('utf-8'))
            temp_ca_bundle_path = temp_file.name

        try:
            response = requests.post(
                url,
                data=csr_data,
                headers=headers,
                auth=auth,
                verify=temp_ca_bundle_path,
                timeout=self.timeout,
            )

            if response.status_code != 200:  # noqa: PLR2004
                msg = (
                    f'EST server returned error status {response.status_code}: {response.text}'
                )
                raise EstClientError(msg)

            content_type_header = response.headers.get('Content-Type', '')
            issued_cert = self._parse_response(response.content, content_type_header)

        except requests.exceptions.RequestException as e:
            msg = f'Failed to communicate with EST server: {e!s}'
            raise EstClientError(msg) from e
        else:
            self.logger.info('Successfully enrolled certificate via EST')
            return issued_cert
        finally:
            Path(temp_ca_bundle_path).unlink()

    def get_ca_certs(self) -> list[x509.Certificate]:
        """Retrieve CA certificates from the EST server.

        This implements the /cacerts operation defined in RFC 7030 section 4.1.

        Returns:
            List of CA certificates from the server.

        Raises:
            EstClientError: If the operation fails.
        """
        url = self._build_url(path='/.well-known/est/cacerts')

        self.logger.info('Retrieving CA certificates from EST server: %s', url)

        headers = {
            'Accept': 'application/pkcs7-mime',
        }

        # Create temporary CA bundle file for requests
        if self.context.est_server_truststore is None:
            msg = 'EST server truststore is not configured'
            raise EstClientError(msg)
        ca_bundle_pem = self.context.est_server_truststore.get_certificate_collection_serializer().as_pem()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as temp_file:
            temp_file.write(ca_bundle_pem.decode('utf-8'))
            temp_ca_bundle_path = temp_file.name

        try:
            response = requests.get(
                url,
                headers=headers,
                verify=temp_ca_bundle_path,
                timeout=self.timeout,
            )

            if response.status_code != 200:  # noqa: PLR2004
                msg = f'EST server returned error status {response.status_code}: {response.text}'
                raise EstClientError(msg)

            pkcs7_data = base64.b64decode(response.content)

            ca_certs = pkcs7.load_der_pkcs7_certificates(pkcs7_data)

        except requests.exceptions.RequestException as e:
            msg = f'Failed to retrieve CA certificates: {e!s}'
            raise EstClientError(msg) from e
        else:
            self.logger.info('Retrieved %d CA certificate(s) from EST server', len(ca_certs))
            return ca_certs
        finally:
            Path(temp_ca_bundle_path).unlink()
