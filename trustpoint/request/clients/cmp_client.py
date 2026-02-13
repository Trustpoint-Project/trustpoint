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

# DER tag bytes used in CMP response parsing
_DER_TAG_SEQUENCE = 0x30
_DER_TAG_CONTEXT_0 = 0xA0  # implicit [0] used by CertOrEncCert.certificate
_DER_TAG_CONTEXT_1 = 0xA1  # implicit [1] used by PKIMessage.extraCerts / caPubs


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
                status_string_field = pki_status['statusString']
                if status_string_field.hasValue() and len(status_string_field) > 0:
                    status_string = str(status_string_field.getComponentByPosition(0))
                else:
                    status_string = 'No details provided'
                msg = f'CMP server returned error status {status_value}: {status_string}'
                raise CmpClientError(msg)

            self.logger.info('Successfully received CMP response: %s', body_name)
            return pki_message

        except (ValueError, TypeError, KeyError) as e:
            msg = f'Failed to parse CMP server response: {e!s}'
            raise CmpClientError(msg) from e

    @staticmethod
    def _parse_der_tlv(data: bytes, offset: int) -> tuple[int, int, int, int]:
        """Parse a DER TLV (Tag-Length-Value) element at the given byte offset.

        Args:
            data: The raw DER byte string.
            offset: The byte position to start parsing.

        Returns:
            A tuple of (tag_byte, header_length, value_length, total_length).

        Raises:
            ValueError: If the offset is beyond the data length.
        """
        if offset >= len(data):
            msg = f'DER parse error: offset {offset} beyond data length {len(data)}'
            raise ValueError(msg)
        tag_byte = data[offset]
        pos = offset + 1
        if data[pos] & 0x80:
            num_bytes = data[pos] & 0x7F
            val_len = int.from_bytes(data[pos + 1 : pos + 1 + num_bytes], 'big')
            header_len = 1 + 1 + num_bytes
        else:
            val_len = data[pos]
            header_len = 2
        total_len = header_len + val_len
        return tag_byte, header_len, val_len, total_len

    def _extract_certs_from_raw_response(self, raw_data: bytes) -> tuple[bytes, list[bytes]]:
        """Extract the issued certificate and extra certificates from the raw DER response.

        pyasn1 cannot reliably encode a CMPCertificate extracted from a CertOrEncCert
        CHOICE type because the implicit ``[0]`` context tag creates a broken hybrid
        object.  Instead we navigate the raw DER byte structure of the PKIMessage to
        locate the certificate and swap the ``0xa0`` implicit CHOICE tag back to the
        standard SEQUENCE tag ``0x30`` that ``x509.load_der_x509_certificate`` expects.

        The PKIMessage DER structure navigated here is::

            PKIMessage = SEQUENCE {
                header    PKIHeader,           -- SEQUENCE
                body      PKIBody,             -- context-tagged CHOICE
                protection [0] OPTIONAL,       -- context-tagged
                extraCerts [1] OPTIONAL         -- context-tagged SEQUENCE OF
            }

        Inside the body (CP [3] or IP [1])::

            CertRepMessage = SEQUENCE {
                caPubs     [1] OPTIONAL,
                response   SEQUENCE OF CertResponse
            }
            CertResponse = SEQUENCE {
                certReqId       INTEGER,
                status          PKIStatusInfo,
                certifiedKeyPair CertifiedKeyPair OPTIONAL
            }
            CertifiedKeyPair = SEQUENCE {
                certOrEncCert CertOrEncCert     -- certificate [0] IMPLICIT
            }

        Args:
            raw_data: The raw DER bytes of the complete PKIMessage response.

        Returns:
            A tuple of (issued_cert_der, list_of_extra_cert_ders).

        Raises:
            CmpClientError: If the DER structure cannot be navigated.
        """
        try:
            tlv = self._parse_der_tlv

            # PKIMessage outer SEQUENCE
            msg_tag, msg_hdr, msg_vlen, _ = tlv(raw_data, 0)
            msg_val_start = msg_hdr
            msg_val_end = msg_hdr + msg_vlen
            self.logger.debug(
                'PKIMessage: tag=0x%02x, hdr=%d, vlen=%d, total=%d',
                msg_tag, msg_hdr, msg_vlen, msg_hdr + msg_vlen,
            )

            pos = msg_val_start

            # Skip header (SEQUENCE)
            h_tag, _, _, h_total = tlv(raw_data, pos)
            self.logger.debug('Header: tag=0x%02x, total=%d at offset %d', h_tag, h_total, pos)
            pos += h_total

            # body = context-tagged CHOICE element (cp=[3] or ip=[1])
            b_tag, b_hdr, b_vlen, b_total = tlv(raw_data, pos)
            body_val_start = pos + b_hdr
            self.logger.debug(
                'Body: tag=0x%02x, hdr=%d, vlen=%d, total=%d at offset %d',
                b_tag, b_hdr, b_vlen, b_total, pos,
            )
            pos += b_total

            # CertRepMessage inside body
            crm_tag, crm_hdr, crm_vlen, _ = tlv(raw_data, body_val_start)
            crm_val_start = body_val_start + crm_hdr
            crm_val_end = body_val_start + crm_hdr + crm_vlen
            crm_pos = crm_val_start
            self.logger.debug(
                'CertRepMessage: tag=0x%02x, hdr=%d, vlen=%d at offset %d',
                crm_tag, crm_hdr, crm_vlen, body_val_start,
            )

            # Skip caPubs [1] if present
            if crm_pos < crm_val_end and raw_data[crm_pos] == _DER_TAG_CONTEXT_1:
                _, _, _, skip = tlv(raw_data, crm_pos)
                self.logger.debug('Skipping caPubs [1]: %d bytes at offset %d', skip, crm_pos)
                crm_pos += skip

            # response SEQUENCE OF CertResponse
            resp_tag, resp_hdr, resp_vlen, _ = tlv(raw_data, crm_pos)
            resp_val_start = crm_pos + resp_hdr
            self.logger.debug(
                'Response SEQUENCE OF: tag=0x%02x, hdr=%d, vlen=%d at offset %d',
                resp_tag, resp_hdr, resp_vlen, crm_pos,
            )

            # First CertResponse SEQUENCE { certReqId, status, certifiedKeyPair }
            cr_tag, cr_hdr, _, cr_total = tlv(raw_data, resp_val_start)
            cr_val_start = resp_val_start + cr_hdr
            cr_val_end = resp_val_start + cr_total
            cr_pos = cr_val_start
            self.logger.debug(
                'CertResponse: tag=0x%02x, hdr=%d, total=%d at offset %d',
                cr_tag, cr_hdr, cr_total, resp_val_start,
            )

            # Skip certReqId (INTEGER)
            id_tag, _, _, skip = tlv(raw_data, cr_pos)
            self.logger.debug('certReqId: tag=0x%02x, total=%d at offset %d', id_tag, skip, cr_pos)
            cr_pos += skip

            # Skip status (PKIStatusInfo SEQUENCE)
            st_tag, _, _, skip = tlv(raw_data, cr_pos)
            self.logger.debug('status: tag=0x%02x, total=%d at offset %d', st_tag, skip, cr_pos)
            cr_pos += skip

            if cr_pos >= cr_val_end:
                msg = 'No certifiedKeyPair found in CertResponse'
                raise CmpClientError(msg)

            # certifiedKeyPair SEQUENCE
            ckp_tag, ckp_hdr, ckp_vlen, _ = tlv(raw_data, cr_pos)
            ckp_val_start = cr_pos + ckp_hdr
            self.logger.debug(
                'certifiedKeyPair: tag=0x%02x, hdr=%d, vlen=%d at offset %d',
                ckp_tag, ckp_hdr, ckp_vlen, cr_pos,
            )

            # CertOrEncCert: certificate [0]
            # pyasn1 encodes this with an EXPLICIT [0] wrapper around the
            # Certificate SEQUENCE, so the DER looks like:
            #   A0 <len> 30 <len> <certificate contents>
            # We need to strip the outer [0] wrapper and return just the
            # inner SEQUENCE (the actual Certificate).
            coec_tag, coec_hdr, _, coec_total = tlv(raw_data, ckp_val_start)
            self.logger.debug(
                'CertOrEncCert: tag=0x%02x, total=%d at offset %d, first 20 bytes: %s',
                coec_tag, coec_total, ckp_val_start,
                raw_data[ckp_val_start : ckp_val_start + 20].hex(),
            )
            if coec_tag == _DER_TAG_CONTEXT_0:
                # EXPLICIT [0] wrapper — the actual certificate SEQUENCE is inside
                inner_start = ckp_val_start + coec_hdr
                inner_tag, _, _, inner_total = tlv(raw_data, inner_start)
                self.logger.debug(
                    'Inner cert: tag=0x%02x, total=%d at offset %d',
                    inner_tag, inner_total, inner_start,
                )
                issued_cert_der = bytes(raw_data[inner_start : inner_start + inner_total])
            else:
                # Unexpected tag — try using the raw bytes as-is
                issued_cert_der = bytes(raw_data[ckp_val_start : ckp_val_start + coec_total])
            self.logger.debug(
                'Issued cert DER: %d bytes, first 20: %s',
                len(issued_cert_der), issued_cert_der[:20].hex(),
            )

            # Extract extraCerts [1] from PKIMessage level (after body)
            extra_certs: list[bytes] = []
            scan_pos = pos  # position after body
            while scan_pos < msg_val_end:
                scan_tag, scan_hdr, _, scan_total = tlv(raw_data, scan_pos)
                if scan_tag == _DER_TAG_CONTEXT_1:
                    # extraCerts [1] EXPLICIT wraps a SEQUENCE OF CMPCertificate.
                    # pyasn1 encodes this as: [1] { SEQUENCE { cert1, cert2, ... } }
                    # We need to enter the inner SEQUENCE to iterate the certs.
                    inner_start = scan_pos + scan_hdr
                    inner_tag, inner_hdr, _, inner_total = tlv(raw_data, inner_start)
                    if inner_tag == _DER_TAG_SEQUENCE:
                        # Dive into the inner SEQUENCE OF wrapper
                        ec_pos = inner_start + inner_hdr
                        ec_end = inner_start + inner_total
                    else:
                        # Unexpected — treat the [1] content as flat cert list
                        ec_pos = inner_start
                        ec_end = scan_pos + scan_total
                    while ec_pos < ec_end:
                        _, _, _, ec_total = tlv(raw_data, ec_pos)
                        extra_certs.append(raw_data[ec_pos : ec_pos + ec_total])
                        ec_pos += ec_total
                scan_pos += scan_total

            return issued_cert_der, extra_certs

        except CmpClientError:
            raise
        except Exception as e:
            msg = f'Failed to extract certificates from raw CMP response DER: {e!s}'
            raise CmpClientError(msg) from e

    def _extract_issued_certificate(
        self,
        response_message: PKIMessage,
        raw_response: bytes,
    ) -> tuple[x509.Certificate, list[x509.Certificate]]:
        """Extract the issued certificate and chain from a CP/IP response.

        Uses pyasn1 for status checking and validation, then extracts the actual
        certificate bytes from the raw DER response to work around a pyasn1 bug
        where ``encoder.encode()`` fails on CMPCertificate objects extracted from
        a CertOrEncCert CHOICE type.

        Args:
            response_message: The parsed PKI response message (CP or IP).
            raw_response: The raw DER bytes of the complete response.

        Returns:
            A tuple of (issued_certificate, list_of_chain_certificates).

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

            # Check status using pyasn1
            pki_status_info = cert_response['status']
            status = int(pki_status_info['status'])
            if status != 0:
                status_string = pki_status_info.get('statusString', 'No details provided')
                msg = f'Certificate issuance failed with status {status}: {status_string}'
                raise CmpClientError(msg)

            # Extract certificates from raw DER bytes (bypasses pyasn1 encoding bug)
            issued_cert_der, extra_cert_ders = self._extract_certs_from_raw_response(raw_response)

            issued_cert = x509.load_der_x509_certificate(issued_cert_der)
            chain_certs = [x509.load_der_x509_certificate(ec) for ec in extra_cert_ders]

            self.logger.info(
                'Successfully extracted issued certificate: %s (+ %d chain certs)',
                issued_cert.subject.rfc4514_string(),
                len(chain_certs),
            )
            return issued_cert, chain_certs

        except CmpClientError:
            raise
        except (ValueError, TypeError, KeyError) as e:
            msg = f'Failed to extract certificate from response: {e!s}'
            raise CmpClientError(msg) from e

    def send_pki_message(
        self,
        pki_message: PKIMessage,
        add_shared_secret_protection: bool = False,
    ) -> tuple[PKIMessage, bytes]:
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
            A tuple of (parsed_response_message, raw_response_bytes).
            The raw bytes are preserved for DER-level certificate extraction.

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

            raw_response = response.content
            response_message = self._parse_response(raw_response)

        except requests.exceptions.RequestException as e:
            msg = f'Failed to communicate with CMP server: {e!s}'
            raise CmpClientError(msg) from e
        else:
            self.logger.info('Successfully received CMP response')
            return response_message, raw_response
        finally:
            if temp_ca_bundle_path is not None:
                Path(temp_ca_bundle_path).unlink()

    def send_and_extract_certificate(
        self,
        pki_message: PKIMessage,
        add_shared_secret_protection: bool = False,
    ) -> tuple[x509.Certificate, list[x509.Certificate]]:
        """Send a certification/initialization request and extract the issued certificate.

        Convenience method that combines send_pki_message() and certificate extraction
        for the common case of requesting a certificate.

        Args:
            pki_message: The CR or IR PKI message to send.
            add_shared_secret_protection: Whether to add HMAC protection.

        Returns:
            A tuple of (issued_certificate, chain_certificates).
            The chain certificates are from the ``extraCerts`` field of the response.

        Raises:
            CmpClientError: If the request fails or certificate extraction fails.
        """
        response_message, raw_response = self.send_pki_message(
            pki_message,
            add_shared_secret_protection=add_shared_secret_protection,
        )

        return self._extract_issued_certificate(response_message, raw_response)
