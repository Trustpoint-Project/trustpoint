# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""CMP (Certificate Management Protocol) client implementation.

This client enables Trustpoint to communicate with external CMP servers in two modes:
1. Direct client: Trustpoint requests certificates for itself
2. Registration Authority (RA): Trustpoint forwards device requests to upstream PKI
"""

from __future__ import annotations

import hmac as stdlib_hmac
from typing import TYPE_CHECKING

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from django.conf import settings
from pyasn1.codec.der import decoder, encoder  # type: ignore[import-untyped]
from pyasn1.error import PyAsn1Error  # type: ignore[import-untyped]
from pyasn1.type import tag, univ  # type: ignore[import-untyped]
from pyasn1_modules import rfc4210  # type: ignore[import-untyped]

from cmp.util import cmp_hmac_algorithm
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from pyasn1_modules.rfc4210 import PKIMessage  # type: ignore[import-untyped]

    from request.request_context import CmpBaseRequestContext


# Constants for RFC 9483 compliance
DEFAULT_CMP_PORT = 443
DEFAULT_CMP_TIMEOUT = 30
MAX_CMP_RESPONSE_BYTES = 131_072
_MINIMUM_NONCE_BYTES = 16
_PBM_OID = '1.2.840.113533.7.66.13'
_PBM_HASHES: dict[str, type[hashes.HashAlgorithm]] = {
    '2.16.840.1.101.3.4.2.1': hashes.SHA256,
    '2.16.840.1.101.3.4.2.2': hashes.SHA384,
    '2.16.840.1.101.3.4.2.3': hashes.SHA512,
    '2.16.840.1.101.3.4.2.8': hashes.SHA3_256,
    '2.16.840.1.101.3.4.2.9': hashes.SHA3_384,
    '2.16.840.1.101.3.4.2.10': hashes.SHA3_512,
}
_RESPONSE_BODY_TYPES = {
    'ir': {'ip'},
    'cr': {'cp'},
    'kur': {'kup'},
    'p10cr': {'cp'},
    'rr': {'rp'},
    'genm': {'genp'},
    'certConf': {'pkiconf'},
    'pollReq': {'pollRep', 'ip', 'cp', 'kup'},
}

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
    Upstream transactions currently require shared-secret PBM protection.
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

    def _raise_cmp_client_error(self, message: str) -> None:
        """Raise a CMP client error with the given message."""
        self.logger.error(message)
        raise CmpClientError(message)

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
            hmac_algorithm = cmp_hmac_algorithm(hmac_algorithm_oid)
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

    @staticmethod
    def _validate_response_binding(response: PKIMessage, request: PKIMessage) -> None:
        """Bind a response to the outstanding request before consuming its contents."""
        header = response['header']
        request_header = request['header']
        if int(header['pvno']) not in {2, 3}:
            msg = 'Unsupported CMP response version.'
            raise CmpClientError(msg)
        for name in ('transactionID', 'senderNonce'):
            if not request_header[name].hasValue() or len(request_header[name].asOctets()) < _MINIMUM_NONCE_BYTES:
                msg = f'CMP request requires at least 128 bits of {name} for response binding.'
                raise CmpClientError(msg)
        if not header['transactionID'].hasValue() or not stdlib_hmac.compare_digest(
            header['transactionID'].asOctets(),
            request_header['transactionID'].asOctets(),
        ):
            msg = 'CMP response transactionID does not match the request.'
            raise CmpClientError(msg)
        if not header['recipNonce'].hasValue() or not stdlib_hmac.compare_digest(
            header['recipNonce'].asOctets(),
            request_header['senderNonce'].asOctets(),
        ):
            msg = 'CMP response recipNonce does not match the request senderNonce.'
            raise CmpClientError(msg)
        if not header['senderNonce'].hasValue() or len(header['senderNonce'].asOctets()) < _MINIMUM_NONCE_BYTES:
            msg = 'CMP response senderNonce must contain at least 128 bits.'
            raise CmpClientError(msg)
        for name in ('senderNonce', 'recipNonce'):
            if request_header[name].hasValue() and stdlib_hmac.compare_digest(
                header['senderNonce'].asOctets(),
                request_header[name].asOctets(),
            ):
                msg = 'CMP response senderNonce is not fresh.'
                raise CmpClientError(msg)

    @staticmethod
    def _validate_response_body(response: PKIMessage, request: PKIMessage) -> None:
        """Require the expected operation response and matching certificate request IDs."""
        request_type = request['body'].getName()
        response_type = response['body'].getName()
        if request_type not in _RESPONSE_BODY_TYPES:
            msg = f'Unsupported outbound CMP request type: {request_type}.'
            raise CmpClientError(msg)
        if response_type == 'error':
            return
        if response_type not in _RESPONSE_BODY_TYPES[request_type]:
            msg = f'Unexpected CMP response body {response_type} for request {request_type}.'
            raise CmpClientError(msg)
        if response_type == 'pollRep':
            poll_requests = request['body']['pollReq']
            poll_responses = response['body']['pollRep']
            if [int(item['certReqId']) for item in poll_responses] != [
                int(item['certReqId']) for item in poll_requests
            ]:
                msg = 'CMP pollRep certReqId does not match the poll request.'
                raise CmpClientError(msg)
        if response_type in {'ip', 'cp', 'kup'}:
            CmpClient._validate_certificate_response_id(response, request)

    @staticmethod
    def _validate_certificate_response_id(response: PKIMessage, request: PKIMessage) -> None:
        """Require the one requested certificate rather than accepting the first result."""
        responses = response['body'][response['body'].getName()]['response']
        if len(responses) != 1:
            msg = 'Exactly one CMP certificate response is required.'
            raise CmpClientError(msg)
        request_type = request['body'].getName()
        expected_ids: list[int] | None = None
        if request_type in {'ir', 'cr', 'kur'}:
            expected_ids = [int(item['certReq']['certReqId']) for item in request['body'][request_type]]
        elif request_type == 'pollReq':
            expected_ids = [int(item['certReqId']) for item in request['body']['pollReq']]
        elif request_type == 'p10cr':
            expected_ids = [-1]
        if expected_ids is not None and expected_ids != [int(responses[0]['certReqId'])]:
            msg = 'CMP response certReqId does not match the request.'
            raise CmpClientError(msg)

    def _verify_response_protection(self, response: PKIMessage, request: PKIMessage) -> None:
        """Authenticate the supported PBM transactions, with bounded untrusted parameters."""
        if not response['header']['protectionAlg'].hasValue() or not response['protection'].hasValue():
            msg = 'CMP response is missing message protection.'
            raise CmpClientError(msg)
        if (
            not request['header']['protectionAlg'].hasValue()
            or str(request['header']['protectionAlg']['algorithm']) != _PBM_OID
            or str(response['header']['protectionAlg']['algorithm']) != _PBM_OID
        ):
            msg = 'Only PBM-protected upstream CMP transactions are supported; protection must not change.'
            raise CmpClientError(msg)
        if not self.context.cmp_shared_secret:
            msg = 'CMP shared secret is required to authenticate the response.'
            raise CmpClientError(msg)
        salt, iterations, factory, mac_hash = self._response_pbm_parameters(response)
        key = self.context.cmp_shared_secret.encode() + salt
        for _ in range(iterations):
            digest = hashes.Hash(factory())
            digest.update(key)
            key = digest.finalize()
        protected = rfc4210.ProtectedPart()
        protected['header'] = response['header']
        protected['infoValue'] = response['body']
        verifier = hmac.HMAC(key, mac_hash)
        verifier.update(encoder.encode(protected))
        if len(response['protection']) % 8:
            msg = 'CMP response protection must contain complete octets.'
            raise CmpClientError(msg)
        try:
            verifier.verify(response['protection'].asOctets())
        except InvalidSignature as exc:
            msg = 'CMP response message protection verification failed.'
            raise CmpClientError(msg) from exc

    @staticmethod
    def _response_pbm_parameters(
        response: PKIMessage,
    ) -> tuple[bytes, int, type[hashes.HashAlgorithm], hashes.HashAlgorithm]:
        """Validate untrusted PBM parameters before performing key derivation."""
        parameters = response['header']['protectionAlg']['parameters']
        pbm, remainder = decoder.decode(parameters.asOctets(), asn1Spec=rfc4210.PBMParameter())
        if remainder:
            msg = 'Unexpected trailing data in CMP response PBM parameters.'
            raise CmpClientError(msg)
        salt = pbm['salt'].asOctets()
        iterations = int(pbm['iterationCount'])
        if not (
            int(getattr(settings, 'TRUSTPOINT_CMP_PBM_MIN_SALT_BYTES', 8))
            <= len(salt)
            <= int(getattr(settings, 'TRUSTPOINT_CMP_PBM_MAX_SALT_BYTES', 64))
            and int(getattr(settings, 'TRUSTPOINT_CMP_PBM_MIN_ITERATIONS', 1))
            <= iterations
            <= int(getattr(settings, 'TRUSTPOINT_CMP_PBM_MAX_ITERATIONS', 100_000))
        ):
            msg = 'CMP response PBM salt length or iterationCount is outside permitted bounds.'
            raise CmpClientError(msg)
        factory = _PBM_HASHES.get(str(pbm['owf']['algorithm']))
        mac_hash = cmp_hmac_algorithm(str(pbm['mac']['algorithm'])).hash_algorithm.hash_algorithm()
        if factory is None or not isinstance(mac_hash, tuple(_PBM_HASHES.values())):
            msg = 'CMP response PBM hash or MAC algorithm is not permitted.'
            raise CmpClientError(msg)
        for name in ('owf', 'mac'):
            algorithm_parameters = pbm[name]['parameters']
            if algorithm_parameters.hasValue() and algorithm_parameters.asOctets() != b'\x05\x00':
                msg = f'Invalid CMP response PBM {name} algorithm parameters.'
                raise CmpClientError(msg)
        return salt, iterations, factory, mac_hash

    def _validate_response(self, response: PKIMessage, request: PKIMessage) -> None:
        """Validate response binding and protection before interpreting status or certificates."""
        self._validate_response_binding(response, request)
        self._verify_response_protection(response, request)
        self._validate_response_body(response, request)

    def _parse_response(self, response_data: bytes, request: PKIMessage | bytes) -> PKIMessage:
        """Parse and authenticate a response to the supplied outbound request.

        Args:
            response_data: Raw response data from the server.
            request: The outstanding request or its immutable transmitted DER bytes.

        Returns:
            The parsed PKI message.

        Raises:
            CmpClientError: If the response is malformed, unauthenticated, or not bound to the request.
        """
        try:
            if len(response_data) > MAX_CMP_RESPONSE_BYTES:
                msg = 'CMP response exceeds the maximum permitted size.'
                raise CmpClientError(msg)
            pki_message, remainder = decoder.decode(response_data, asn1Spec=rfc4210.PKIMessage())
            if remainder:
                msg = 'Unexpected trailing data in CMP response.'
                raise CmpClientError(msg)
            if isinstance(request, bytes):
                request, request_remainder = decoder.decode(request, asn1Spec=rfc4210.PKIMessage())
                if request_remainder:
                    msg = 'Unexpected trailing data in outbound CMP request.'
                    raise CmpClientError(msg)
            self._validate_response(pki_message, request)

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

        except (PyAsn1Error, ValueError, TypeError, KeyError) as e:
            msg = f'Failed to parse CMP server response: {e!s}'
            raise CmpClientError(msg) from e
        else:
            self.logger.info('Successfully received CMP response: %s', body_name)
            return pki_message

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
        object.

        Args:
            raw_data: The raw DER bytes of the complete PKIMessage response.

        Returns:
            A tuple of (issued_cert_der, list_of_extra_cert_ders).

        Raises:
            CmpClientError: If the DER structure cannot be navigated.
        """
        try:
            msg_val_start, msg_val_end = self._parse_pki_message_envelope(raw_data)
            body_val_start, body_end = self._parse_body(raw_data, msg_val_start)
            crm_val_start, crm_val_end = self._parse_cert_rep_message(raw_data, body_val_start)
            resp_val_start = self._skip_ca_pubs_if_present(raw_data, crm_val_start, crm_val_end)
            cr_val_start, cr_val_end = self._parse_cert_response(raw_data, resp_val_start)
            ckp_val_start = self._skip_cert_req_id_and_status(raw_data, cr_val_start, cr_val_end)
            issued_cert_der = self._extract_issued_cert_from_ckp(raw_data, ckp_val_start)
            extra_certs = self._extract_extra_certs(raw_data, body_end, msg_val_end)

        except CmpClientError:
            raise
        except Exception as e:
            msg = f'Failed to extract certificates from raw CMP response DER: {e!s}'
            raise CmpClientError(msg) from e
        else:
            return issued_cert_der, extra_certs

    def _parse_pki_message_envelope(self, raw_data: bytes) -> tuple[int, int]:
        """Parse the PKIMessage outer SEQUENCE and return value start and end."""
        tlv = self._parse_der_tlv
        msg_tag, msg_hdr, msg_vlen, _ = tlv(raw_data, 0)
        msg_val_start = msg_hdr
        msg_val_end = msg_hdr + msg_vlen
        self.logger.debug(
            'PKIMessage: tag=0x%02x, hdr=%d, vlen=%d, total=%d',
            msg_tag,
            msg_hdr,
            msg_vlen,
            msg_hdr + msg_vlen,
        )
        return msg_val_start, msg_val_end

    def _parse_body(self, raw_data: bytes, msg_val_start: int) -> tuple[int, int]:
        """Parse the header and body, return body value start and end."""
        tlv = self._parse_der_tlv
        pos = msg_val_start
        # Skip header (SEQUENCE)
        h_tag, _, _, h_total = tlv(raw_data, pos)
        self.logger.debug('Header: tag=0x%02x, total=%d at offset %d', h_tag, h_total, pos)
        pos += h_total

        b_tag, b_hdr, b_vlen, b_total = tlv(raw_data, pos)
        body_val_start = pos + b_hdr
        body_end = pos + b_total
        self.logger.debug(
            'Body: tag=0x%02x, hdr=%d, vlen=%d, total=%d at offset %d',
            b_tag,
            b_hdr,
            b_vlen,
            b_total,
            pos,
        )
        return body_val_start, body_end

    def _parse_cert_rep_message(self, raw_data: bytes, body_val_start: int) -> tuple[int, int]:
        """Parse CertRepMessage and return value start and end."""
        tlv = self._parse_der_tlv
        crm_tag, crm_hdr, crm_vlen, _ = tlv(raw_data, body_val_start)
        crm_val_start = body_val_start + crm_hdr
        crm_val_end = body_val_start + crm_hdr + crm_vlen
        self.logger.debug(
            'CertRepMessage: tag=0x%02x, hdr=%d, vlen=%d at offset %d',
            crm_tag,
            crm_hdr,
            crm_vlen,
            body_val_start,
        )
        return crm_val_start, crm_val_end

    def _skip_ca_pubs_if_present(self, raw_data: bytes, crm_val_start: int, crm_val_end: int) -> int:
        """Skip caPubs [1] if present and return position of response."""
        tlv = self._parse_der_tlv
        crm_pos = crm_val_start
        if crm_pos < crm_val_end and raw_data[crm_pos] == _DER_TAG_CONTEXT_1:
            _, _, _, skip = tlv(raw_data, crm_pos)
            self.logger.debug('Skipping caPubs [1]: %d bytes at offset %d', skip, crm_pos)
            crm_pos += skip
        return crm_pos

    def _parse_cert_response(self, raw_data: bytes, resp_val_start: int) -> tuple[int, int]:
        """Parse the response SEQUENCE OF and CertResponse, return CertResponse value start and end."""
        tlv = self._parse_der_tlv
        resp_tag, resp_hdr, resp_vlen, _ = tlv(raw_data, resp_val_start)
        self.logger.debug(
            'Response SEQUENCE OF: tag=0x%02x, hdr=%d, vlen=%d at offset %d',
            resp_tag,
            resp_hdr,
            resp_vlen,
            resp_val_start,
        )

        cr_tag, cr_hdr, _, cr_total = tlv(raw_data, resp_val_start + resp_hdr)
        cr_val_start = resp_val_start + resp_hdr + cr_hdr
        cr_val_end = resp_val_start + resp_hdr + cr_total
        self.logger.debug(
            'CertResponse: tag=0x%02x, hdr=%d, total=%d at offset %d',
            cr_tag,
            cr_hdr,
            cr_total,
            resp_val_start + resp_hdr,
        )
        return cr_val_start, cr_val_end

    def _skip_cert_req_id_and_status(self, raw_data: bytes, cr_val_start: int, cr_val_end: int) -> int:
        """Skip certReqId and status, return position of certifiedKeyPair."""
        tlv = self._parse_der_tlv
        cr_pos = cr_val_start
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
            self._raise_cmp_client_error(msg)
        return cr_pos

    def _extract_issued_cert_from_ckp(self, raw_data: bytes, ckp_val_start: int) -> bytes:
        """Extract the issued certificate from certifiedKeyPair."""
        tlv = self._parse_der_tlv
        # certifiedKeyPair SEQUENCE
        ckp_tag, ckp_hdr, ckp_vlen, _ = tlv(raw_data, ckp_val_start)
        ckp_val_start_inner = ckp_val_start + ckp_hdr
        self.logger.debug(
            'certifiedKeyPair: tag=0x%02x, hdr=%d, vlen=%d at offset %d',
            ckp_tag,
            ckp_hdr,
            ckp_vlen,
            ckp_val_start,
        )

        coec_tag, coec_hdr, _, coec_total = tlv(raw_data, ckp_val_start_inner)
        self.logger.debug(
            'CertOrEncCert: tag=0x%02x, total=%d at offset %d, first 20 bytes: %s',
            coec_tag,
            coec_total,
            ckp_val_start_inner,
            raw_data[ckp_val_start_inner : ckp_val_start_inner + 20].hex(),
        )
        if coec_tag == _DER_TAG_CONTEXT_0:
            inner_start = ckp_val_start_inner + coec_hdr
            inner_tag, _, _, inner_total = tlv(raw_data, inner_start)
            self.logger.debug(
                'Inner cert: tag=0x%02x, total=%d at offset %d',
                inner_tag,
                inner_total,
                inner_start,
            )
            issued_cert_der = bytes(raw_data[inner_start : inner_start + inner_total])
        else:
            # Unexpected tag — try using the raw bytes as-is
            issued_cert_der = bytes(raw_data[ckp_val_start_inner : ckp_val_start_inner + coec_total])
        self.logger.debug(
            'Issued cert DER: %d bytes, first 20: %s',
            len(issued_cert_der),
            issued_cert_der[:20].hex(),
        )
        return issued_cert_der

    def _extract_extra_certs(self, raw_data: bytes, body_end: int, msg_val_end: int) -> list[bytes]:
        """Extract extra certificates from after the body."""
        tlv = self._parse_der_tlv
        extra_certs: list[bytes] = []
        scan_pos = body_end
        while scan_pos < msg_val_end:
            scan_tag, scan_hdr, _, scan_total = tlv(raw_data, scan_pos)
            if scan_tag == _DER_TAG_CONTEXT_1:
                # extraCerts [1] EXPLICIT wraps a SEQUENCE OF CMPCertificate.
                # pyasn1 encodes this as: [1] { SEQUENCE { cert1, cert2, ... } }
                # We need to enter the inner SEQUENCE to iterate the certs.
                inner_start = scan_pos + scan_hdr
                inner_tag, inner_hdr, _, inner_total = tlv(raw_data, inner_start)
                if inner_tag == _DER_TAG_SEQUENCE:
                    ec_pos = inner_start + inner_hdr
                    ec_end = inner_start + inner_total
                else:
                    ec_pos = inner_start
                    ec_end = scan_pos + scan_total
                while ec_pos < ec_end:
                    _, _, _, ec_total = tlv(raw_data, ec_pos)
                    extra_certs.append(raw_data[ec_pos : ec_pos + ec_total])
                    ec_pos += ec_total
            scan_pos += scan_total
        return extra_certs

    def _extract_issued_certificate(
        self,
        response_message: PKIMessage,
        raw_response: bytes,
    ) -> tuple[x509.Certificate, list[x509.Certificate]]:
        """Extract the issued certificate and chain from a CP/IP response.

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

            if body_name not in ['cp', 'ip']:
                msg = f'Expected CP or IP response, got: {body_name}'
                self._raise_cmp_client_error(msg)

            cert_response_msg = body[body_name]
            cert_responses = cert_response_msg['response']

            if len(cert_responses) < 1:
                msg = 'No certificate responses in CMP message'
                self._raise_cmp_client_error(msg)

            cert_response = cert_responses[0]

            pki_status_info = cert_response['status']
            status = int(pki_status_info['status'])
            if status != 0:
                status_string = pki_status_info.get('statusString', 'No details provided')
                msg = f'Certificate issuance failed with status {status}: {status_string}'
                self._raise_cmp_client_error(msg)

            issued_cert_der, extra_cert_ders = self._extract_certs_from_raw_response(raw_response)

            issued_cert = x509.load_der_x509_certificate(issued_cert_der)
            chain_certs = [x509.load_der_x509_certificate(ec) for ec in extra_cert_ders]

        except CmpClientError:
            raise
        except (ValueError, TypeError, KeyError) as e:
            msg = f'Failed to extract certificate from response: {e!s}'
            raise CmpClientError(msg) from e
        else:
            self.logger.info(
                'Successfully extracted issued certificate: %s (+ %d chain certs)',
                issued_cert.subject.rfc4514_string(),
                len(chain_certs),
            )
            return issued_cert, chain_certs

    def send_pki_message(
        self,
        pki_message: PKIMessage,
        *,
        add_shared_secret_protection: bool = False,
    ) -> tuple[PKIMessage, bytes]:
        """Send a PKI message to the CMP server and return the response.

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

        if add_shared_secret_protection:
            pki_message = self._add_protection_shared_secret(pki_message)

        # Retain the transmitted DER as the immutable response-binding snapshot.
        request_data = encoder.encode(pki_message)

        headers = {
            'Content-Type': 'application/pkixcmp',
            'Accept': 'application/pkixcmp',
        }

        # Authentication is provided by request-bound CMP message protection.
        try:
            response = requests.post(
                url,
                data=request_data,
                headers=headers,
                verify=False,  # noqa: S501
                timeout=self.timeout,
            )

            if response.status_code != 200:  # noqa: PLR2004
                msg = f'CMP server returned error status {response.status_code}: {response.text}'
                raise CmpClientError(msg)

            raw_response = response.content
            response_message = self._parse_response(raw_response, request_data)

        except requests.exceptions.RequestException as e:
            msg = f'Failed to communicate with CMP server: {e!s}'
            raise CmpClientError(msg) from e
        else:
            self.logger.info('Successfully received CMP response')
            return response_message, raw_response

    def send_and_extract_certificate(
        self,
        pki_message: PKIMessage,
        *,
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
