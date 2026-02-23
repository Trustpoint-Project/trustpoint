"""Provides classes for building CMP PKI messages."""

from __future__ import annotations

import os
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from pyasn1.codec.der import decoder, encoder  # type: ignore[import-untyped]
from pyasn1.type import tag, univ, useful  # type: ignore[import-untyped]
from pyasn1_modules import rfc3280, rfc4210, rfc4211, rfc5280  # type: ignore[import-untyped]
from trustpoint_core.oid import AlgorithmIdentifier, HashAlgorithm, HmacAlgorithm

from request.request_context import (
    BaseRequestContext,
    CmpCertificateRequestContext,
)
from trustpoint.logger import LoggerMixin

from .base import BuildingComponent, CompositeBuilding


class CmpMessageBuilderError(Exception):
    """Base exception for CMP message builder errors."""



CMP_MESSAGE_VERSION = 2
TRANSACTION_ID_LENGTH = 16
SENDER_NONCE_LENGTH = 16
IMPLICIT_CONFIRM_OID = '1.3.6.1.5.5.7.4.13'
PBM_OID = '1.2.840.113533.7.66.13'
SHA256_OID = HashAlgorithm.SHA256.dotted_string

# Threshold below which DER length fits in a single byte (short form).
_DER_LENGTH_SHORT_FORM_MAX = 0x7F


def _der_tlv(tag_byte: int, value: bytes) -> bytes:
    """Construct a DER Tag-Length-Value triplet.

    Handles both short-form (length < 128) and long-form DER lengths.

    Args:
        tag_byte: Single-byte ASN.1 tag (e.g. ``0xA4`` for ``[4] CONSTRUCTED``).
        value: The encoded value octets.

    Returns:
        The complete TLV as ``bytes``.
    """
    length = len(value)
    if length <= _DER_LENGTH_SHORT_FORM_MAX:
        return bytes([tag_byte, length]) + value
    length_payload = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([tag_byte, 0x80 | len(length_payload)]) + length_payload + value


class CmpCertTemplateBuilding(BuildingComponent, LoggerMixin):
    """Build a ``CertTemplate`` from the context's certificate request data."""

    def build(self, context: BaseRequestContext) -> None:
        """Build the CertTemplate and store it in the context."""
        if not isinstance(context, CmpCertificateRequestContext):
            exc_msg = 'CmpCertTemplateBuilding requires a CmpCertificateRequestContext.'
            raise TypeError(exc_msg)

        request_data = context.request_data
        if not request_data:
            exc_msg = 'request_data is missing from the context.'
            raise ValueError(exc_msg)

        subject: x509.Name | None = request_data.get('subject')
        public_key = request_data.get('public_key')
        extensions: list[x509.Extension[x509.ExtensionType]] | None = request_data.get('extensions')

        if subject is None:
            exc_msg = 'subject is required in request_data.'
            raise ValueError(exc_msg)
        if public_key is None:
            exc_msg = 'public_key is required in request_data.'
            raise ValueError(exc_msg)

        cert_template = self._build_cert_template(subject, public_key, extensions)
        context.validated_request_data = context.validated_request_data or {}
        context.validated_request_data['_cert_template'] = cert_template

        self.logger.info('CertTemplate built for subject: %s', subject.rfc4514_string())

    @staticmethod
    def _get_cert_template_field_schema(field_name: str) -> univ.Asn1Type:
        """Return the schema type (with correct implicit tag) for a ``CertTemplate`` field."""
        ct = rfc4211.CertTemplate()
        for i in range(len(ct.componentType)):
            if ct.componentType.getNameByPosition(i) == field_name:
                return ct.componentType.getTypeByPosition(i)
        exc_msg = f'Unknown CertTemplate field: {field_name}'
        raise ValueError(exc_msg)

    @staticmethod
    def _build_cert_template(
        subject: x509.Name,
        public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
        extensions: list[x509.Extension[x509.ExtensionType]] | None = None,
    ) -> rfc4211.CertTemplate:
        """Build a ``CertTemplate`` from certificate components.

        Args:
            subject: The subject name for the certificate.
            public_key: The public key for the certificate request.
            extensions: Optional list of extensions to include.

        Returns:
            The constructed ``CertTemplate``.
        """
        cert_template = rfc4211.CertTemplate()

        subject_der = subject.public_bytes(serialization.Encoding.DER)
        subject_asn1, _ = decoder.decode(subject_der, asn1Spec=rfc3280.Name())
        subject_schema = CmpCertTemplateBuilding._get_cert_template_field_schema('subject')
        tagged_subject = subject_asn1.clone(tagSet=subject_schema.tagSet)
        tagged_subject['rdnSequence'] = subject_asn1.getComponent()
        cert_template['subject'] = tagged_subject

        public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_key_asn1, _ = decoder.decode(public_key_der, asn1Spec=rfc3280.SubjectPublicKeyInfo())
        pubkey_schema = CmpCertTemplateBuilding._get_cert_template_field_schema('publicKey')
        tagged_pubkey = public_key_asn1.clone(tagSet=pubkey_schema.tagSet, cloneValueFlag=True)
        cert_template['publicKey'] = tagged_pubkey

        if extensions:
            extensions_asn1 = rfc3280.Extensions()
            for idx, ext in enumerate(extensions):
                extension_asn1 = rfc3280.Extension()
                extension_asn1['extnID'] = univ.ObjectIdentifier(ext.oid.dotted_string)
                extension_asn1['critical'] = ext.critical
                extension_asn1['extnValue'] = univ.OctetString(ext.value.public_bytes())
                extensions_asn1.setComponentByPosition(idx, extension_asn1)
            ext_schema = CmpCertTemplateBuilding._get_cert_template_field_schema('extensions')
            tagged_ext = extensions_asn1.clone(tagSet=ext_schema.tagSet, cloneValueFlag=True)
            cert_template['extensions'] = tagged_ext

        return cert_template


class CmpCertRequestBodyBuilding(BuildingComponent, LoggerMixin):
    """Build the PKI body from the ``CertTemplate``."""

    def build(self, context: BaseRequestContext) -> None:
        """Build the PKI body and store it in the context."""
        if not isinstance(context, CmpCertificateRequestContext):
            exc_msg = 'CmpCertRequestBodyBuilding requires a CmpCertificateRequestContext.'
            raise TypeError(exc_msg)

        request_data = context.request_data or {}
        validated = context.validated_request_data or {}

        cert_template = validated.get('_cert_template')
        if cert_template is None:
            exc_msg = '_cert_template is missing - run CmpCertTemplateBuilding first.'
            raise ValueError(exc_msg)

        private_key = request_data.get('private_key')
        if private_key is None:
            exc_msg = 'private_key is required in request_data.'
            raise ValueError(exc_msg)

        use_ir: bool = request_data.get('use_initialization_request', False)
        add_pop: bool = request_data.get('add_pop', True)

        try:
            cert_request = rfc4211.CertRequest()
            cert_request['certReqId'] = 0
            cert_request['certTemplate'] = cert_template

            cert_req_msg = rfc4211.CertReqMsg()
            cert_req_msg['certReq'] = cert_request

            if add_pop:
                pop = self._build_pop_signature(cert_request, private_key)
                cert_req_msg.setComponentByName('popo', pop, verifyConstraints=False)

            pki_body = rfc4210.PKIBody()
            body_choice = 'ir' if use_ir else 'cr'

            body_idx = pki_body.componentType.getPositionByName(body_choice)
            cert_req_messages = pki_body.componentType.getTypeByPosition(body_idx).clone()
            cert_req_messages.setComponentByPosition(0, cert_req_msg)
            pki_body[body_choice] = cert_req_messages

            validated['_pki_body'] = pki_body
            context.validated_request_data = validated

            self.logger.info(
                'PKI body (%s) built successfully',
                'IR' if use_ir else 'CR',
            )

        except Exception as e:
            msg = f'Failed to build CMP certification request body: {e!s}'
            raise CmpMessageBuilderError(msg) from e

    @staticmethod
    def _build_pop_signature(
        cert_request: rfc4211.CertRequest,
        private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    ) -> rfc4211.ProofOfPossession:
        """Build signature-based Proof-of-Possession.

        Args:
            cert_request: The certificate request to sign.
            private_key: Private key for signing.

        Returns:
            ``ProofOfPossession`` structure with signature.

        Raises:
            CmpMessageBuilderError: If the key type is unsupported.
        """
        encoded_cert_request = encoder.encode(cert_request)

        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(
                encoded_cert_request,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            algorithm_oid = AlgorithmIdentifier.RSA_SHA256.dotted_string
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            signature = private_key.sign(
                encoded_cert_request,
                ec.ECDSA(hashes.SHA256()),
            )
            algorithm_oid = AlgorithmIdentifier.ECDSA_SHA256.dotted_string
        else:
            msg = f'Unsupported private key type: {type(private_key)}'
            raise CmpMessageBuilderError(msg)

        popo_signing_key = rfc4211.POPOSigningKey()

        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id['algorithm'] = univ.ObjectIdentifier(algorithm_oid)
        popo_signing_key['algorithmIdentifier'] = alg_id

        binary_signature = f'{int.from_bytes(signature, byteorder="big"):b}'.zfill(len(signature) * 8)
        popo_signing_key['signature'] = univ.BitString(binary_signature)


        pop = rfc4211.ProofOfPossession()
        sig_idx = pop.componentType.getPositionByName('signature')
        sig_schema = pop.componentType.getTypeByPosition(sig_idx)
        tagged_signing_key = popo_signing_key.clone(
            tagSet=sig_schema.tagSet,
            cloneValueFlag=True,
        )
        pop['signature'] = tagged_signing_key

        return pop



class CmpPkiHeaderBuilding(BuildingComponent, LoggerMixin):
    """Build the PKI header for the CMP message."""

    def build(self, context: BaseRequestContext) -> None:
        """Build the PKI header and store it in the context."""
        if not isinstance(context, CmpCertificateRequestContext):
            exc_msg = 'CmpPkiHeaderBuilding requires a CmpCertificateRequestContext.'
            raise TypeError(exc_msg)

        request_data = context.request_data or {}
        validated = context.validated_request_data or {}

        subject: x509.Name | None = request_data.get('subject')
        recipient_name: str | None = request_data.get('recipient_name')

        if subject is None:
            exc_msg = 'subject is required in request_data for header building.'
            raise ValueError(exc_msg)
        if recipient_name is None:
            exc_msg = 'recipient_name is required in request_data for header building.'
            raise ValueError(exc_msg)

        sender_name = subject.rfc4514_string()

        try:
            transaction_id = os.urandom(TRANSACTION_ID_LENGTH)
            sender_nonce = os.urandom(SENDER_NONCE_LENGTH)

            header = rfc4210.PKIHeader()

            header['pvno'] = CMP_MESSAGE_VERSION

            header['sender'] = self._build_general_name_from_dn(sender_name)
            header['recipient'] = self._build_general_name_from_dn(recipient_name)

            now = datetime.now(UTC)
            current_time = now.strftime('%Y%m%d%H%M%SZ')
            header['messageTime'] = useful.GeneralizedTime(current_time).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )

            header['transactionID'] = univ.OctetString(value=transaction_id).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
            )

            header['senderNonce'] = univ.OctetString(value=sender_nonce).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)
            )

            sender_kid: int | None = request_data.get('sender_kid')
            if sender_kid is not None:
                kid_idx = header.componentType.getPositionByName('senderKID')
                kid_schema = header.componentType.getTypeByPosition(kid_idx).clone()
                kid_value = kid_schema.clone(value=str(sender_kid).encode())
                header['senderKID'] = kid_value

            header = self._add_implicit_confirm(header)

            prepare_protection: bool = request_data.get('prepare_shared_secret_protection', False)
            if prepare_protection:
                hmac_algorithm: HmacAlgorithm = request_data.get(
                    'hmac_algorithm', HmacAlgorithm.HMAC_SHA256,
                )
                header = self._prepare_protection_algorithm_pbm(
                    header, hmac_algorithm=hmac_algorithm,
                )

            validated['_pki_header'] = header
            context.validated_request_data = validated

            self.logger.info('PKI header built for sender: %s', sender_name)

        except Exception as e:
            msg = f'Failed to build CMP PKI header: {e!s}'
            raise CmpMessageBuilderError(msg) from e

    @staticmethod
    def _build_general_name_from_dn(dn_string: str) -> rfc5280.GeneralName:
        """Build a ``GeneralName`` from a distinguished name string."""
        name = x509.Name.from_rfc4514_string(dn_string)
        name_der = name.public_bytes(serialization.Encoding.DER)
        tagged_der = _der_tlv(0xA4, name_der)
        general_name, _ = decoder.decode(tagged_der, asn1Spec=rfc5280.GeneralName())
        return general_name

    @staticmethod
    def _add_implicit_confirm(header: rfc4210.PKIHeader) -> rfc4210.PKIHeader:
        """Add the implicit confirm ``InfoTypeAndValue`` entry to ``generalInfo``.

        Args:
            header: The PKI header to modify.

        Returns:
            The modified header with implicit confirm set.
        """
        general_info_idx = header.componentType.getPositionByName('generalInfo')
        general_info = header.componentType.getTypeByPosition(general_info_idx).clone()

        implicit_confirm = general_info.componentType.clone()
        implicit_confirm['infoType'] = univ.ObjectIdentifier(IMPLICIT_CONFIRM_OID)
        implicit_confirm['infoValue'] = univ.Any(hexValue='0500')

        general_info.setComponentByPosition(0, implicit_confirm)
        header['generalInfo'] = general_info

        return header

    @staticmethod
    def _prepare_protection_algorithm_pbm(
        header: rfc4210.PKIHeader,
        *,
        hmac_algorithm: HmacAlgorithm = HmacAlgorithm.HMAC_SHA256,
        iteration_count: int = 10000,
        salt_length: int = 16,
    ) -> rfc4210.PKIHeader:
        """Prepare the protection algorithm in the header for Password-Based MAC.

        Sets up the ``PBMParameter`` in the header's ``protectionAlg`` field so that
        ``CmpClient._add_protection_shared_secret`` can later compute the actual HMAC.

        Args:
            header: The PKI header to modify.
            hmac_algorithm: HMAC algorithm to use for protection.
            iteration_count: Number of iterations for key derivation.
            salt_length: Length of salt in bytes.

        Returns:
            The modified PKI header with protection algorithm set.
        """
        salt = os.urandom(salt_length)

        salt_der = bytes([0x04]) + bytes([len(salt)]) + salt

        owf = rfc5280.AlgorithmIdentifier()
        owf['algorithm'] = univ.ObjectIdentifier(SHA256_OID)
        owf_der = encoder.encode(owf)

        iteration_count_bytes = iteration_count.to_bytes(
            (iteration_count.bit_length() + 7) // 8 or 1, 'big',
        )
        iteration_count_der = (
            bytes([0x02]) + bytes([len(iteration_count_bytes)]) + iteration_count_bytes
        )

        mac_alg = rfc5280.AlgorithmIdentifier()
        mac_alg['algorithm'] = univ.ObjectIdentifier(hmac_algorithm.dotted_string)
        mac_der = encoder.encode(mac_alg)

        pbm_der = (
            bytes([0x30])
            + bytes([len(salt_der + owf_der + iteration_count_der + mac_der)])
            + salt_der + owf_der + iteration_count_der + mac_der
        )

        prot_alg_idx = header.componentType.getPositionByName('protectionAlg')
        prot_alg = header.componentType.getTypeByPosition(prot_alg_idx).clone()
        prot_alg['algorithm'] = univ.ObjectIdentifier(PBM_OID)
        prot_alg['parameters'] = univ.Any(value=pbm_der)

        header['protectionAlg'] = prot_alg

        return header



class CmpPkiMessageAssembly(BuildingComponent, LoggerMixin):
    """Assemble the final ``PKIMessage`` from header and body."""

    def build(self, context: BaseRequestContext) -> None:
        """Assemble the PKI message and store it in the context."""
        if not isinstance(context, CmpCertificateRequestContext):
            exc_msg = 'CmpPkiMessageAssembly requires a CmpCertificateRequestContext.'
            raise TypeError(exc_msg)

        validated = context.validated_request_data or {}

        header = validated.get('_pki_header')
        body = validated.get('_pki_body')

        if header is None:
            exc_msg = '_pki_header is missing - run CmpPkiHeaderBuilding first.'
            raise ValueError(exc_msg)
        if body is None:
            exc_msg = '_pki_body is missing - run CmpCertRequestBodyBuilding first.'
            raise ValueError(exc_msg)

        pki_message = rfc4210.PKIMessage()
        pki_message['header'] = header
        pki_message['body'] = body

        context.parsed_message = pki_message

        self.logger.info('CMP PKI message assembled successfully')


class CmpMessageBuilder(CompositeBuilding):
    """Composite builder for CMP certification/initialization request messages."""

    def __init__(self) -> None:
        """Initialize the composite builder with the default set of building components."""
        super().__init__()
        self.add(CmpCertTemplateBuilding())
        self.add(CmpCertRequestBodyBuilding())
        self.add(CmpPkiHeaderBuilding())
        self.add(CmpPkiMessageAssembly())
