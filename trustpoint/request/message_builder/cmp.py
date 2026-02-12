"""Provides classes for building CMP PKI messages.

This module mirrors the structure of ``message_parser/cmp.py`` but for the *building*
direction.  Where ``CmpPkiMessageParsing`` takes raw bytes → ``PKIMessage`` in the
context, the builders here take request context data → ``PKIMessage`` ready to be
sent by ``CmpClient``.

Building components
-------------------
* ``CmpCertTemplateBuilding`` - builds a ``CertTemplate`` from the context's
  certificate request data (subject, public key, extensions).
* ``CmpCertRequestBodyBuilding`` - wraps the template in a ``CertReqMsg``/``CertReqMessages``
  and sets the PKI body (IR or CR), optionally adding Proof-of-Possession.
* ``CmpPkiHeaderBuilding`` - constructs the PKI header (pvno, sender, recipient,
  transactionID, senderNonce, messageTime, implicit confirm, protection algorithm).
* ``CmpPkiMessageAssembly`` - assembles header + body into the final ``PKIMessage``.

Composite
---------
* ``CmpMessageBuilder`` - composite that chains all components in order.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from pyasn1.codec.der import decoder, encoder  # type: ignore[import-untyped]
from pyasn1.type import tag, univ, useful  # type: ignore[import-untyped]
from pyasn1_modules import rfc3280, rfc4210, rfc4211, rfc5280  # type: ignore[import-untyped]
from trustpoint_core.oid import HmacAlgorithm

from request.request_context import (
    BaseRequestContext,
    CmpCertificateRequestContext,
)
from trustpoint.logger import LoggerMixin

from .base import BuildingComponent, CompositeBuilding


class CmpMessageBuilderError(Exception):
    """Base exception for CMP message builder errors."""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CMP_MESSAGE_VERSION = 2
TRANSACTION_ID_LENGTH = 16
SENDER_NONCE_LENGTH = 16
IMPLICIT_CONFIRM_OID = '1.3.6.1.5.5.7.4.13'
PBM_OID = '1.2.840.113533.7.66.13'  # id-PasswordBasedMac
SHA256_OID = '2.16.840.1.101.3.4.2.1'


# ---------------------------------------------------------------------------
# 1. CertTemplate building
# ---------------------------------------------------------------------------
class CmpCertTemplateBuilding(BuildingComponent, LoggerMixin):
    """Build a ``CertTemplate`` from the context's certificate request data.

    Reads from ``context``:
    * ``subject`` - ``x509.Name``
    * ``public_key`` - ``rsa.RSAPublicKey | ec.EllipticCurvePublicKey``
    * ``extensions`` - optional list of ``x509.Extension``

    Stores into ``context``:
    * ``_cert_template`` - the constructed ``rfc4211.CertTemplate``
    """

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
        """Return the schema type (with correct implicit tag) for a ``CertTemplate`` field.

        ``rfc4211.CertTemplate`` uses implicit context tags on every optional field.
        When we decode a value with a *plain* ASN.1 spec (e.g. ``rfc3280.Name()``),
        the decoded object carries no implicit tag.  pyasn1 refuses to assign such a
        value to the tagged slot.  We need the *schema* object so that we can
        ``clone`` the decoded value with the correct ``tagSet``.
        """
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

        Uses ``rfc4211.CertTemplate`` which carries implicit context tags on all
        fields (e.g. ``[5] IMPLICIT Name`` for *subject*).  After decoding from
        DER with a plain spec we must ``clone`` the result with the schema's
        ``tagSet`` so that pyasn1 accepts the assignment.

        For **CHOICE** types (``Name``), we additionally need to re-set the
        inner chosen component because ``clone`` only copies the outer tag.
        For **SEQUENCE** types (``SubjectPublicKeyInfo``, ``Extensions``),
        ``clone(..., cloneValueFlag=True)`` suffices.

        Args:
            subject: The subject name for the certificate.
            public_key: The public key for the certificate request.
            extensions: Optional list of extensions to include.

        Returns:
            The constructed ``CertTemplate``.
        """
        cert_template = rfc4211.CertTemplate()

        # --- Subject (Name is a CHOICE → special handling) ----------------
        subject_der = subject.public_bytes(serialization.Encoding.DER)
        subject_asn1, _ = decoder.decode(subject_der, asn1Spec=rfc3280.Name())
        subject_schema = CmpCertTemplateBuilding._get_cert_template_field_schema('subject')
        tagged_subject = subject_asn1.clone(tagSet=subject_schema.tagSet)
        tagged_subject['rdnSequence'] = subject_asn1.getComponent()
        cert_template['subject'] = tagged_subject

        # --- Public key (SubjectPublicKeyInfo is a SEQUENCE) --------------
        public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_key_asn1, _ = decoder.decode(public_key_der, asn1Spec=rfc3280.SubjectPublicKeyInfo())
        pubkey_schema = CmpCertTemplateBuilding._get_cert_template_field_schema('publicKey')
        tagged_pubkey = public_key_asn1.clone(tagSet=pubkey_schema.tagSet, cloneValueFlag=True)
        cert_template['publicKey'] = tagged_pubkey

        # --- Extensions (SEQUENCE OF Extension) ---------------------------
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


# ---------------------------------------------------------------------------
# 2. CertRequest body building (CertReqMsg + PKIBody + optional PoP)
# ---------------------------------------------------------------------------
class CmpCertRequestBodyBuilding(BuildingComponent, LoggerMixin):
    """Build the PKI body from the ``CertTemplate``.

    Reads from ``context``:
    * ``validated_request_data['_cert_template']`` - the CertTemplate
    * ``request_data['private_key']`` - private key (for PoP signature)
    * ``request_data['use_initialization_request']`` - bool, IR vs CR
    * ``request_data.get('add_pop', True)`` - whether to add Proof-of-Possession

    Stores into ``context``:
    * ``validated_request_data['_pki_body']`` - the constructed ``rfc4210.PKIBody``
    """

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
            # CertRequest
            cert_request = rfc4211.CertRequest()
            cert_request['certReqId'] = 0
            cert_request['certTemplate'] = cert_template

            # CertReqMsg
            cert_req_msg = rfc4211.CertReqMsg()
            cert_req_msg['certReq'] = cert_request

            # Proof-of-Possession
            if add_pop:
                pop = self._build_pop_signature(cert_request, private_key)
                cert_req_msg.setComponentByName('popo', pop, verifyConstraints=False)

            # PKI body
            pki_body = rfc4210.PKIBody()
            body_choice = 'ir' if use_ir else 'cr'
            cert_req_messages = rfc4211.CertReqMessages()
            cert_req_messages.setComponentByPosition(0, cert_req_msg)
            pki_body.setComponentByName(body_choice, cert_req_messages, verifyConstraints=False)

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
            algorithm_oid = '1.2.840.113549.1.1.11'  # sha256WithRSAEncryption
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            signature = private_key.sign(
                encoded_cert_request,
                ec.ECDSA(hashes.SHA256()),
            )
            algorithm_oid = '1.2.840.10045.4.3.2'  # ecdsa-with-SHA256
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
        pop.setComponentByName('signature', popo_signing_key, verifyConstraints=False)

        return pop


# ---------------------------------------------------------------------------
# 3. PKI header building
# ---------------------------------------------------------------------------
class CmpPkiHeaderBuilding(BuildingComponent, LoggerMixin):
    """Build the PKI header for the CMP message.

    Constructs the header with:
    * pvno = 2  (cmp2000)
    * sender / recipient as ``GeneralName`` (directoryName)
    * messageTime
    * transactionID  (16 random bytes)
    * senderNonce    (16 random bytes)
    * generalInfo    with implicit confirm entry
    * protectionAlg  (PBM) if ``prepare_shared_secret_protection`` is requested

    Reads from ``context``:
    * ``request_data['subject']``        - ``x509.Name`` (sender)
    * ``request_data['recipient_name']`` - str DN (recipient)
    * ``request_data.get('prepare_shared_secret_protection', False)``
    * ``request_data.get('hmac_algorithm', HmacAlgorithm.HMAC_SHA256)``

    Stores into ``context``:
    * ``validated_request_data['_pki_header']``
    """

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

            # Protocol version
            header['pvno'] = CMP_MESSAGE_VERSION

            # Sender
            header['sender'] = self._build_general_name_from_dn(sender_name)

            # Recipient
            header['recipient'] = self._build_general_name_from_dn(recipient_name)

            # Message time
            now = datetime.now(UTC)
            current_time = now.strftime('%Y%m%d%H%M%SZ')
            header['messageTime'] = useful.GeneralizedTime(current_time).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )

            # Transaction ID
            header['transactionID'] = univ.OctetString(value=transaction_id).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
            )

            # Sender nonce
            header['senderNonce'] = univ.OctetString(value=sender_nonce).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)
            )

            # Implicit confirm (generalInfo)
            header = self._add_implicit_confirm(header)

            # Protection algorithm (PBM) if requested
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
        """Build a ``GeneralName`` from a distinguished name string.

        Args:
            dn_string: DN string in RFC 4514 format (e.g., ``CN=Device,O=Company``).

        Returns:
            ``GeneralName`` with ``directoryName`` choice.
        """
        name = x509.Name.from_rfc4514_string(dn_string)
        name_der = name.public_bytes(serialization.Encoding.DER)
        # Wrap in context-specific [4] tag for directoryName
        tagged_der = bytes([0xA4]) + bytes([len(name_der)]) + name_der
        general_name, _ = decoder.decode(tagged_der, asn1Spec=rfc5280.GeneralName())
        return general_name

    @staticmethod
    def _add_implicit_confirm(header: rfc4210.PKIHeader) -> rfc4210.PKIHeader:
        """Add the implicit confirm ``InfoTypeAndValue`` entry to ``generalInfo``.

        The implicit confirm extension (OID 1.3.6.1.5.5.7.4.13) signals to the CA
        that no certConf/PKIConfirm exchange is needed.  Its value is ASN.1 NULL
        (DER ``0x0500``).

        We must obtain the ``generalInfo`` SequenceOf *schema* from the header's own
        ``componentType`` so that the inner ``InfoTypeAndValue`` carries the correct
        ``subtypeSpec`` constraints.  Using a standalone ``rfc4210.InfoTypeAndValue()``
        would fail pyasn1's tag-compatibility check because the SequenceOf's
        ``componentType`` has an additional ``ValueSizeConstraint(1, inf)``.

        Args:
            header: The PKI header to modify.

        Returns:
            The modified header with implicit confirm set.
        """
        # Get the generalInfo SequenceOf schema from the header definition
        general_info_idx = header.componentType.getPositionByName('generalInfo')
        general_info = header.componentType.getTypeByPosition(general_info_idx).clone()

        # Create the InfoTypeAndValue from the SequenceOf's own componentType
        # so it inherits the correct subtypeSpec constraints.
        implicit_confirm = general_info.componentType.clone()
        implicit_confirm['infoType'] = univ.ObjectIdentifier(IMPLICIT_CONFIRM_OID)
        implicit_confirm['infoValue'] = univ.Any(hexValue='0500')  # ASN.1 NULL

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


# ---------------------------------------------------------------------------
# 4. Final PKIMessage assembly
# ---------------------------------------------------------------------------
class CmpPkiMessageAssembly(BuildingComponent, LoggerMixin):
    """Assemble the final ``PKIMessage`` from header and body.

    Reads from ``context``:
    * ``validated_request_data['_pki_header']``
    * ``validated_request_data['_pki_body']``

    Stores into ``context``:
    * ``parsed_message`` - the final ``rfc4210.PKIMessage`` (ready for ``CmpClient``)
    """

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


# ---------------------------------------------------------------------------
# 5. Composite builder  (mirrors CmpMessageParser)
# ---------------------------------------------------------------------------
class CmpMessageBuilder(CompositeBuilding):
    """Composite builder for CMP certification/initialization request messages.

    Mirrors ``CmpMessageParser`` from ``message_parser/cmp.py``:

    * ``CmpMessageParser``  chains:  PkiMessageParsing → BodyValidation → HeaderValidation → Domain → Profile
    * ``CmpMessageBuilder`` chains:  CertTemplateBuilding → CertRequestBodyBuilding → PkiHeaderBuilding → Assembly

    Usage::

        context = CmpCertificateRequestContext(
            protocol='cmp',
            operation='certification',  # or 'initialization'
            request_data={
                'subject': x509.Name([...]),
                'public_key': public_key,
                'private_key': private_key,
                'recipient_name': 'CN=CA,O=Company',
                'extensions': [...],                      # optional
                'use_initialization_request': False,       # True for IR
                'add_pop': True,                           # default
                'prepare_shared_secret_protection': True,  # optional
                'hmac_algorithm': HmacAlgorithm.HMAC_SHA256,  # optional
            },
            cmp_server_host='cmp.example.com',
            cmp_shared_secret='secret',
        )

        builder = CmpMessageBuilder()
        builder.build(context)

        # context.parsed_message is now the rfc4210.PKIMessage
        cmp_client = CmpClient(context)
        cert = cmp_client.send_and_extract_certificate(
            context.parsed_message,
            add_shared_secret_protection=True,
        )
    """

    def __init__(self) -> None:
        """Initialize the composite builder with the default set of building components."""
        super().__init__()
        self.add(CmpCertTemplateBuilding())
        self.add(CmpCertRequestBodyBuilding())
        self.add(CmpPkiHeaderBuilding())
        self.add(CmpPkiMessageAssembly())
