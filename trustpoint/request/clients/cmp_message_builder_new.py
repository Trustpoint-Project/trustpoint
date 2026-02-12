"""CMP PKIMessage builder for creating certification requests.

This module provides utilities for constructing CMP PKIMessages (IR/CR) that are
compatible with the Trustpoint CMP parser.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from pyasn1.codec.der import decoder, encoder  # type: ignore[import-untyped]
from pyasn1.type import tag, univ, useful  # type: ignore[import-untyped]
from pyasn1_modules import rfc2459, rfc2511, rfc4210, rfc4211, rfc5280  # type: ignore[import-untyped]
from trustpoint_core.oid import HmacAlgorithm

from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from pyasn1_modules.rfc4210 import PKIMessage  # type: ignore[import-untyped]


class CmpMessageBuilderError(Exception):
    """Base exception for CMP message builder errors."""


class CmpMessageBuilderMixin(LoggerMixin):
    """Mixin class providing CMP PKIMessage building functionality."""

    subject: x509.Name
    public_key_template: rsa.RSAPublicKey | ec.EllipticCurvePublicKey
    extensions: list[x509.Extension[x509.ExtensionType]] | None
    recipient_name: str
    sender_name: str
    use_initialization_request: bool

    def __init__(
        self,
        subject: x509.Name,
        public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
        recipient_name: str,
        extensions: list[x509.Extension[x509.ExtensionType]] | None = None,
    ) -> None:
        """Initialize the CMP message builder mixin.

        Args:
            subject: The subject name for the certificate.
            public_key: The public key for the certificate request.
            recipient_name: Distinguished name of the recipient CA.
            extensions: Optional list of extensions to include.
        """
        self.subject = subject
        self.public_key_template = public_key
        self.extensions = extensions
        self.recipient_name = recipient_name
        self.sender_name = subject.rfc4514_string()

    def _generate_transaction_id(self) -> bytes:
        """Generate a random transaction ID."""
        return os.urandom(16)

    def _generate_sender_nonce(self) -> bytes:
        """Generate a random sender nonce."""
        return os.urandom(16)

    def _build_general_name_from_dn(self, dn_string: str) -> rfc5280.GeneralName:
        """Build a GeneralName from a distinguished name string."""
        name = x509.Name.from_rfc4514_string(dn_string)
        name_der = name.public_bytes(serialization.Encoding.DER)
        tagged_der = bytes([0xA4]) + bytes([len(name_der)]) + name_der
        general_name, _ = decoder.decode(tagged_der, asn1Spec=rfc5280.GeneralName())
        return general_name

    def _build_cert_template(
        self,
        subject: x509.Name,
        public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
        extensions: list[x509.Extension[x509.ExtensionType]] | None = None,
    ) -> rfc2511.CertTemplate:
        """Build a CertTemplate from certificate components."""
        cert_template = rfc2511.CertTemplate()

        # Subject
        subject_der = subject.public_bytes(serialization.Encoding.DER)
        subject_asn1, _ = decoder.decode(subject_der, asn1Spec=rfc5280.Name())
        cert_template['subject'] = subject_asn1

        # Public key
        public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_key_asn1, _ = decoder.decode(public_key_der, asn1Spec=rfc5280.SubjectPublicKeyInfo())
        cert_template['publicKey'] = public_key_asn1

        # Extensions
        if extensions:
            extensions_asn1 = rfc2459.Extensions()
            for idx, ext in enumerate(extensions):
                extension_asn1 = rfc2459.Extension()
                extension_asn1['extnID'] = univ.ObjectIdentifier(ext.oid.dotted_string)
                extension_asn1['critical'] = ext.critical
                extension_asn1['extnValue'] = univ.OctetString(ext.value.public_bytes())
                extensions_asn1.setComponentByPosition(idx, extension_asn1)
            cert_template['extensions'] = extensions_asn1

        return cert_template

    def _build_pki_header(
        self,
        transaction_id: bytes,
        sender_nonce: bytes,
    ) -> rfc4210.PKIHeader:
        """Build the PKI header for the message."""
        header = rfc4210.PKIHeader()

        header['pvno'] = 2

        header['sender'] = self._build_general_name_from_dn(self.sender_name)

        header['recipient'] = self._build_general_name_from_dn(self.recipient_name)

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

        return header

    def _prepare_protection_algorithm_pbm(
        self,
        header: rfc4210.PKIHeader,
        *,
        hmac_algorithm: HmacAlgorithm = HmacAlgorithm.HMAC_SHA256,
        iteration_count: int = 10000,
        salt_length: int = 16,
    ) -> rfc4210.PKIHeader:
        """Prepare the protection algorithm in the header for Password-Based MAC."""
        salt = os.urandom(salt_length)

        salt_der = bytes([0x04]) + bytes([len(salt)]) + salt

        owf = rfc5280.AlgorithmIdentifier()
        owf['algorithm'] = univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1')
        owf_der = encoder.encode(owf)

        iteration_count_bytes = iteration_count.to_bytes((iteration_count.bit_length() + 7) // 8 or 1, 'big')
        iteration_count_der = bytes([0x02]) + bytes([len(iteration_count_bytes)]) + iteration_count_bytes

        mac_alg = rfc5280.AlgorithmIdentifier()
        mac_alg['algorithm'] = univ.ObjectIdentifier(hmac_algorithm.dotted_string)
        mac_der = encoder.encode(mac_alg)

        pbm_der = (
            bytes([0x30]) +
            bytes([len(salt_der + owf_der + iteration_count_der + mac_der)]) +
            salt_der + owf_der + iteration_count_der + mac_der
        )

        prot_alg = rfc5280.AlgorithmIdentifier()
        prot_alg['algorithm'] = univ.ObjectIdentifier('1.2.840.113533.7.66.13')
        prot_alg['parameters'] = univ.Any(value=pbm_der)

        tagged_alg = rfc5280.AlgorithmIdentifier()
        tagged_alg['algorithm'] = prot_alg['algorithm']
        tagged_alg['parameters'] = prot_alg['parameters']
        tagged_alg = tagged_alg.subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))

        header['protectionAlg'] = tagged_alg

        return header

    def _build_pki_message(
        self,
        private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
        *,
        add_pop: bool = True,
        prepare_shared_secret_protection: bool = False,
        hmac_algorithm: HmacAlgorithm = HmacAlgorithm.HMAC_SHA256,
    ) -> PKIMessage:
        """Build a CMP PKI message (CR or IR)."""
        try:
            public_key = private_key.public_key()

            cert_template = self._build_cert_template(self.subject, public_key, self.extensions)

            cert_request = rfc4211.CertRequest()
            cert_request['certReqId'] = 0
            cert_request['certTemplate'] = cert_template

            cert_req_msg = rfc4211.CertReqMsg()
            cert_req_msg['certReq'] = cert_request

            if add_pop:
                pop = self._build_pop_signature(cert_request, private_key)
                cert_req_msg.setComponentByName('popo', pop, verifyConstraints=False)

            pki_body = rfc4210.PKIBody()
            body_choice = 'ir' if self.use_initialization_request else 'cr'
            cert_req_messages = rfc4211.CertReqMessages()
            cert_req_messages.setComponentByPosition(0, cert_req_msg)
            pki_body.setComponentByName(body_choice, cert_req_messages, verifyConstraints=False)

            transaction_id = self._generate_transaction_id()
            sender_nonce = self._generate_sender_nonce()
            header = self._build_pki_header(transaction_id, sender_nonce)

            if prepare_shared_secret_protection:
                header = self._prepare_protection_algorithm_pbm(
                    header,
                    hmac_algorithm=hmac_algorithm,
                )

            pki_message = rfc4210.PKIMessage()
            pki_message['header'] = header
            pki_message['body'] = pki_body

            self.logger.info(
                'Built CMP %s message for subject: %s',
                'IR' if self.use_initialization_request else 'CR',
                self.sender_name,
            )

            return pki_message

        except Exception as e:
            msg = f'Failed to build CMP certification request: {e!s}'
            raise CmpMessageBuilderError(msg) from e

    def _build_pop_signature(
        self,
        cert_request: rfc4211.CertRequest,
        private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    ) -> rfc4211.ProofOfPossession:
        """Build signature-based Proof-of-Possession."""
        encoded_cert_request = encoder.encode(cert_request)

        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(
                encoded_cert_request,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            algorithm_oid = '1.2.840.113549.1.1.11'
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            signature = private_key.sign(
                encoded_cert_request,
                ec.ECDSA(hashes.SHA256()),
            )
            algorithm_oid = '1.2.840.10045.4.3.2'
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


class CmpInitializationRequest(CmpMessageBuilderMixin):
    """Builder for CMP Initialization Request (IR) messages."""

    def __init__(
        self,
        subject: x509.Name,
        public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
        recipient_name: str,
        extensions: list[x509.Extension[x509.ExtensionType]] | None = None,
    ) -> None:
        """Initialize the CMP Initialization Request builder."""
        super().__init__(subject, public_key, recipient_name, extensions)
        self.use_initialization_request = True

    def build(
        self,
        private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
        *,
        add_pop: bool = True,
        prepare_shared_secret_protection: bool = False,
        hmac_algorithm: HmacAlgorithm = HmacAlgorithm.HMAC_SHA256,
    ) -> PKIMessage:
        """Build a CMP Initialization Request (IR) message."""
        return self._build_pki_message(
            private_key=private_key,
            add_pop=add_pop,
            prepare_shared_secret_protection=prepare_shared_secret_protection,
            hmac_algorithm=hmac_algorithm,
        )


class CmpCertificationRequest(CmpMessageBuilderMixin):
    """Builder for CMP Certification Request (CR) messages."""

    def __init__(
        self,
        subject: x509.Name,
        public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
        recipient_name: str,
        extensions: list[x509.Extension[x509.ExtensionType]] | None = None,
    ) -> None:
        """Initialize the CMP Certification Request builder."""
        super().__init__(subject, public_key, recipient_name, extensions)
        self.use_initialization_request = False

    def build(
        self,
        private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
        *,
        add_pop: bool = True,
        prepare_shared_secret_protection: bool = False,
        hmac_algorithm: HmacAlgorithm = HmacAlgorithm.HMAC_SHA256,
    ) -> PKIMessage:
        """Build a CMP Certification Request (CR) message."""
        return self._build_pki_message(
            private_key=private_key,
            add_pop=add_pop,
            prepare_shared_secret_protection=prepare_shared_secret_protection,
            hmac_algorithm=hmac_algorithm,
        )
