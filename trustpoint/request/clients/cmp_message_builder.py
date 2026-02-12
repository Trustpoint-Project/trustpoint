"""CMP PKIMessage builder for creating certification requests from CertificateBuilder.

This module provides utilities for constructing CMP PKIMessages (IR/CR) from
cryptography.x509.CertificateBuilder objects, enabling Trustpoint to request
certificates from upstream CMP servers.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from pyasn1.codec.der import decoder, encoder  # type: ignore[import-untyped]
from pyasn1.type import univ  # type: ignore[import-untyped]
from pyasn1_modules import rfc4210, rfc5280  # type: ignore[import-untyped]
from trustpoint_core.oid import HmacAlgorithm

from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from cryptography.x509.base import CertificateBuilder
    from pyasn1_modules.rfc4210 import PKIMessage  # type: ignore[import-untyped]


class CmpMessageBuilderError(Exception):
    """Base exception for CMP message builder errors."""


class CmpMessageBuilderMixin(LoggerMixin):
    """Mixin class providing CMP PKIMessage building functionality.

    This mixin provides core functionality for constructing CMP messages from
    CertificateBuilder objects. It handles:
    - Converting CertificateBuilder to CertTemplate
    - Building CertReqMsg structures
    - Creating complete PKIMessage with header and protection preparation
    """

    certificate_builder: CertificateBuilder
    recipient_name: str
    use_initialization_request: bool

    def __init__(
        self,
        certificate_builder: CertificateBuilder,
        recipient_name: str,
    ) -> None:
        """Initialize the CMP message builder mixin.

        Args:
            certificate_builder: Certificate builder with subject, extensions, etc.
                                The subject will be used as the sender name.
            recipient_name: Distinguished name of the recipient CA (e.g., "CN=CA,O=Company").
        """
        self.certificate_builder = certificate_builder
        self.recipient_name = recipient_name

    @property
    def sender_name(self) -> str:
        """Extract sender name from the certificate builder's subject.

        Returns:
            The subject DN in RFC 4514 format.

        Raises:
            CmpMessageBuilderError: If certificate builder has no subject.
        """
        try:
            subject = self.certificate_builder._subject  # noqa: SLF001
            if subject is None:
                msg = 'CertificateBuilder must have a subject set'
                raise CmpMessageBuilderError(msg)
            return subject.rfc4514_string()
        except AttributeError as e:
            msg = 'CertificateBuilder must have a subject set'
            raise CmpMessageBuilderError(msg) from e

    def _generate_transaction_id(self) -> bytes:
        """Generate a random transaction ID.

        Returns:
            16 random bytes for the transaction ID.
        """
        return os.urandom(16)

    def _generate_sender_nonce(self) -> bytes:
        """Generate a random sender nonce.

        Returns:
            16 random bytes for the sender nonce.
        """
        return os.urandom(16)

    def _build_general_name_from_dn(self, dn_string: str) -> rfc4210.GeneralName:
        """Build a GeneralName from a distinguished name string.

        Args:
            dn_string: DN string in RFC 4514 format (e.g., "CN=Device,O=Company").

        Returns:
            GeneralName with directoryName choice.
        """
        # Parse the DN string using cryptography
        name = x509.Name.from_rfc4514_string(dn_string)

        # Convert to pyasn1 Name
        name_der = name.public_bytes(serialization.Encoding.DER)
        pyasn1_name, _ = decoder.decode(name_der, asn1Spec=rfc5280.Name())

        # Create GeneralName with directoryName
        general_name = rfc4210.GeneralName()
        general_name['directoryName'] = pyasn1_name
        return general_name

    def _build_cert_template(
        self,
        certificate_builder: CertificateBuilder,
        public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
    ) -> rfc4210.CertTemplate:
        """Build a CertTemplate from a CertificateBuilder.

        Args:
            certificate_builder: The certificate builder with subject, extensions, etc.
            public_key: The public key for the certificate request.

        Returns:
            The constructed CertTemplate.

        Raises:
            CmpMessageBuilderError: If the certificate builder is invalid.
        """
        cert_template = rfc4210.CertTemplate()

        # Extract subject from certificate builder
        # Note: We need to access the private _subject attribute as there's no public API
        try:
            subject = certificate_builder._subject  # noqa: SLF001
            if subject:
                subject_der = subject.public_bytes(serialization.Encoding.DER)
                pyasn1_subject, _ = decoder.decode(subject_der, asn1Spec=rfc5280.Name())
                cert_template['subject'] = pyasn1_subject
        except AttributeError as e:
            msg = 'CertificateBuilder must have a subject set'
            raise CmpMessageBuilderError(msg) from e

        # Add public key
        public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pyasn1_pubkey, _ = decoder.decode(
            public_key_der,
            asn1Spec=rfc5280.SubjectPublicKeyInfo(),
        )
        cert_template['publicKey'] = pyasn1_pubkey

        # Add extensions if present
        try:
            extensions = certificate_builder._extensions  # noqa: SLF001
            if extensions:
                extensions_asn1 = rfc5280.Extensions()
                for idx, ext in enumerate(extensions):
                    extension_asn1 = rfc5280.Extension()
                    extension_asn1['extnID'] = univ.ObjectIdentifier(ext.oid.dotted_string)
                    extension_asn1['critical'] = ext.critical
                    extension_asn1['extnValue'] = ext.value.public_bytes()
                    extensions_asn1[idx] = extension_asn1
                cert_template['extensions'] = extensions_asn1
        except AttributeError:
            # No extensions - that's okay
            pass

        return cert_template

    def _build_pki_header(
        self,
        transaction_id: bytes,
        sender_nonce: bytes,
    ) -> rfc4210.PKIHeader:
        """Build the PKI header for the message.

        Args:
            transaction_id: Transaction ID for the request.
            sender_nonce: Sender nonce for the request.

        Returns:
            The constructed PKI header.
        """
        header = rfc4210.PKIHeader()

        # Protocol version (cmp2000 = 2)
        header['pvno'] = 2

        # Sender
        header['sender'] = self._build_general_name_from_dn(self.sender_name)

        # Recipient
        header['recipient'] = self._build_general_name_from_dn(self.recipient_name)

        # Message time
        now = datetime.now(UTC)
        generalized_time = univ.GeneralizedTime(now.strftime('%Y%m%d%H%M%SZ'))
        header['messageTime'] = generalized_time

        # Protection algorithm (placeholder - will be set when adding protection)
        prot_alg = rfc4210.AlgorithmIdentifier()
        prot_alg['algorithm'] = univ.ObjectIdentifier('1.2.840.113549.1.1.5')  # sha1WithRSAEncryption placeholder
        header['protectionAlg'] = prot_alg

        # Transaction ID
        header['transactionID'] = univ.OctetString(hexValue=transaction_id.hex())

        # Sender nonce
        header['senderNonce'] = univ.OctetString(hexValue=sender_nonce.hex())

        return header

    def _prepare_protection_algorithm_pbm(
        self,
        header: rfc4210.PKIHeader,
        *,
        hmac_algorithm: HmacAlgorithm = HmacAlgorithm.HMAC_SHA256,
        iteration_count: int = 10000,
        salt_length: int = 16,
    ) -> rfc4210.PKIHeader:
        """Prepare the protection algorithm in the header for Password-Based MAC.

        This sets up the PBMParameter in the header's protectionAlg field.
        The actual protection (HMAC) will be added later by the CMP client.

        Args:
            header: The PKI header to modify.
            hmac_algorithm: HMAC algorithm to use for protection.
            iteration_count: Number of iterations for key derivation.
            salt_length: Length of salt in bytes.

        Returns:
            The modified PKI header with protection algorithm set.
        """
        # Generate random salt
        salt = os.urandom(salt_length)

        # Build PBMParameter
        pbm_param = rfc4210.PBMParameter()

        # Salt
        pbm_param['salt'] = univ.OctetString(hexValue=salt.hex())

        # OWF (One-Way Function) - SHA256
        owf = rfc4210.AlgorithmIdentifier()
        owf['algorithm'] = univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1')  # id-sha256
        pbm_param['owf'] = owf

        # Iteration count
        pbm_param['iterationCount'] = iteration_count

        # MAC algorithm
        mac_alg = rfc4210.AlgorithmIdentifier()
        mac_alg['algorithm'] = univ.ObjectIdentifier(hmac_algorithm.oid)
        pbm_param['mac'] = mac_alg

        # Encode PBMParameter
        encoded_pbm = encoder.encode(pbm_param)

        # Set protection algorithm in header
        prot_alg = rfc4210.AlgorithmIdentifier()
        prot_alg['algorithm'] = univ.ObjectIdentifier('1.2.840.113533.7.66.13')  # id-PasswordBasedMac
        prot_alg['parameters'] = univ.Any(hexValue=encoded_pbm.hex())

        header['protectionAlg'] = prot_alg

        return header

    def _build_pki_message(
        self,
        private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
        *,
        add_pop: bool = True,
        prepare_shared_secret_protection: bool = False,
        hmac_algorithm: HmacAlgorithm = HmacAlgorithm.HMAC_SHA256,
    ) -> PKIMessage:
        """Build a CMP PKI message (CR or IR) from the configured CertificateBuilder.

        This is an internal method that builds either an IR or CR message depending
        on the use_initialization_request flag.

        Args:
            private_key: Private key corresponding to the public key in the request.
            add_pop: If True, adds Proof-of-Possession (signature-based).
            prepare_shared_secret_protection: If True, prepares the header for
                                             shared secret protection (PBM).
            hmac_algorithm: HMAC algorithm to use if preparing shared secret protection.

        Returns:
            The constructed PKIMessage (CR or IR).

        Raises:
            CmpMessageBuilderError: If message construction fails.
        """
        try:
            # Get public key from private key
            public_key = private_key.public_key()

            # Build CertTemplate
            cert_template = self._build_cert_template(self.certificate_builder, public_key)

            # Build CertRequest
            cert_request = rfc4210.CertRequest()
            cert_request['certReqId'] = 0
            cert_request['certTemplate'] = cert_template

            # Build CertReqMsg
            cert_req_msg = rfc4210.CertReqMsg()
            cert_req_msg['certReq'] = cert_request

            # Add Proof-of-Possession if requested
            if add_pop:
                pop = self._build_pop_signature(cert_request, private_key)
                cert_req_msg['popo'] = pop

            # Build PKI body (IR or CR)
            pki_body = rfc4210.PKIBody()
            body_choice = 'ir' if self.use_initialization_request else 'cr'
            cert_req_messages = rfc4210.CertReqMessages()
            cert_req_messages[0] = cert_req_msg
            pki_body[body_choice] = cert_req_messages

            # Build PKI header
            transaction_id = self._generate_transaction_id()
            sender_nonce = self._generate_sender_nonce()
            header = self._build_pki_header(transaction_id, sender_nonce)

            # Prepare protection if requested
            if prepare_shared_secret_protection:
                header = self._prepare_protection_algorithm_pbm(
                    header,
                    hmac_algorithm=hmac_algorithm,
                )

            # Build complete PKI message
            pki_message = rfc4210.PKIMessage()
            pki_message['header'] = header
            pki_message['body'] = pki_body

        except Exception as e:
            msg = f'Failed to build CMP certification request: {e!s}'
            raise CmpMessageBuilderError(msg) from e
        else:
            self.logger.info(
                'Built CMP %s message for subject: %s',
                'IR' if self.use_initialization_request else 'CR',
                self.sender_name,
            )

            return pki_message

    def _build_pop_signature(
        self,
        cert_request: rfc4210.CertRequest,
        private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    ) -> rfc4210.ProofOfPossession:
        """Build signature-based Proof-of-Possession.

        Args:
            cert_request: The certificate request to sign.
            private_key: Private key for signing.

        Returns:
            ProofOfPossession structure with signature.
        """
        # Encode the CertRequest
        encoded_cert_request = encoder.encode(cert_request)

        # Sign the encoded request
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

        # Build POPOSigningKey
        popo_signing_key = rfc4210.POPOSigningKey()

        # Algorithm identifier
        alg_id = rfc4210.AlgorithmIdentifier()
        alg_id['algorithm'] = univ.ObjectIdentifier(algorithm_oid)
        popo_signing_key['algorithmIdentifier'] = alg_id

        # Signature
        binary_signature = f'{int.from_bytes(signature, byteorder="big"):b}'.zfill(len(signature) * 8)
        popo_signing_key['signature'] = univ.BitString(binary_signature)

        # Build ProofOfPossession
        pop = rfc4210.ProofOfPossession()
        pop['signature'] = popo_signing_key

        return pop


class CmpInitializationRequest(CmpMessageBuilderMixin):
    """Builder for CMP Initialization Request (IR) messages.

    Use this class when a device or entity is requesting its first certificate
    from a CA (initial enrollment). An IR is typically used when:
    - The entity has no existing certificate from the CA
    - This is the first time the entity is enrolling with the CA
    - The entity needs to establish its initial identity (LDevID)
    """

    def __init__(
        self,
        certificate_builder: CertificateBuilder,
        recipient_name: str,
    ) -> None:
        """Initialize the CMP Initialization Request builder.

        Args:
            certificate_builder: Certificate builder with subject, extensions, etc.
                                The subject will be used as the sender name.
            recipient_name: Distinguished name of the recipient CA (e.g., "CN=CA,O=Company").
        """
        super().__init__(certificate_builder, recipient_name)
        self.use_initialization_request = True

    def build(
        self,
        private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
        *,
        add_pop: bool = True,
        prepare_shared_secret_protection: bool = False,
        hmac_algorithm: HmacAlgorithm = HmacAlgorithm.HMAC_SHA256,
    ) -> PKIMessage:
        """Build a CMP Initialization Request (IR) message.

        Args:
            private_key: Private key corresponding to the public key in the request.
            add_pop: If True, adds Proof-of-Possession (signature-based).
            prepare_shared_secret_protection: If True, prepares the header for
                                             shared secret protection (PBM).
            hmac_algorithm: HMAC algorithm to use if preparing shared secret protection.

        Returns:
            The constructed PKIMessage (IR).

        Raises:
            CmpMessageBuilderError: If message construction fails.
        """
        return self._build_pki_message(
            private_key=private_key,
            add_pop=add_pop,
            prepare_shared_secret_protection=prepare_shared_secret_protection,
            hmac_algorithm=hmac_algorithm,
        )


class CmpCertificationRequest(CmpMessageBuilderMixin):
    """Builder for CMP Certification Request (CR) messages.

    Use this class when a device or entity is requesting a subsequent certificate
    from a CA (renewal or additional certificate). A CR is typically used when:
    - The entity already has an existing certificate from the CA
    - This is a renewal or re-enrollment operation
    - The entity is requesting an additional certificate (e.g., TLS, signing)
    """

    def __init__(
        self,
        certificate_builder: CertificateBuilder,
        recipient_name: str,
    ) -> None:
        """Initialize the CMP Certification Request builder.

        Args:
            certificate_builder: Certificate builder with subject, extensions, etc.
                                The subject will be used as the sender name.
            recipient_name: Distinguished name of the recipient CA (e.g., "CN=CA,O=Company").
        """
        super().__init__(certificate_builder, recipient_name)
        self.use_initialization_request = False

    def build(
        self,
        private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
        *,
        add_pop: bool = True,
        prepare_shared_secret_protection: bool = False,
        hmac_algorithm: HmacAlgorithm = HmacAlgorithm.HMAC_SHA256,
    ) -> PKIMessage:
        """Build a CMP Certification Request (CR) message.

        Args:
            private_key: Private key corresponding to the public key in the request.
            add_pop: If True, adds Proof-of-Possession (signature-based).
            prepare_shared_secret_protection: If True, prepares the header for
                                             shared secret protection (PBM).
            hmac_algorithm: HMAC algorithm to use if preparing shared secret protection.

        Returns:
            The constructed PKIMessage (CR).

        Raises:
            CmpMessageBuilderError: If message construction fails.
        """
        return self._build_pki_message(
            private_key=private_key,
            add_pop=add_pop,
            prepare_shared_secret_protection=prepare_shared_secret_protection,
            hmac_algorithm=hmac_algorithm,
        )
