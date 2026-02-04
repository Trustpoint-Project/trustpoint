"""CMP-specific message responder classes."""

from __future__ import annotations

import datetime
import secrets
from typing import TYPE_CHECKING, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.serialization import Encoding
from pyasn1.codec.der import decoder, encoder  # type: ignore[import-untyped]
from pyasn1.type import tag, univ, useful  # type: ignore[import-untyped]
from pyasn1_modules import rfc2459, rfc4210  # type: ignore[import-untyped]
from trustpoint_core.oid import HashAlgorithm, HmacAlgorithm

from devices.models import OnboardingStatus
from request.message_responder.base import AbstractMessageResponder
from request.operation_processor import LocalCaCmpSignatureProcessor
from request.request_context import CmpBaseRequestContext, CmpCertificateRequestContext, CmpRevocationRequestContext
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from pki.models import CredentialModel
    from request.request_context import BaseRequestContext

CMP_MESSAGE_VERSION = 2
SENDER_NONCE_LENGTH = 16


class CmpMessageResponder(AbstractMessageResponder, LoggerMixin):
    """Builds response to CMP requests."""

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Respond to a CMP message."""
        responder: CmpMessageResponder
        if isinstance(context, CmpCertificateRequestContext) and context.issued_certificate:
            if context.operation == 'initialization':
                responder = CmpInitializationResponder()
                return responder.build_response(context)
            if context.operation == 'certification':
                responder = CmpCertificationResponder()
                return responder.build_response(context)
        elif isinstance(context, CmpRevocationRequestContext):
            if context.operation == 'revocation':
                responder = CmpRevocationResponder()
                return responder.build_response(context)

        exc_msg = 'No suitable responder found for this CMP message.'
        CmpMessageResponder.logger.warning(exc_msg)
        context.http_response_status = 500
        context.http_response_content = exc_msg
        return CmpErrorMessageResponder().build_response(context)

    @staticmethod
    def _get_encoded_protected_part(cmp_message: rfc4210.PKIMessage) -> bytes:
        """Encode the protected part of the CMP message."""
        protected_part = rfc4210.ProtectedPart()
        protected_part['header'] = cmp_message['header']
        protected_part['infoValue'] = cmp_message['body']
        return cast('bytes', encoder.encode(protected_part))

    @staticmethod
    def _build_response_message_header(
            serialized_pyasn1_message: rfc4210.PKIMessage,
            sender_kid: rfc2459.KeyIdentifier,
            issuer_cert: x509.Certificate) -> rfc4210.PKIHeader:
        """Builds the PKI response message header for the IP and CP response messages."""
        header = rfc4210.PKIHeader()

        header['pvno'] = CMP_MESSAGE_VERSION

        raw_issuing_ca_subject = issuer_cert.subject.public_bytes()
        name, _ = decoder.decode(raw_issuing_ca_subject, asn1spec=rfc2459.Name())
        sender = rfc2459.GeneralName()
        sender['directoryName'][0] = name
        header['sender'] = sender

        header['recipient'] = serialized_pyasn1_message['header']['sender']

        current_time = datetime.datetime.now(datetime.UTC).strftime('%Y%m%d%H%M%SZ')
        header['messageTime'] = useful.GeneralizedTime(current_time).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )

        header['protectionAlg'] = serialized_pyasn1_message['header']['protectionAlg']

        header['senderKID'] = sender_kid

        header['transactionID'] = serialized_pyasn1_message['header']['transactionID']

        header['senderNonce'] = univ.OctetString(secrets.token_bytes(SENDER_NONCE_LENGTH)).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)
        )

        header['recipNonce'] = univ.OctetString(serialized_pyasn1_message['header']['senderNonce']).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
        )

        header['generalInfo'] = serialized_pyasn1_message['header']['generalInfo']

        return header

    @staticmethod
    def _add_protection_shared_secret(
            pki_message: rfc4210.PKIMessage, context: CmpBaseRequestContext
    ) -> rfc4210.PKIMessage:
        """Adds HMAC-based shared-secret protection to the base PKI message."""
        if not context.cmp_shared_secret:
            err_msg = 'CMP shared secret is not set in the context.'
            raise ValueError(err_msg)
        shared_secret = context.cmp_shared_secret
        parsed_request_message: rfc4210.PKIMessage = context.parsed_message

        # We are just copying protection parameters from the request message
        # TODO(Air): Check if that is needed for compatibility and/or could lead to too weak parameters  # noqa: FIX002
        pbm_parameters_bitstring = parsed_request_message['header']['protectionAlg']['parameters']
        decoded_pbm, _ = decoder.decode(pbm_parameters_bitstring, asn1Spec=rfc4210.PBMParameter())

        # Generate fresh salt
        salt = secrets.token_bytes(len(decoded_pbm['salt']))

        response_pbm_parameters = decoded_pbm
        response_pbm_parameters['salt'] = decoded_pbm['salt'].clone(salt)

        pki_message['header']['protectionAlg']['parameters'] = encoder.encode(response_pbm_parameters)

        try:
            owf = HashAlgorithm.from_dotted_string(decoded_pbm['owf']['algorithm'].prettyPrint())
        except Exception as exception:
            err_msg = 'owf algorithm not supported.'
            raise ValueError(err_msg) from exception

        iteration_count = int(decoded_pbm['iterationCount'])

        shared_secret_bytes = shared_secret.encode()
        salted_secret = shared_secret_bytes + salt
        hmac_key = salted_secret
        for _ in range(iteration_count):
            hasher = hashes.Hash(owf.hash_algorithm())
            hasher.update(hmac_key)
            hmac_key = hasher.finalize()

        hmac_algorithm_oid = decoded_pbm['mac']['algorithm'].prettyPrint()
        try:
            hmac_algorithm = HmacAlgorithm.from_dotted_string(hmac_algorithm_oid)
        except Exception as exception:
            err_msg = 'hmac algorithm not supported.'
            raise ValueError(err_msg) from exception

        encoded_protected_part = CmpMessageResponder._get_encoded_protected_part(pki_message)

        hmac_gen = hmac.HMAC(hmac_key, hmac_algorithm.hash_algorithm.hash_algorithm())

        hmac_gen.update(encoded_protected_part)
        hmac_digest = hmac_gen.finalize()

        binary_stuff = f'{int.from_bytes(hmac_digest, byteorder='big'):b}'.zfill(160)
        pki_message['protection'] = rfc4210.PKIProtection(univ.BitString(binary_stuff)).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )

        return pki_message

    @staticmethod
    def _sign_pki_message(
        pki_message: rfc4210.PKIMessage, context: CmpBaseRequestContext
        ) -> rfc4210.PKIMessage:
        """Applies signature-based protection to the base PKI message."""
        encoded_protected_part = CmpMessageResponder._get_encoded_protected_part(pki_message)

        signing_processor = LocalCaCmpSignatureProcessor(encoded_protected_part)
        signing_processor.process_operation(context)
        signature = signing_processor.get_signature()

        pki_message['protection'] = rfc4210.PKIProtection(univ.BitString.fromOctetString(signature)).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )

        return pki_message


class CmpInitializationResponder(CmpMessageResponder):
    """Respond to a CMP initialization request (IR) with the issued certificate (IP)."""

    @staticmethod
    def _build_base_ip_message(
            parsed_message: rfc4210.PKIMessage,
            issued_cert: x509.Certificate,
            issuer_credential: CredentialModel,
            sender_kid: rfc2459.KeyIdentifier,
            signer_credential: CredentialModel | None = None,
            ) -> rfc4210.PKIMessage:
        """Builds the IP response message (without the protection)."""
        ip_header = CmpInitializationResponder._build_response_message_header(
            serialized_pyasn1_message=parsed_message,
            sender_kid=sender_kid,
            issuer_cert=signer_credential.get_certificate() if signer_credential
                                                            else issuer_credential.get_certificate())

        ip_extra_certs = univ.SequenceOf()

        certificate_chain = [
            issuer_credential.get_certificate(),
            *issuer_credential.get_certificate_chain(),
        ]
        if signer_credential and issuer_credential.pk != signer_credential.pk:
            # Include both the DevOwnerID (signer) and the Issuer CA in extraCerts
            signer_chain = [
                signer_credential.get_certificate(),
                *signer_credential.get_certificate_chain(),
            ]
            certificate_chain = signer_chain + certificate_chain
        for certificate in certificate_chain:
            der_bytes = certificate.public_bytes(encoding=Encoding.DER)
            asn1_certificate, _ = decoder.decode(der_bytes, asn1Spec=rfc4210.CMPCertificate())
            ip_extra_certs.append(asn1_certificate)

        ip_body = rfc4210.PKIBody()
        ip_body['ip'] = rfc4210.CertRepMessage().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
        )
        ip_body['ip']['caPubs'] = univ.SequenceOf().subtype(
            sizeSpec=rfc4210.constraint.ValueSizeConstraint(1, rfc4210.MAX),
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1),
        )
        # TODO(AlexHx8472): Add TLS Server Certificate Root CA  # noqa: FIX002

        cert_response = rfc4210.CertResponse()
        cert_response['certReqId'] = 0

        pki_status_info = rfc4210.PKIStatusInfo()
        pki_status_info['status'] = 0
        cert_response['status'] = pki_status_info

        cmp_cert = rfc4210.CMPCertificate().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        )

        encoded_cert = issued_cert.public_bytes(encoding=Encoding.DER)
        der_cert, _ = decoder.decode(encoded_cert, asn1Spec=rfc4210.CMPCertificate())
        cmp_cert.setComponentByName('tbsCertificate', der_cert['tbsCertificate'])
        cmp_cert.setComponentByName('signatureValue', der_cert['signatureValue'])
        cmp_cert.setComponentByName('signatureAlgorithm', der_cert['signatureAlgorithm'])
        cert_or_enc_cert = rfc4210.CertOrEncCert()
        cert_or_enc_cert['certificate'] = cmp_cert

        cert_response['certifiedKeyPair']['certOrEncCert'] = cert_or_enc_cert

        ip_body['ip']['response'].append(cert_response)

        ip_message = rfc4210.PKIMessage()
        ip_message['header'] = ip_header
        ip_message['body'] = ip_body
        for extra_cert in ip_extra_certs:
            ip_message['extraCerts'].append(extra_cert)

        return ip_message


    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Respond to a CMP initialization message with the issued certificate."""
        if not isinstance(context, CmpCertificateRequestContext):
            exc_msg = 'CmpInitializationResponder requires a CmpCertificateRequestContext.'
            raise TypeError(exc_msg)

        if context.issued_certificate is None:
            exc_msg = 'Issued certificate is not set in the context.'
            raise ValueError(exc_msg)

        if context.issuer_credential is None:
            exc_msg = 'Issuer credential is not set in the context.'
            raise ValueError(exc_msg)
        issuing_ca_credential = context.issuer_credential

        # AOKI: Sign with owner credential
        signer_credential = context.owner_credential if context.owner_credential else issuing_ca_credential

        sender_ski = x509.SubjectKeyIdentifier.from_public_key(signer_credential.get_certificate().public_key())
        sender_kid = rfc2459.KeyIdentifier(sender_ski.digest).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        )

        pki_message = CmpInitializationResponder._build_base_ip_message(
            parsed_message=context.parsed_message,
            issued_cert=context.issued_certificate,
            sender_kid=sender_kid,
            issuer_credential=issuing_ca_credential,
            signer_credential=signer_credential
        )
        if context.cmp_shared_secret:
            pki_message = CmpInitializationResponder._add_protection_shared_secret(
                pki_message=pki_message, context=context
            )
        else:
            pki_message = CmpInitializationResponder._sign_pki_message(
                pki_message=pki_message, context=context
            )

        encoded_message = encoder.encode(pki_message)

        if context.device and context.device.onboarding_config:
            context.device.onboarding_config.onboarding_status = OnboardingStatus.ONBOARDED
            context.device.onboarding_config.save()
        context.http_response_status = 200
        context.http_response_content = encoded_message
        context.http_response_content_type = 'application/pkixcmp'


class CmpCertificationResponder(CmpMessageResponder):
    """Respond to a CMP certification request (CR) with the issued certificate (CP)."""

    @staticmethod
    def _build_base_cp_message(
            parsed_message: rfc4210.PKIMessage,
            issued_cert: x509.Certificate,
            issuer_credential: CredentialModel,
            sender_kid: rfc2459.KeyIdentifier,
    ) -> rfc4210.PKIMessage:
        """Builds the CR response message (without the protection)."""
        cp_header = CmpCertificationResponder._build_response_message_header(
            serialized_pyasn1_message=parsed_message,
            sender_kid=sender_kid,
            issuer_cert=issuer_credential.get_certificate())

        cp_extra_certs = univ.SequenceOf()

        certificate_chain = [
            issuer_credential.get_certificate(),
            *issuer_credential.get_certificate_chain(),
        ]
        for certificate in certificate_chain:
            der_bytes = certificate.public_bytes(encoding=Encoding.DER)
            asn1_certificate, _ = decoder.decode(der_bytes, asn1Spec=rfc4210.CMPCertificate())
            cp_extra_certs.append(asn1_certificate)

        cp_body = rfc4210.PKIBody()
        cp_body['cp'] = rfc4210.CertRepMessage().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)
        )
        cp_body['cp']['caPubs'] = univ.SequenceOf().subtype(
            sizeSpec=rfc4210.constraint.ValueSizeConstraint(1, rfc4210.MAX),
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1),
        )
        # TODO(AlexHx8472): Add TLS Server Certificate Root CA  # noqa: FIX002

        cert_response = rfc4210.CertResponse()
        cert_response['certReqId'] = 0

        pki_status_info = rfc4210.PKIStatusInfo()
        pki_status_info['status'] = 0
        cert_response['status'] = pki_status_info

        cmp_cert = rfc4210.CMPCertificate().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        )

        encoded_cert = issued_cert.public_bytes(encoding=Encoding.DER)
        der_cert, _ = decoder.decode(encoded_cert, asn1Spec=rfc4210.CMPCertificate())
        cmp_cert.setComponentByName('tbsCertificate', der_cert['tbsCertificate'])
        cmp_cert.setComponentByName('signatureValue', der_cert['signatureValue'])
        cmp_cert.setComponentByName('signatureAlgorithm', der_cert['signatureAlgorithm'])
        cert_or_enc_cert = rfc4210.CertOrEncCert()
        cert_or_enc_cert['certificate'] = cmp_cert

        cert_response['certifiedKeyPair']['certOrEncCert'] = cert_or_enc_cert

        cp_body['cp']['response'].append(cert_response)

        cp_message = rfc4210.PKIMessage()
        cp_message['header'] = cp_header
        cp_message['body'] = cp_body
        for extra_cert in cp_extra_certs:
            cp_message['extraCerts'].append(extra_cert)

        return cp_message

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Respond to a CMP certification message with the issued certificate."""
        if not isinstance(context, CmpCertificateRequestContext):
            exc_msg = 'CmpCertificationResponder requires a CmpCertificateRequestContext.'
            raise TypeError(exc_msg)

        if context.issued_certificate is None:
            exc_msg = 'Issued certificate is not set in the context.'
            raise ValueError(exc_msg)

        if context.issuer_credential is None:
            exc_msg = 'Issuer credential is not set in the context.'
            raise ValueError(exc_msg)
        issuing_ca_credential = context.issuer_credential

        sender_ski = x509.SubjectKeyIdentifier.from_public_key(issuing_ca_credential.get_certificate().public_key())
        sender_kid = rfc2459.KeyIdentifier(sender_ski.digest).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        )

        pki_message = CmpCertificationResponder._build_base_cp_message(
            parsed_message=context.parsed_message,
            issued_cert=context.issued_certificate,
            sender_kid=sender_kid,
            issuer_credential=issuing_ca_credential,
        )
        if context.cmp_shared_secret:
            pki_message = CmpCertificationResponder._add_protection_shared_secret(
                pki_message=pki_message, context=context
            )
        else:
            pki_message = CmpCertificationResponder._sign_pki_message(
                pki_message=pki_message, context=context
            )

        encoded_message = encoder.encode(pki_message)

        if context.device and context.device.onboarding_config:
            context.device.onboarding_config.onboarding_status = OnboardingStatus.ONBOARDED
            context.device.onboarding_config.save()
        context.http_response_status = 200
        context.http_response_content = encoded_message
        context.http_response_content_type = 'application/pkixcmp'


class CmpRevocationResponder(CmpMessageResponder):
    """Respond to a CMP revocation request (RR) with the revocation response (RP)."""

    @staticmethod
    def _build_base_rp_message(
            parsed_message: rfc4210.PKIMessage,
            issuer_credential: CredentialModel,
            sender_kid: rfc2459.KeyIdentifier,
    ) -> rfc4210.PKIMessage:
        """Builds the CR response message (without the protection)."""
        rp_header = CmpRevocationResponder._build_response_message_header(
            serialized_pyasn1_message=parsed_message,
            sender_kid=sender_kid,
            issuer_cert=issuer_credential.get_certificate())

        rp_extra_certs = univ.SequenceOf()

        certificate_chain = [
            issuer_credential.get_certificate(),
            *issuer_credential.get_certificate_chain(),
        ]
        for certificate in certificate_chain:
            der_bytes = certificate.public_bytes(encoding=Encoding.DER)
            asn1_certificate, _ = decoder.decode(der_bytes, asn1Spec=rfc4210.CMPCertificate())
            rp_extra_certs.append(asn1_certificate)

        rp_body = rfc4210.PKIBody()
        rp_body['rp'] = rfc4210.RevRepContent().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 12)
        )
        # rp_body['rp']['caPubs'] = univ.SequenceOf().subtype(
        #     sizeSpec=rfc4210.constraint.ValueSizeConstraint(1, rfc4210.MAX),
        #     explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1),
        # )
        # TODO(AlexHx8472): Add TLS Server Certificate Root CA  # noqa: FIX002

        # cert_response = rfc4210.CertResponse()
        # cert_response['certReqId'] = 0

        pki_status_info = rfc4210.PKIStatusInfo()
        pki_status_info['status'] = 0
        rp_body['rp']['status'].append(pki_status_info)

        # cmp_cert = rfc4210.CMPCertificate().subtype(
        #     explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        # )

        rp_message = rfc4210.PKIMessage()
        rp_message['header'] = rp_header
        rp_message['body'] = rp_body
        for extra_cert in rp_extra_certs:
            rp_message['extraCerts'].append(extra_cert)

        return rp_message

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Respond to a CMP revocation message with the revocation response."""
        if not isinstance(context, CmpRevocationRequestContext):
            exc_msg = 'CmpRevocationResponder requires a CmpRevocationRequestContext.'
            raise TypeError(exc_msg)

        if context.issuer_credential is None:
            exc_msg = 'Issuer credential is not set in the context.'
            raise ValueError(exc_msg)
        issuing_ca_credential = context.issuer_credential

        sender_ski = x509.SubjectKeyIdentifier.from_public_key(issuing_ca_credential.get_certificate().public_key())
        sender_kid = rfc2459.KeyIdentifier(sender_ski.digest).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        )
        pki_message = CmpRevocationResponder._build_base_rp_message(
            parsed_message=context.parsed_message,
            sender_kid=sender_kid,
            issuer_credential=issuing_ca_credential,
        )
        pki_message = CmpRevocationResponder._sign_pki_message(
            pki_message=pki_message, context=context
        )

        encoded_message = encoder.encode(pki_message)

        context.http_response_status = 200
        context.http_response_content = encoded_message
        context.http_response_content_type = 'application/pkixcmp'


class CmpErrorMessageResponder(CmpMessageResponder):
    """Respond to a CMP message with an error."""

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Respond to a CMP message with an error."""
        if not isinstance(context, CmpBaseRequestContext):
            exc_msg = 'CmpErrorMessageResponder requires a CmpBaseRequestContext.'
            raise TypeError(exc_msg)
        # Set appropriate HTTP status code and error message in context
        # TODO(Air): Use CMP error message format instead of plain text  # noqa: FIX002
        # perhaps add context.cmp_failure_status from PKIFailureInfo values
        context.http_response_status = context.http_response_status or 500
        context.http_response_content = context.http_response_content or 'An error occurred processing the CMP request.'
        context.http_response_content_type = context.http_response_content_type or 'text/plain'
