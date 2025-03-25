"""This module contains the CMP endpoints (views)."""

from __future__ import annotations

import datetime
import enum
import ipaddress
import re
import secrets
import uuid
from typing import TYPE_CHECKING, Protocol, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, load_der_public_key, load_pem_private_key
from cryptography.x509.oid import ExtensionOID
from devices.issuer import (
    LocalDomainCredentialIssuer,
    LocalTlsClientCredentialIssuer,
    LocalTlsServerCredentialIssuer,
    OpcUaClientCredentialIssuer,
    OpcUaServerCredentialIssuer,
)
from devices.models import DeviceModel
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from pki.models.devid_registration import DevIdRegistration
from pki.models.domain import DomainModel
from pyasn1.codec.der import decoder, encoder  # type: ignore[import-untyped]
from pyasn1.type import tag, univ, useful  # type: ignore[import-untyped]
from pyasn1_modules import rfc2459, rfc2511, rfc4210  # type: ignore[import-untyped]
from trustpoint_core.oid import AlgorithmIdentifier, HashAlgorithm, HmacAlgorithm, SignatureSuite

from cmp.util import NameParser

if TYPE_CHECKING:
    from typing import Any

    from django.http import HttpRequest


UTC_TIME_THRESHOLD = 2050
UTC_TIME_CORRECTION = 100
CERT_TEMPLATE_VERSION = 2
DEFAULT_VALIDITY_DAYS = 10
CMP_MESSAGE_VERSION = 2
SENDER_NONCE_LENGTH = 16
TRANSACTION_ID_LENGTH = 16


class ApplicationCertificateTemplateNames(enum.Enum):
    """Application Certificate Template."""

    TLS_CLIENT = 'tls-client'
    TLS_SERVER = 'tls-server'
    OPCUA_SERVER = 'opcua-server'
    OPCUA_CLIENT = 'opcua-client'


IMPLICIT_CONFIRM_OID = '1.3.6.1.5.5.7.4.13'
IMPLICIT_CONFIRM_STR_VALUE = '0x0500'


class Dispatchable(Protocol):
    """Dispatchable Protocol."""

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Dispatch method."""
        ...


class CmpHttpMixin:
    """CMP Http Validations."""

    expected_content_type = 'application/pkixcmp'
    max_payload_size = 131072  # max 128 KiByte
    raw_message: bytes

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Dispatch method."""
        self.raw_message = request.read()
        if len(self.raw_message) > self.max_payload_size:
            return HttpResponse('Message is too large.', status=413)

        content_type = request.headers.get('Content-Type')
        if content_type is None:
            return HttpResponse('Message is missing the content type.', status=415)

        if content_type != self.expected_content_type:
            return HttpResponse(
                f'Message does not have the expected content type: {self.expected_content_type}.', status=415
            )

        parent = cast(Dispatchable, super())
        return parent.dispatch(request, *args, **kwargs)


class CmpRequestedDomainExtractorMixin:
    """Domain name extractor."""

    requested_domain: DomainModel

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Dispatch method."""
        domain_name = cast(str, kwargs.get('domain'))

        try:
            self.requested_domain = DomainModel.objects.get(unique_name=domain_name)  # type: ignore[attr-defined]
        except DomainModel.DoesNotExist:
            return HttpResponse('Domain does not exist.', status=404)

        parent = cast(Dispatchable, super())
        return parent.dispatch(request, *args, **kwargs)


class CmpPkiMessageSerializerMixin:
    """CMP message serialization."""

    raw_message: bytes
    serialized_pyasn1_message: None | rfc4210.PKIMessage

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Dispatch method."""
        try:
            self.serialized_pyasn1_message, _ = decoder.decode(self.raw_message, asn1Spec=rfc4210.PKIMessage())
        except (ValueError, TypeError):
            return HttpResponse('Failed to parse the CMP message. Seems to be corrupted.', status=400)

        parent = cast(Dispatchable, super())
        return parent.dispatch(request, *args, **kwargs)


class CmpRequestTemplateExtractorMixin:
    """CMP template extractor."""

    application_certificate_template: ApplicationCertificateTemplateNames | None = None

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Dispatch method."""
        self.template_name = cast(None | str, kwargs.get('template'))
        parent = cast(Dispatchable, super())

        if self.template_name is None:
            return parent.dispatch(request, *args, **kwargs)

        try:
            self.application_certificate_template = ApplicationCertificateTemplateNames(self.template_name.lower())
        except (ValueError, TypeError):
            return HttpResponse('Template does not exist.', status=404)

        return parent.dispatch(request, *args, **kwargs)


def check_header(serialized_pyasn1_message: rfc4210.PKIMessage) -> None:
    """Checks some parts of the header."""
    transaction_id = serialized_pyasn1_message['header']['transactionID'].asOctets()
    if len(transaction_id) != TRANSACTION_ID_LENGTH:
        err_msg = 'transactionID fail'
        raise ValueError(err_msg)

    sender_nonce = serialized_pyasn1_message['header']['senderNonce'].asOctets()
    if len(sender_nonce) != SENDER_NONCE_LENGTH:
        err_msg = 'senderNonce fail'
        raise ValueError(err_msg)

    implicit_confirm_entry = None
    for entry in serialized_pyasn1_message['header']['generalInfo']:
        if entry['infoType'].prettyPrint() == IMPLICIT_CONFIRM_OID:
            implicit_confirm_entry = entry
            break
    if implicit_confirm_entry is None:
        err_msg = 'implicit confirm missing'
        raise ValueError(err_msg)

    if implicit_confirm_entry['infoValue'].prettyPrint() != IMPLICIT_CONFIRM_STR_VALUE:
        err_msg = 'implicit confirm entry fail'
        raise ValueError(err_msg)


@method_decorator(csrf_exempt, name='dispatch')
class CmpInitializationRequestView(
    CmpHttpMixin, CmpRequestedDomainExtractorMixin, CmpPkiMessageSerializerMixin, CmpRequestTemplateExtractorMixin, View
):
    """Handles CMP Initialization Request Messages."""

    http_method_names = ('post',)

    raw_message: bytes
    serialized_pyasn1_message: rfc4210.PKIMessage
    requested_domain: DomainModel
    device: None | DeviceModel = None

    def post(  # noqa: C901, PLR0911, PLR0912, PLR0915
        self,
        request: HttpRequest,  # noqa: ARG002
        *args: Any,  # noqa: ARG002
        **kwargs: Any,  # noqa: ARG002
    ) -> HttpResponse:
        """Handles the POST requests."""
        if self.serialized_pyasn1_message['header']['pvno'] != CMP_MESSAGE_VERSION:
            err_msg = 'pvno fail'
            raise ValueError(err_msg)

        protection_algorithm = AlgorithmIdentifier(  # type: ignore[call-arg]
            self.serialized_pyasn1_message['header']['protectionAlg']['algorithm'].prettyPrint()
        )
        if protection_algorithm == AlgorithmIdentifier.PASSWORD_BASED_MAC:
            try:
                sender_kid = int(self.serialized_pyasn1_message['header']['senderKID'].prettyPrint())
                self.device = DeviceModel.objects.get(pk=sender_kid)
            except (DeviceModel.DoesNotExist, Exception):
                return HttpResponse('Device not found.', status=404)

            if (
                not self.device.domain_credential_onboarding
                and self.device.onboarding_protocol == self.device.OnboardingProtocol.NO_ONBOARDING
                and self.device.pki_protocol == self.device.PkiProtocol.CMP_SHARED_SECRET
            ):
                if not self.application_certificate_template:
                    return HttpResponse('Missing application certificate template.', status=404)

                try:
                    sender_kid = int(self.serialized_pyasn1_message['header']['senderKID'].prettyPrint())
                    self.device = DeviceModel.objects.get(pk=sender_kid)
                except (DeviceModel.DoesNotExist, Exception):
                    return HttpResponse('Device not found.', status=404)

                message_body_name = self.serialized_pyasn1_message['body'].getName()
                if message_body_name != 'ir':
                    return HttpResponse(
                        f'Expected CMP IR body, but got CMP {message_body_name.upper()} body.', status=450
                    )

                if self.device.domain != self.requested_domain:
                    raise ValueError

                check_header(serialized_pyasn1_message=self.serialized_pyasn1_message)

                protection_value = self.serialized_pyasn1_message['protection'].asOctets()

                # ignore extra certs

                if self.serialized_pyasn1_message['body'].getName() != 'ir':
                    err_msg = 'not ir message'
                    raise ValueError(err_msg)

                ir_body = self.serialized_pyasn1_message['body']['ir']
                if len(ir_body) > 1:
                    err_msg = 'multiple CertReqMessages found for IR.'
                    raise ValueError(err_msg)

                if len(ir_body) < 1:
                    err_msg = 'no CertReqMessages found for IR.'
                    raise ValueError(err_msg)

                cert_req_msg = ir_body[0]['certReq']

                if cert_req_msg['certReqId'] != 0:
                    err_msg = 'certReqId must be 0.'
                    raise ValueError(err_msg)

                if not cert_req_msg['certTemplate'].hasValue():
                    err_msg = 'certTemplate must be contained in IR CertReqMessage.'
                    raise ValueError(err_msg)

                cert_req_template = cert_req_msg['certTemplate']

                # noinspection PyBroadException
                try:
                    validity_not_before = convert_rfc2459_time(cert_req_template['validity']['notBefore'])
                    validity_not_after = convert_rfc2459_time(cert_req_template['validity']['notAfter'])
                    validity_in_days = (validity_not_after - validity_not_before).days
                except Exception:  # noqa: BLE001
                    validity_in_days = DEFAULT_VALIDITY_DAYS

                if cert_req_template['version'].hasValue() and cert_req_template['version'] != CERT_TEMPLATE_VERSION:
                    err_msg = 'Version must be 2 if supplied in certificate request.'
                    raise ValueError(err_msg)

                if not cert_req_template['subject'].isValue:
                    err_msg = 'subject missing in CertReqMessage.'
                    raise ValueError(err_msg)

                # ignores subject request for now and forces values to set
                subject = NameParser.parse_name(cert_req_template['subject'])

                common_names = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                if len(common_names) != 1:
                    raise ValueError

                common_name = common_names[0]

                if isinstance(common_name.value, str):
                    common_name_value = common_name.value
                elif isinstance(common_name.value, bytes):
                    common_name_value = common_name.value.decode()
                else:
                    err_msg = 'Failed to parse common name value'
                    raise ValueError(err_msg)

                # only local key-gen supported currently -> public key must be present
                asn1_public_key = cert_req_template['publicKey']
                if not asn1_public_key.hasValue():
                    err_msg = 'Public-missing in CertTemplate.'
                    raise ValueError(err_msg)

                spki = rfc2511.SubjectPublicKeyInfo()
                spki.setComponentByName('algorithm', cert_req_template['publicKey']['algorithm'])
                spki.setComponentByName('subjectPublicKey', cert_req_template['publicKey']['subjectPublicKey'])
                loaded_public_key = load_der_public_key(encoder.encode(spki))

                # TODO(AlexHx8472): verify popo / process popo: popo = ir_body[0]['pop'].prettyPrint()

                pbm_parameters_bitstring = self.serialized_pyasn1_message['header']['protectionAlg']['parameters']
                decoded_pbm, _ = decoder.decode(pbm_parameters_bitstring, asn1Spec=rfc4210.PBMParameter())

                salt = decoded_pbm['salt'].asOctets()
                try:
                    owf = HashAlgorithm(decoded_pbm['owf']['algorithm'].prettyPrint())  # type: ignore[call-arg]
                except Exception as exception:
                    err_msg = 'owf algorithm not supported.'
                    raise ValueError(err_msg) from exception

                iteration_count = int(decoded_pbm['iterationCount'])

                if self.device.cmp_shared_secret is None:
                    err_msg = 'Device is misconfigured.'
                    raise ValueError(err_msg)

                shared_secret = self.device.cmp_shared_secret.encode()
                salted_secret = shared_secret + salt
                hmac_key = salted_secret
                for _ in range(iteration_count):
                    hasher = hashes.Hash(owf.hash_algorithm())
                    hasher.update(hmac_key)
                    hmac_key = hasher.finalize()

                hmac_algorithm_oid = decoded_pbm['mac']['algorithm'].prettyPrint()
                try:
                    hmac_algorithm = HmacAlgorithm(hmac_algorithm_oid)  # type: ignore[call-arg]
                except Exception as exception:
                    err_msg = 'hmac algorithm not supported.'
                    raise ValueError(err_msg) from exception

                protected_part = rfc4210.ProtectedPart()
                protected_part['header'] = self.serialized_pyasn1_message['header']
                protected_part['infoValue'] = self.serialized_pyasn1_message['body']

                encoded_protected_part = encoder.encode(protected_part)

                hmac_gen = hmac.HMAC(hmac_key, hmac_algorithm.hash_algorithm.hash_algorithm())
                hmac_gen.update(encoded_protected_part)

                try:
                    hmac_gen.verify(protection_value)
                except InvalidSignature as exception:
                    err_msg = 'hmac verification failed.'
                    raise ValueError(err_msg) from exception

                # Checks regarding contained public key and corresponding signature suite of the issuing CA
                issuing_ca_certificate = self.requested_domain.issuing_ca.credential.get_certificate()
                signature_suite = SignatureSuite.from_certificate(issuing_ca_certificate)
                if not signature_suite.public_key_matches_signature_suite(loaded_public_key):
                    err_msg = 'Contained public key type does not match the signature suite.'
                    raise ValueError(err_msg)

                if self.application_certificate_template == ApplicationCertificateTemplateNames.TLS_CLIENT:
                    issuer = LocalTlsClientCredentialIssuer(device=self.device, domain=self.device.domain)
                    issued_app_cred = issuer.issue_tls_client_certificate(
                        common_name=common_name_value, validity_days=validity_in_days, public_key=loaded_public_key
                    )
                elif self.application_certificate_template == ApplicationCertificateTemplateNames.TLS_SERVER:
                    if cert_req_template['extensions'].hasValue():
                        san_extensions = [
                            extension
                            for extension in cert_req_template['extensions']
                            if str(extension['extnID']) == ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string
                        ]
                        if len(san_extensions) != 1:
                            raise ValueError
                        san_extension = san_extensions[0]
                        san_critical = str(san_extension['critical']) == 'True'
                        san_extension_bytes = bytes(san_extension['extnValue'])
                        san_asn1, _ = decoder.decode(san_extension_bytes, asn1Spec=rfc2459.SubjectAltName())

                        dns_names = []
                        ipv4_addresses = []
                        ipv6_addresses = []

                        for general_name in san_asn1:
                            name_type = general_name.getName()
                            value = general_name.getComponent()

                            if name_type == 'iPAddress':
                                try:
                                    ipv4_addresses.append(ipaddress.IPv4Address(value.asOctets()))
                                except (ValueError, TypeError):
                                    ipv6_addresses.append(ipaddress.IPv6Address(value.asOctets()))

                            elif name_type == 'dNSName':
                                dns_names.append(str(value))
                    else:
                        raise ValueError

                    issuer_tls_server = LocalTlsServerCredentialIssuer(device=self.device, domain=self.device.domain)
                    issued_app_cred = issuer_tls_server.issue_tls_server_certificate(
                        common_name=common_name_value,
                        validity_days=validity_in_days,
                        ipv4_addresses=ipv4_addresses,
                        ipv6_addresses=ipv6_addresses,
                        san_critical=san_critical,
                        domain_names=dns_names,
                        public_key=loaded_public_key,
                    )
                else:
                    raise ValueError

                ip_header = rfc4210.PKIHeader()

                ip_header['pvno'] = CMP_MESSAGE_VERSION

                issuing_ca_cert = self.requested_domain.issuing_ca.credential.get_certificate()
                raw_issuing_ca_subject = issuing_ca_cert.subject.public_bytes()
                name, _ = decoder.decode(raw_issuing_ca_subject, asn1spec=rfc2459.Name())
                sender = rfc2459.GeneralName()
                sender['directoryName'][0] = name
                ip_header['sender'] = sender

                ip_header['recipient'] = self.serialized_pyasn1_message['header']['sender']

                current_time = datetime.datetime.now(datetime.UTC).strftime('%Y%m%d%H%M%SZ')
                ip_header['messageTime'] = useful.GeneralizedTime(current_time).subtype(
                    explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
                )

                ip_header['protectionAlg'] = self.serialized_pyasn1_message['header']['protectionAlg']

                ip_header['senderKID'] = self.serialized_pyasn1_message['header']['senderKID']

                ip_header['transactionID'] = self.serialized_pyasn1_message['header']['transactionID']

                ip_header['senderNonce'] = univ.OctetString(secrets.token_bytes(SENDER_NONCE_LENGTH)).subtype(
                    explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)
                )

                ip_header['recipNonce'] = univ.OctetString(
                    self.serialized_pyasn1_message['header']['senderNonce']
                ).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))

                ip_header['generalInfo'] = self.serialized_pyasn1_message['header']['generalInfo']

                ip_extra_certs = univ.SequenceOf()

                certificate_chain = [
                    self.requested_domain.issuing_ca.credential.get_certificate(),
                    *self.requested_domain.issuing_ca.credential.get_certificate_chain(),
                ]
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

                cert_response = rfc4210.CertResponse()
                cert_response['certReqId'] = 0

                pki_status_info = rfc4210.PKIStatusInfo()
                pki_status_info['status'] = 0
                cert_response['status'] = pki_status_info

                cmp_cert = rfc4210.CMPCertificate().subtype(
                    explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
                )

                encoded_cert = issued_app_cred.credential.get_certificate().public_bytes(encoding=Encoding.DER)
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

                protected_part = rfc4210.ProtectedPart()
                protected_part['header'] = ip_message['header']
                protected_part['infoValue'] = ip_message['body']

                encoded_protected_part = encoder.encode(protected_part)

                hmac_gen = hmac.HMAC(hmac_key, hmac_algorithm.hash_algorithm.hash_algorithm())
                hmac_gen.update(encoded_protected_part)
                hmac_digest = hmac_gen.finalize()

                binary_stuff = bin(int.from_bytes(hmac_digest, byteorder='big'))[2:].zfill(160)
                ip_message['protection'] = rfc4210.PKIProtection(univ.BitString(binary_stuff)).subtype(
                    explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
                )

                encoded_ip_message = encoder.encode(ip_message)
                decoded_ip_message, _ = decoder.decode(encoded_ip_message, asn1Spec=rfc4210.PKIMessage())

            elif (
                self.device.domain_credential_onboarding
                and self.device.onboarding_protocol == self.device.OnboardingProtocol.CMP_SHARED_SECRET
                and self.device.pki_protocol == self.device.PkiProtocol.CMP_CLIENT_CERTIFICATE
            ):
                if self.application_certificate_template:
                    return HttpResponse(
                        'Found application certificate template for domain credential certificate request.', status=404
                    )

                message_body_name = self.serialized_pyasn1_message['body'].getName()
                if message_body_name != 'ir':
                    return HttpResponse(
                        f'Expected CMP IR body, but got CMP {message_body_name.upper()} body.', status=450
                    )

                if self.device.domain != self.requested_domain:
                    raise ValueError

                check_header(serialized_pyasn1_message=self.serialized_pyasn1_message)

                protection_value = self.serialized_pyasn1_message['protection'].asOctets()

                # ignore extra certs

                if self.serialized_pyasn1_message['body'].getName() != 'ir':
                    err_msg = 'not ir message'
                    raise ValueError(err_msg)

                ir_body = self.serialized_pyasn1_message['body']['ir']
                if len(ir_body) > 1:
                    err_msg = 'multiple CertReqMessages found for IR.'
                    raise ValueError(err_msg)

                if len(ir_body) < 1:
                    err_msg = 'no CertReqMessages found for IR.'
                    raise ValueError(err_msg)

                cert_req_msg = ir_body[0]['certReq']

                if cert_req_msg['certReqId'] != 0:
                    err_msg = 'certReqId must be 0.'
                    raise ValueError(err_msg)

                if not cert_req_msg['certTemplate'].hasValue():
                    err_msg = 'certTemplate must be contained in IR CertReqMessage.'
                    raise ValueError(err_msg)

                cert_req_template = cert_req_msg['certTemplate']

                # noinspection PyBroadException
                try:
                    validity_not_before = convert_rfc2459_time(cert_req_template['validity']['notBefore'])
                    validity_not_after = convert_rfc2459_time(cert_req_template['validity']['notAfter'])
                    validity_in_days = (validity_not_after - validity_not_before).days
                except Exception:  # noqa: BLE001
                    validity_in_days = DEFAULT_VALIDITY_DAYS

                if cert_req_template['version'].hasValue() and cert_req_template['version'] != CERT_TEMPLATE_VERSION:
                    err_msg = 'Version must be 2 if supplied in certificate request.'
                    raise ValueError(err_msg)

                if not cert_req_template['subject'].isValue:
                    err_msg = 'subject missing in CertReqMessage.'
                    raise ValueError(err_msg)

                # ignores subject request for now and forces values to set
                subject = NameParser.parse_name(cert_req_template['subject'])

                common_names = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                if len(common_names) != 1:
                    raise ValueError

                # only local key-gen supported currently -> public key must be present
                asn1_public_key = cert_req_template['publicKey']
                if not asn1_public_key.hasValue():
                    err_msg = 'Public-missing in CertTemplate.'
                    raise ValueError(err_msg)

                spki = rfc2511.SubjectPublicKeyInfo()
                spki.setComponentByName('algorithm', cert_req_template['publicKey']['algorithm'])
                spki.setComponentByName('subjectPublicKey', cert_req_template['publicKey']['subjectPublicKey'])
                loaded_public_key = load_der_public_key(encoder.encode(spki))

                # TODO(AlexHx8472): verify popo / process popo: popo = ir_body[0]['pop'].prettyPrint()

                pbm_parameters_bitstring = self.serialized_pyasn1_message['header']['protectionAlg']['parameters']
                decoded_pbm, _ = decoder.decode(pbm_parameters_bitstring, asn1Spec=rfc4210.PBMParameter())

                salt = decoded_pbm['salt'].asOctets()
                try:
                    owf = HashAlgorithm(decoded_pbm['owf']['algorithm'].prettyPrint())  # type: ignore[call-arg]
                except Exception as exception:
                    err_msg = 'owf algorithm not supported.'
                    raise ValueError(err_msg) from exception
                iteration_count = int(decoded_pbm['iterationCount'])

                if self.device.cmp_shared_secret is None:
                    err_msg = 'Device is misconfigured.'
                    raise ValueError(err_msg)

                shared_secret = self.device.cmp_shared_secret.encode()
                salted_secret = shared_secret + salt
                hmac_key = salted_secret
                for _ in range(iteration_count):
                    hasher = hashes.Hash(owf.hash_algorithm())
                    hasher.update(hmac_key)
                    hmac_key = hasher.finalize()

                hmac_algorithm_oid = decoded_pbm['mac']['algorithm'].prettyPrint()
                try:
                    hmac_algorithm = HmacAlgorithm(hmac_algorithm_oid)  # type: ignore[call-arg]
                except Exception as exception:
                    err_msg = 'hmac algorithm not supported.'
                    raise ValueError(err_msg) from exception

                protected_part = rfc4210.ProtectedPart()
                protected_part['header'] = self.serialized_pyasn1_message['header']
                protected_part['infoValue'] = self.serialized_pyasn1_message['body']

                encoded_protected_part = encoder.encode(protected_part)

                hmac_gen = hmac.HMAC(hmac_key, hmac_algorithm.hash_algorithm.hash_algorithm())
                hmac_gen.update(encoded_protected_part)

                try:
                    hmac_gen.verify(protection_value)
                except InvalidSignature as exception:
                    err_msg = 'hmac verification failed.'
                    raise ValueError(err_msg) from exception

                # Checks regarding contained public key and corresponding signature suite of the issuing CA
                issuing_ca_certificate = self.requested_domain.issuing_ca.credential.get_certificate()
                signature_suite = SignatureSuite.from_certificate(issuing_ca_certificate)
                if not signature_suite.public_key_matches_signature_suite(loaded_public_key):
                    err_msg = 'Contained public key type does not match the signature suite.'
                    raise ValueError(err_msg)

                issuer_domain_credential = LocalDomainCredentialIssuer(device=self.device, domain=self.device.domain)
                issued_domain_credential = issuer_domain_credential.issue_domain_credential_certificate(
                    public_key=loaded_public_key
                )

                ip_header = rfc4210.PKIHeader()

                ip_header['pvno'] = CMP_MESSAGE_VERSION

                issuing_ca_cert = self.requested_domain.issuing_ca.credential.get_certificate()
                raw_issuing_ca_subject = issuing_ca_cert.subject.public_bytes()
                name, _ = decoder.decode(raw_issuing_ca_subject, asn1spec=rfc2459.Name())
                sender = rfc2459.GeneralName()
                sender['directoryName'][0] = name
                ip_header['sender'] = sender

                ip_header['recipient'] = self.serialized_pyasn1_message['header']['sender']

                current_time = datetime.datetime.now(datetime.UTC).strftime('%Y%m%d%H%M%SZ')
                ip_header['messageTime'] = useful.GeneralizedTime(current_time).subtype(
                    explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
                )

                ip_header['protectionAlg'] = self.serialized_pyasn1_message['header']['protectionAlg']

                ip_header['senderKID'] = self.serialized_pyasn1_message['header']['senderKID']

                ip_header['transactionID'] = self.serialized_pyasn1_message['header']['transactionID']

                ip_header['senderNonce'] = univ.OctetString(secrets.token_bytes(SENDER_NONCE_LENGTH)).subtype(
                    explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)
                )

                ip_header['recipNonce'] = univ.OctetString(
                    self.serialized_pyasn1_message['header']['senderNonce']
                ).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))

                ip_header['generalInfo'] = self.serialized_pyasn1_message['header']['generalInfo']

                ip_extra_certs = univ.SequenceOf()

                certificate_chain = [
                    self.requested_domain.issuing_ca.credential.get_certificate(),
                    *self.requested_domain.issuing_ca.credential.get_certificate_chain(),
                ]
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
                # TODO(AlexHx8472): Add TLS Server Certificate Root CA

                cert_response = rfc4210.CertResponse()
                cert_response['certReqId'] = 0

                pki_status_info = rfc4210.PKIStatusInfo()
                pki_status_info['status'] = 0
                cert_response['status'] = pki_status_info

                cmp_cert = rfc4210.CMPCertificate().subtype(
                    explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
                )

                encoded_cert = issued_domain_credential.credential.get_certificate().public_bytes(encoding=Encoding.DER)
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

                # TODO(AlexHx8472): Use fresh salt!
                protected_part = rfc4210.ProtectedPart()
                protected_part['header'] = ip_message['header']
                protected_part['infoValue'] = ip_message['body']

                encoded_protected_part = encoder.encode(protected_part)

                hmac_gen = hmac.HMAC(hmac_key, hmac_algorithm.hash_algorithm.hash_algorithm())
                hmac_gen.update(encoded_protected_part)
                hmac_digest = hmac_gen.finalize()

                binary_stuff = bin(int.from_bytes(hmac_digest, byteorder='big'))[2:].zfill(160)
                ip_message['protection'] = rfc4210.PKIProtection(univ.BitString(binary_stuff)).subtype(
                    explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
                )

                encoded_ip_message = encoder.encode(ip_message)
                decoded_ip_message, _ = decoder.decode(encoded_ip_message, asn1Spec=rfc4210.PKIMessage())

            else:
                return HttpResponse('Invalid Request for corresponding device.', status=460)

        else:
            extra_certs = self.serialized_pyasn1_message['extraCerts']
            if extra_certs is None or len(extra_certs) == 0:
                err_msg = 'No extra certificates found in the PKIMessage.'
                raise ValueError(err_msg)

            cmp_signer_extra_cert = extra_certs[0]
            der_cmp_signer_cert = encoder.encode(cmp_signer_extra_cert)
            cmp_signer_cert = x509.load_der_x509_certificate(der_cmp_signer_cert)

            loaded_extra_cert = None
            intermediate_certs = []
            for extra_cert in extra_certs[1:]:
                der_extra_cert = encoder.encode(extra_cert)
                loaded_extra_cert = x509.load_der_x509_certificate(der_extra_cert)
                # Do not include self-signed certs
                if loaded_extra_cert.subject.public_bytes() != loaded_extra_cert.issuer.public_bytes():
                    intermediate_certs.append(loaded_extra_cert)

            if not loaded_extra_cert:
                err_msg = 'CMP signer certificate missing in extra certs.'
                raise ValueError(err_msg)

            device_serial_number = cmp_signer_cert.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)[0].value

            device_candidates = DeviceModel.objects.filter(
                serial_number=device_serial_number, domain=self.requested_domain
            )
            if device_candidates:
                for device_candidate in device_candidates:
                    if not device_candidate.idevid_trust_store:
                        continue
                    trust_store = (
                        device_candidate.idevid_trust_store.get_certificate_collection_serializer().as_crypto()
                    )
                    for cert in trust_store:
                        try:
                            loaded_extra_cert.verify_directly_issued_by(cert)
                            self.device = device_candidate
                            break
                        except (ValueError, TypeError, InvalidSignature):
                            pass

                    if self.device:
                        break

            dev_reg_model = None
            if self.device is None:
                devid_reg_candidates = DevIdRegistration.objects.all()  # type: ignore[attr-defined]
                for devid_reg_candidate in devid_reg_candidates:
                    trust_store = devid_reg_candidate.truststore.get_certificate_collection_serializer().as_crypto()

                    for cert in trust_store:
                        try:
                            loaded_extra_cert.verify_directly_issued_by(cert)
                            dev_reg_model = devid_reg_candidate
                            break
                        except (ValueError, TypeError, InvalidSignature):
                            pass

                if not dev_reg_model:
                    err_msg = 'Neither a device nor a devid registrations found.'
                    raise ValueError(err_msg)

                pattern = re.compile(dev_reg_model.serial_number_pattern)

                if not pattern.fullmatch(device_serial_number):
                    err_msg = 'Serial-Number not allowed.'
                    raise ValueError(err_msg)

                device_model = DeviceModel(
                    unique_name=f'Auto-Created Device - {uuid.uuid4()}',
                    domain=dev_reg_model.domain,
                    serial_number=device_serial_number,
                    domain_credential_onboarding=True,
                    onboarding_status=DeviceModel.OnboardingStatus.PENDING,
                    onboarding_protocol=DeviceModel.OnboardingProtocol.CMP_IDEVID,
                    pki_protocol=DeviceModel.PkiProtocol.CMP_CLIENT_CERTIFICATE,
                    idevid_trust_store=dev_reg_model.truststore,
                )

                self.device = device_model
                self.device.save()

            else:
                if not self.device.domain_credential_onboarding:
                    return HttpResponse(
                        'The corresponding device is not configured to use the onboarding mechanism.', status=404
                    )

                if not self.device.onboarding_protocol == DeviceModel.OnboardingProtocol.CMP_IDEVID:  # noqa: SIM201
                    return HttpResponse('Wrong onboarding protocol.')

                if self.device.pki_protocol != DeviceModel.PkiProtocol.CMP_CLIENT_CERTIFICATE.value:
                    return HttpResponse('PKI protocol CMP client certificate expected, but got something else.')

            message_body_name = self.serialized_pyasn1_message['body'].getName()
            if message_body_name != 'ir':
                return HttpResponse(f'Expected CMP IR body, but got CMP {message_body_name.upper()} body.', status=450)

            check_header(serialized_pyasn1_message=self.serialized_pyasn1_message)

            protection_value = self.serialized_pyasn1_message['protection'].asOctets()

            if self.serialized_pyasn1_message['body'].getName() != 'ir':
                err_msg = 'not ir message'
                raise ValueError(err_msg)

            ir_body = self.serialized_pyasn1_message['body']['ir']
            if len(ir_body) > 1:
                err_msg = 'multiple CertReqMessages found for IR.'
                raise ValueError(err_msg)

            if len(ir_body) < 1:
                err_msg = 'no CertReqMessages found for IR.'
                raise ValueError(err_msg)

            cert_req_msg = ir_body[0]['certReq']

            if cert_req_msg['certReqId'] != 0:
                err_msg = 'certReqId must be 0.'
                raise ValueError(err_msg)

            if not cert_req_msg['certTemplate'].hasValue():
                err_msg = 'certTemplate must be contained in IR CertReqMessage.'
                raise ValueError(err_msg)

            cert_req_template = cert_req_msg['certTemplate']

            # noinspection PyBroadException
            try:
                validity_not_before = convert_rfc2459_time(cert_req_template['validity']['notBefore'])
                validity_not_after = convert_rfc2459_time(cert_req_template['validity']['notAfter'])
                validity_in_days = (validity_not_after - validity_not_before).days
            except Exception:  # noqa: BLE001
                validity_in_days = DEFAULT_VALIDITY_DAYS

            if cert_req_template['version'].hasValue() and cert_req_template['version'] != CERT_TEMPLATE_VERSION:
                err_msg = 'Version must be 2 if supplied in certificate request.'
                raise ValueError(err_msg)

            if not cert_req_template['subject'].isValue:
                err_msg = 'subject missing in CertReqMessage.'
                raise ValueError(err_msg)

            # ignores subject request for now and forces values to set
            subject = NameParser.parse_name(cert_req_template['subject'])

            common_names = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if len(common_names) != 1:
                raise ValueError

            # only local key-gen supported currently -> public key must be present
            asn1_public_key = cert_req_template['publicKey']
            if not asn1_public_key.hasValue():
                err_msg = 'Public-missing in CertTemplate.'
                raise ValueError(err_msg)

            spki = rfc2511.SubjectPublicKeyInfo()
            spki.setComponentByName('algorithm', cert_req_template['publicKey']['algorithm'])
            spki.setComponentByName('subjectPublicKey', cert_req_template['publicKey']['subjectPublicKey'])
            loaded_public_key = load_der_public_key(encoder.encode(spki))

            # TODO(AlexHx8472): verify popo / process popo: popo = ir_body[0]['pop'].prettyPrint()

            protected_part = rfc4210.ProtectedPart()
            protected_part['header'] = self.serialized_pyasn1_message['header']
            protected_part['infoValue'] = self.serialized_pyasn1_message['body']

            encoded_protected_part = encoder.encode(protected_part)
            signature_suite = SignatureSuite.from_certificate(cmp_signer_cert)

            public_key = cmp_signer_cert.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature=protection_value,
                    data=encoded_protected_part,
                    padding=padding.PKCS1v15(),
                    algorithm=signature_suite.algorithm_identifier.hash_algorithm.hash_algorithm(),
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature=protection_value,
                    data=encoded_protected_part,
                    signature_algorithm=ec.ECDSA(signature_suite.algorithm_identifier.hash_algorithm.hash_algorithm()),
                )

            # Checks regarding contained public key and corresponding signature suite of the issuing CA
            issuing_ca_certificate = self.requested_domain.issuing_ca.credential.get_certificate()
            signature_suite = SignatureSuite.from_certificate(issuing_ca_certificate)
            if not signature_suite.public_key_matches_signature_suite(loaded_public_key):
                err_msg = 'Contained public key type does not match the signature suite.'
                raise ValueError(err_msg)

            issuer_domain_credential = LocalDomainCredentialIssuer(device=self.device, domain=self.device.domain)
            issued_domain_credential = issuer_domain_credential.issue_domain_credential_certificate(
                public_key=loaded_public_key
            )

            ip_header = rfc4210.PKIHeader()

            ip_header['pvno'] = CMP_MESSAGE_VERSION

            issuing_ca_cert = self.requested_domain.issuing_ca.credential.get_certificate()
            raw_issuing_ca_subject = issuing_ca_cert.subject.public_bytes()
            name, _ = decoder.decode(raw_issuing_ca_subject, asn1spec=rfc2459.Name())
            sender = rfc2459.GeneralName()
            sender['directoryName'][0] = name
            ip_header['sender'] = sender

            ip_header['recipient'] = self.serialized_pyasn1_message['header']['sender']

            current_time = datetime.datetime.now(datetime.UTC).strftime('%Y%m%d%H%M%SZ')
            ip_header['messageTime'] = useful.GeneralizedTime(current_time).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )

            ip_header['protectionAlg'] = self.serialized_pyasn1_message['header']['protectionAlg']

            ski = x509.SubjectKeyIdentifier.from_public_key(issuing_ca_cert.public_key())
            ip_header['senderKID'] = rfc2459.KeyIdentifier(ski.digest).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
            )

            ip_header['transactionID'] = self.serialized_pyasn1_message['header']['transactionID']

            ip_header['senderNonce'] = univ.OctetString(secrets.token_bytes(SENDER_NONCE_LENGTH)).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)
            )

            ip_header['recipNonce'] = univ.OctetString(self.serialized_pyasn1_message['header']['senderNonce']).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
            )

            ip_header['generalInfo'] = self.serialized_pyasn1_message['header']['generalInfo']

            ip_extra_certs = univ.SequenceOf()

            certificate_chain = [
                self.requested_domain.issuing_ca.credential.get_certificate(),
                *self.requested_domain.issuing_ca.credential.get_certificate_chain(),
            ]
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
            # TODO(AlexHx8472): Add TLS Server Certificate Root CA

            cert_response = rfc4210.CertResponse()
            cert_response['certReqId'] = 0

            pki_status_info = rfc4210.PKIStatusInfo()
            pki_status_info['status'] = 0
            cert_response['status'] = pki_status_info

            cmp_cert = rfc4210.CMPCertificate().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            )

            encoded_cert = issued_domain_credential.credential.get_certificate().public_bytes(encoding=Encoding.DER)
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

            protected_part = rfc4210.ProtectedPart()
            protected_part['header'] = ip_message['header']
            protected_part['infoValue'] = ip_message['body']

            encoded_protected_part = encoder.encode(protected_part)
            signature_suite = SignatureSuite.from_certificate(cmp_signer_cert)
            private_key = load_pem_private_key(
                self.device.domain.issuing_ca.credential.private_key.encode(), password=None
            )
            # TODO(AlexHx8472): Algo support

            if isinstance(private_key, rsa.RSAPrivateKey):
                signature = private_key.sign(
                    encoded_protected_part,
                    padding.PKCS1v15(),
                    signature_suite.algorithm_identifier.hash_algorithm.hash_algorithm(),
                )
            elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                signature = private_key.sign(
                    encoded_protected_part,
                    ec.ECDSA(signature_suite.algorithm_identifier.hash_algorithm.hash_algorithm()),
                )
            else:
                raise TypeError

            ip_message['protection'] = rfc4210.PKIProtection(univ.BitString.fromOctetString(signature)).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )

            encoded_ip_message = encoder.encode(ip_message)

            self.device.onboarding_status = DeviceModel.OnboardingStatus.ONBOARDED
            self.device.save()

        return HttpResponse(encoded_ip_message, content_type='application/pkixcmp', status=200)


@method_decorator(csrf_exempt, name='dispatch')
class CmpCertificationRequestView(
    CmpHttpMixin, CmpRequestedDomainExtractorMixin, CmpPkiMessageSerializerMixin, CmpRequestTemplateExtractorMixin, View
):
    """Handles CMP Certification Request Messages."""

    http_method_names = ('post',)

    raw_message: bytes
    serialized_pyasn1_message: rfc4210.PKIMessage
    requested_domain: DomainModel
    device: DeviceModel
    application_certificate_template: None | ApplicationCertificateTemplateNames = None

    def post(  # noqa: C901, PLR0911, PLR0912, PLR0915
        self,
        request: HttpRequest,  # noqa: ARG002
        *args: Any,  # noqa: ARG002
        **kwargs: Any,  # noqa: ARG002
    ) -> HttpResponse:
        """Handles the POST requests."""
        if self.serialized_pyasn1_message['header']['pvno'] != CMP_MESSAGE_VERSION:
            err_msg = 'pvno fail'
            raise ValueError(err_msg)

        protection_algorithm = AlgorithmIdentifier(  # type: ignore[call-arg]
            self.serialized_pyasn1_message['header']['protectionAlg']['algorithm'].prettyPrint()
        )
        if protection_algorithm == AlgorithmIdentifier.PASSWORD_BASED_MAC:
            if not self.application_certificate_template:
                return HttpResponse('Missing application certificate template.', status=404)

            try:
                sender_kid = int(self.serialized_pyasn1_message['header']['senderKID'].prettyPrint())
                self.device = DeviceModel.objects.get(pk=sender_kid)
            except (DeviceModel.DoesNotExist, Exception):
                return HttpResponse('Device not found.', status=404)

            if (
                self.device.domain_credential_onboarding
                or self.device.onboarding_protocol != self.device.OnboardingProtocol.NO_ONBOARDING
            ):
                return HttpResponse(
                    'Password based MAC protected CMP messages while using CMP '
                    'CR message types are not allowed for onboarded devices. '
                    'Use signature based protection utilizing the domain credential',
                    status=404,
                )

            if self.device.pki_protocol != DeviceModel.PkiProtocol.CMP_SHARED_SECRET.value:
                return HttpResponse(
                    'Received a password based MAC protected CMP message for a device that does not use the '
                    f'pki-protocol {DeviceModel.PkiProtocol.CMP_SHARED_SECRET.label}, but instead uses'
                    f'{self.device.get_pki_protocol_display()}.'  # type: ignore[attr-defined]
                )

            if self.device.domain != self.requested_domain:
                raise ValueError

            message_body_name = self.serialized_pyasn1_message['body'].getName()
            if message_body_name != 'cr':
                return HttpResponse(f'Expected CMP CR body, but got CMP {message_body_name.upper()} body.', status=450)

            check_header(serialized_pyasn1_message=self.serialized_pyasn1_message)

            protection_value = self.serialized_pyasn1_message['protection'].asOctets()

            if self.serialized_pyasn1_message['body'].getName() != 'cr':
                err_msg = 'not cr message'
                raise ValueError(err_msg)

            cr_body = self.serialized_pyasn1_message['body']['cr']
            if len(cr_body) > 1:
                err_msg = 'multiple CertReqMessages found for CR.'
                raise ValueError(err_msg)

            if len(cr_body) < 1:
                err_msg = 'no CertReqMessages found for CR.'
                raise ValueError(err_msg)

            cert_req_msg = cr_body[0]['certReq']

            if cert_req_msg['certReqId'] != 0:
                err_msg = 'certReqId must be 0.'
                raise ValueError(err_msg)

            if not cert_req_msg['certTemplate'].hasValue():
                err_msg = 'certTemplate must be contained in CR CertReqMessage.'
                raise ValueError(err_msg)

            cert_req_template = cert_req_msg['certTemplate']

            # noinspection PyBroadException
            try:
                validity_not_before = convert_rfc2459_time(cert_req_template['validity']['notBefore'])
                validity_not_after = convert_rfc2459_time(cert_req_template['validity']['notAfter'])
                validity_in_days = (validity_not_after - validity_not_before).days
            except Exception:  # noqa: BLE001
                validity_in_days = DEFAULT_VALIDITY_DAYS

            if cert_req_template['version'].hasValue() and cert_req_template['version'] != CERT_TEMPLATE_VERSION:
                err_msg = 'Version must be 2 if supplied in certificate request.'
                raise ValueError(err_msg)

            if not cert_req_template['subject'].isValue:
                err_msg = 'subject missing in CertReqMessage.'
                raise ValueError(err_msg)

            # ignores subject request for now and forces values to set
            subject = NameParser.parse_name(cert_req_template['subject'])

            common_names = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if len(common_names) != 1:
                raise ValueError

            common_name = common_names[0]
            if isinstance(common_name.value, str):
                common_name_value = common_name.value
            elif isinstance(common_name.value, bytes):
                common_name_value = common_name.value.decode()
            else:
                err_msg = 'Failed to parse common name value'
                raise ValueError(err_msg)

            # only local key-gen supported currently -> public key must be present
            asn1_public_key = cert_req_template['publicKey']
            if not asn1_public_key.hasValue():
                err_msg = 'Public-missing in CertTemplate.'
                raise ValueError(err_msg)

            spki = rfc2511.SubjectPublicKeyInfo()
            spki.setComponentByName('algorithm', cert_req_template['publicKey']['algorithm'])
            spki.setComponentByName('subjectPublicKey', cert_req_template['publicKey']['subjectPublicKey'])
            loaded_public_key = load_der_public_key(encoder.encode(spki))

            # TODO(AlexHx8472): verify popo / process popo: popo = cr_body[0]['pop'].prettyPrint()

            pbm_parameters_bitstring = self.serialized_pyasn1_message['header']['protectionAlg']['parameters']
            decoded_pbm, _ = decoder.decode(pbm_parameters_bitstring, asn1Spec=rfc4210.PBMParameter())

            salt = decoded_pbm['salt'].asOctets()
            try:
                owf = HashAlgorithm(decoded_pbm['owf']['algorithm'].prettyPrint())  # type: ignore[call-arg]
            except Exception as exception:
                err_msg = 'owf algorithm not supported.'
                raise ValueError(err_msg) from exception

            iteration_count = int(decoded_pbm['iterationCount'])

            if self.device.cmp_shared_secret is None:
                err_msg = 'Device is misconfigured.'
                raise ValueError(err_msg)

            shared_secret = self.device.cmp_shared_secret.encode()
            salted_secret = shared_secret + salt
            hmac_key = salted_secret
            for _ in range(iteration_count):
                hasher = hashes.Hash(owf.hash_algorithm())
                hasher.update(hmac_key)
                hmac_key = hasher.finalize()

            hmac_algorithm_oid = decoded_pbm['mac']['algorithm'].prettyPrint()
            try:
                hmac_algorithm = HmacAlgorithm(hmac_algorithm_oid)  # type: ignore[call-arg]
            except Exception as exception:
                err_msg = 'hmac algorithm not supported.'
                raise ValueError(err_msg) from exception

            protected_part = rfc4210.ProtectedPart()
            protected_part['header'] = self.serialized_pyasn1_message['header']
            protected_part['infoValue'] = self.serialized_pyasn1_message['body']

            encoded_protected_part = encoder.encode(protected_part)

            hmac_gen = hmac.HMAC(hmac_key, hmac_algorithm.hash_algorithm.hash_algorithm())
            hmac_gen.update(encoded_protected_part)

            try:
                hmac_gen.verify(protection_value)
            except InvalidSignature as exception:
                err_msg = 'hmac verification failed.'
                raise ValueError(err_msg) from exception

            # Checks regarding contained public key and corresponding signature suite of the issuing CA
            issuing_ca_certificate = self.requested_domain.issuing_ca.credential.get_certificate()
            signature_suite = SignatureSuite.from_certificate(issuing_ca_certificate)
            if not signature_suite.public_key_matches_signature_suite(loaded_public_key):
                err_msg = 'Contained public key type does not match the signature suite.'
                raise ValueError(err_msg)

            if self.application_certificate_template == ApplicationCertificateTemplateNames.TLS_CLIENT:
                issuer = LocalTlsClientCredentialIssuer(device=self.device, domain=self.device.domain)
                issued_app_cred = issuer.issue_tls_client_certificate(
                    common_name=common_name_value, validity_days=validity_in_days, public_key=loaded_public_key
                )
            elif self.application_certificate_template == ApplicationCertificateTemplateNames.TLS_SERVER:
                if cert_req_template['extensions'].hasValue():
                    san_extensions = [
                        extension
                        for extension in cert_req_template['extensions']
                        if str(extension['extnID']) == ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string
                    ]
                    if len(san_extensions) != 1:
                        raise ValueError
                    san_extension = san_extensions[0]
                    san_critical = str(san_extension['critical']) == 'True'
                    san_extension_bytes = bytes(san_extension['extnValue'])
                    san_asn1, _ = decoder.decode(san_extension_bytes, asn1Spec=rfc2459.SubjectAltName())

                    dns_names = []
                    ipv4_addresses = []
                    ipv6_addresses = []

                    for general_name in san_asn1:
                        name_type = general_name.getName()
                        value = general_name.getComponent()

                        if name_type == 'iPAddress':
                            try:
                                ipv4_addresses.append(ipaddress.IPv4Address(value.asOctets()))
                            except (ValueError, TypeError):
                                ipv6_addresses.append(ipaddress.IPv6Address(value.asOctets()))

                        elif name_type == 'dNSName':
                            dns_names.append(str(value))
                else:
                    raise ValueError

                issuer_tls_server = LocalTlsServerCredentialIssuer(device=self.device, domain=self.device.domain)
                issued_app_cred = issuer_tls_server.issue_tls_server_certificate(
                    common_name=common_name_value,
                    validity_days=validity_in_days,
                    ipv4_addresses=ipv4_addresses,
                    ipv6_addresses=ipv6_addresses,
                    san_critical=san_critical,
                    domain_names=dns_names,
                    public_key=loaded_public_key,
                )
            elif self.application_certificate_template == ApplicationCertificateTemplateNames.OPCUA_SERVER:
                if cert_req_template['extensions'].hasValue():
                    san_extensions = [
                        extension
                        for extension in cert_req_template['extensions']
                        if str(extension['extnID']) == ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string
                    ]
                    if len(san_extensions) != 1:
                        raise ValueError('Invalid SAN extension count')

                    san_extension = san_extensions[0]
                    # san_critical = str(san_extension['critical']) == 'True'
                    # TODO (FHKatCSW): san_critical not supported in OpcUaServerCredentialIssuer
                    san_extension_bytes = bytes(san_extension['extnValue'])
                    san_asn1, _ = decoder.decode(san_extension_bytes, asn1Spec=rfc2459.SubjectAltName())

                    dns_names = []
                    ipv4_addresses = []
                    ipv6_addresses = []
                    application_uri = None

                    for general_name in san_asn1:
                        name_type = general_name.getName()
                        value = general_name.getComponent()

                        if name_type == 'iPAddress':
                            try:
                                ipv4_addresses.append(ipaddress.IPv4Address(value.asOctets()))
                            except (ValueError, TypeError):
                                ipv6_addresses.append(ipaddress.IPv6Address(value.asOctets()))

                        elif name_type == 'dNSName':
                            dns_names.append(str(value))

                        elif name_type == 'uniformResourceIdentifier':
                            application_uri = str(value)

                    if not application_uri:
                        raise ValueError('Missing OPC UA Application URI in SAN extension')

                else:
                    raise ValueError('SAN extension is required for OPC UA Server Certificates')

                issuer = OpcUaServerCredentialIssuer(device=self.device, domain=self.device.domain)
                issued_app_cred = issuer.issue_opcua_server_certificate(
                    common_name=common_name_value,
                    application_uri=application_uri,
                    ipv4_addresses=ipv4_addresses,
                    ipv6_addresses=ipv6_addresses,
                    domain_names=dns_names,
                    validity_days=validity_in_days,
                    public_key=loaded_public_key,
                )

            elif self.application_certificate_template == ApplicationCertificateTemplateNames.OPCUA_CLIENT:
                if cert_req_template['extensions'].hasValue():
                    san_extensions = [
                        extension
                        for extension in cert_req_template['extensions']
                        if str(extension['extnID']) == ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string
                    ]
                    if len(san_extensions) != 1:
                        raise ValueError('Invalid SAN extension count')

                    san_extension = san_extensions[0]
                    # san_critical = str(san_extension['critical']) == 'True'
                    # TODO (FHKatCSW): san_critical not supported in OpcUaClientCredentialIssuer
                    san_extension_bytes = bytes(san_extension['extnValue'])
                    san_asn1, _ = decoder.decode(san_extension_bytes, asn1Spec=rfc2459.SubjectAltName())

                    application_uri = None

                    for general_name in san_asn1:
                        name_type = general_name.getName()
                        value = general_name.getComponent()

                        if name_type == 'uniformResourceIdentifier':
                            application_uri = str(value)

                    if not application_uri:
                        raise ValueError('Missing OPC UA Application URI in SAN extension')

                else:
                    raise ValueError('SAN extension is required for OPC UA Client Certificates')

                issuer = OpcUaClientCredentialIssuer(device=self.device, domain=self.device.domain)
                issued_app_cred = issuer.issue_opcua_client_certificate(
                    common_name=common_name_value,
                    application_uri=application_uri,
                    validity_days=validity_in_days,
                    public_key=loaded_public_key,
                )
            else:
                raise ValueError

            cp_header = rfc4210.PKIHeader()

            cp_header['pvno'] = CMP_MESSAGE_VERSION

            issuing_ca_cert = self.requested_domain.issuing_ca.credential.get_certificate()
            raw_issuing_ca_subject = issuing_ca_cert.subject.public_bytes()
            name, _ = decoder.decode(raw_issuing_ca_subject, asn1spec=rfc2459.Name())
            sender = rfc2459.GeneralName()
            sender['directoryName'][0] = name
            cp_header['sender'] = sender

            cp_header['recipient'] = self.serialized_pyasn1_message['header']['sender']

            current_time = datetime.datetime.now(datetime.UTC).strftime('%Y%m%d%H%M%SZ')
            cp_header['messageTime'] = useful.GeneralizedTime(current_time).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )

            cp_header['protectionAlg'] = self.serialized_pyasn1_message['header']['protectionAlg']

            cp_header['senderKID'] = self.serialized_pyasn1_message['header']['senderKID']

            cp_header['transactionID'] = self.serialized_pyasn1_message['header']['transactionID']

            cp_header['senderNonce'] = univ.OctetString(secrets.token_bytes(SENDER_NONCE_LENGTH)).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)
            )

            cp_header['recipNonce'] = univ.OctetString(self.serialized_pyasn1_message['header']['senderNonce']).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
            )

            cp_header['generalInfo'] = self.serialized_pyasn1_message['header']['generalInfo']

            cp_extra_certs = univ.SequenceOf()

            certificate_chain = [
                self.requested_domain.issuing_ca.credential.get_certificate(),
                *self.requested_domain.issuing_ca.credential.get_certificate_chain(),
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
            # TODO(AlexHx8472): Add TLS Server Certificate Root CA

            cert_response = rfc4210.CertResponse()
            cert_response['certReqId'] = 0

            pki_status_info = rfc4210.PKIStatusInfo()
            pki_status_info['status'] = 0
            cert_response['status'] = pki_status_info

            cmp_cert = rfc4210.CMPCertificate().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            )

            encoded_cert = issued_app_cred.credential.get_certificate().public_bytes(encoding=Encoding.DER)
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

            # TODO(AlexHx8472): Use fresh salt!
            protected_part = rfc4210.ProtectedPart()
            protected_part['header'] = cp_message['header']
            protected_part['infoValue'] = cp_message['body']

            encoded_protected_part = encoder.encode(protected_part)

            hmac_gen = hmac.HMAC(hmac_key, hmac_algorithm.hash_algorithm.hash_algorithm())
            hmac_gen.update(encoded_protected_part)
            hmac_digest = hmac_gen.finalize()

            binary_stuff = bin(int.from_bytes(hmac_digest, byteorder='big'))[2:].zfill(160)
            cp_message['protection'] = rfc4210.PKIProtection(univ.BitString(binary_stuff)).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )

            encoded_cp_message = encoder.encode(cp_message)
            decoded_cp_message, _ = decoder.decode(encoded_cp_message, asn1Spec=rfc4210.PKIMessage())

        else:
            if not self.application_certificate_template:
                return HttpResponse('Missing application certificate template.', status=404)

            extra_certs = self.serialized_pyasn1_message['extraCerts']
            if extra_certs is None or len(extra_certs) == 0:
                err_msg = 'No extra certificates found in the PKIMessage.'
                raise ValueError(err_msg)

            cmp_signer_extra_cert = extra_certs[0]
            der_cmp_signer_cert = encoder.encode(cmp_signer_extra_cert)
            cmp_signer_cert = x509.load_der_x509_certificate(der_cmp_signer_cert)

            device_id = int(cmp_signer_cert.subject.get_attributes_for_oid(x509.NameOID.USER_ID)[0].value)
            device_serial_number = cmp_signer_cert.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)[0].value
            domain_name = cmp_signer_cert.subject.get_attributes_for_oid(x509.NameOID.DOMAIN_COMPONENT)[0].value
            common_name = cmp_signer_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0]

            if isinstance(common_name.value, str):
                common_name_value = common_name.value
            elif isinstance(common_name.value, bytes):
                common_name_value = common_name.value.decode()
            else:
                err_msg = 'Failed to parse common name value'
                raise ValueError(err_msg)

            if common_name_value != 'Trustpoint Domain Credential':
                err_msg = 'Not a domain credential.'
                raise ValueError(err_msg)

            try:
                self.device = DeviceModel.objects.get(pk=device_id)
            except DeviceModel.DoesNotExist:
                return HttpResponse('Device not found.', status=404)

            if device_serial_number != self.device.serial_number:
                err_msg = 'SN mismatch'
                raise ValueError(err_msg)

            if domain_name != self.device.domain.unique_name:
                err_msg = 'Domain mismatch.'
                raise ValueError(err_msg)

            issuing_ca_certificate = self.device.domain.issuing_ca.credential.get_certificate()

            # verifies the domain credential signature
            cmp_signer_cert.verify_directly_issued_by(issuing_ca_certificate)

            if not self.device.domain_credential_onboarding:
                return HttpResponse(
                    'The corresponding device is not configured to use the onboarding mechanism.', status=404
                )

            if self.device.pki_protocol != DeviceModel.PkiProtocol.CMP_CLIENT_CERTIFICATE.value:
                return HttpResponse('PKI protocol CMP client certificate expected, but got something else.')

            message_body_name = self.serialized_pyasn1_message['body'].getName()
            if message_body_name != 'cr':
                return HttpResponse(f'Expected CMP CR body, but got CMP {message_body_name.upper()} body.', status=450)

            check_header(serialized_pyasn1_message=self.serialized_pyasn1_message)

            protection_value = self.serialized_pyasn1_message['protection'].asOctets()

            if self.serialized_pyasn1_message['body'].getName() != 'cr':
                err_msg = 'not cr message'
                raise ValueError(err_msg)

            cr_body = self.serialized_pyasn1_message['body']['cr']
            if len(cr_body) > 1:
                err_msg = 'multiple CertReqMessages found for CR.'
                raise ValueError(err_msg)

            if len(cr_body) < 1:
                err_msg = 'no CertReqMessages found for CR.'
                raise ValueError(err_msg)

            cert_req_msg = cr_body[0]['certReq']

            if cert_req_msg['certReqId'] != 0:
                err_msg = 'certReqId must be 0.'
                raise ValueError(err_msg)

            if not cert_req_msg['certTemplate'].hasValue():
                err_msg = 'certTemplate must be contained in CR CertReqMessage.'
                raise ValueError(err_msg)

            cert_req_template = cert_req_msg['certTemplate']

            # noinspection PyBroadException
            try:
                validity_not_before = convert_rfc2459_time(cert_req_template['validity']['notBefore'])
                validity_not_after = convert_rfc2459_time(cert_req_template['validity']['notAfter'])
                validity_in_days = (validity_not_after - validity_not_before).days
            except Exception:  # noqa: BLE001
                validity_in_days = DEFAULT_VALIDITY_DAYS

            if cert_req_template['version'].hasValue() and cert_req_template['version'] != CERT_TEMPLATE_VERSION:
                err_msg = 'Version must be 2 if supplied in certificate request.'
                raise ValueError(err_msg)

            if not cert_req_template['subject'].isValue:
                err_msg = 'subject missing in CertReqMessage.'
                raise ValueError(err_msg)

            # ignores subject request for now and forces values to set
            subject = NameParser.parse_name(cert_req_template['subject'])

            common_names = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if len(common_names) != 1:
                raise ValueError

            common_name = common_names[0]
            if isinstance(common_name.value, str):
                common_name_value = common_name.value
            elif isinstance(common_name.value, bytes):
                common_name_value = common_name.value.decode()
            else:
                err_msg = 'Failed to parse common name value'
                raise ValueError(err_msg)

            # only local key-gen supported currently -> public key must be present
            asn1_public_key = cert_req_template['publicKey']
            if not asn1_public_key.hasValue():
                err_msg = 'Public-missing in CertTemplate.'
                raise ValueError(err_msg)

            spki = rfc2511.SubjectPublicKeyInfo()
            spki.setComponentByName('algorithm', cert_req_template['publicKey']['algorithm'])
            spki.setComponentByName('subjectPublicKey', cert_req_template['publicKey']['subjectPublicKey'])
            loaded_public_key = load_der_public_key(encoder.encode(spki))

            # TODO(AlexHx8472): verify popo / process popo: popo = cr_body[0]['pop'].prettyPrint()

            protected_part = rfc4210.ProtectedPart()
            protected_part['header'] = self.serialized_pyasn1_message['header']
            protected_part['infoValue'] = self.serialized_pyasn1_message['body']

            encoded_protected_part = encoder.encode(protected_part)
            signature_suite = SignatureSuite.from_certificate(issuing_ca_certificate)

            public_key = cmp_signer_cert.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature=protection_value,
                    data=encoded_protected_part,
                    padding=padding.PKCS1v15(),
                    algorithm=signature_suite.algorithm_identifier.hash_algorithm.hash_algorithm(),
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature=protection_value,
                    data=encoded_protected_part,
                    signature_algorithm=ec.ECDSA(signature_suite.algorithm_identifier.hash_algorithm.hash_algorithm()),
                )

            # Checks regarding contained public key and corresponding signature suite of the issuing CA
            issuing_ca_certificate = self.requested_domain.issuing_ca.credential.get_certificate()
            signature_suite = SignatureSuite.from_certificate(issuing_ca_certificate)
            if not signature_suite.public_key_matches_signature_suite(loaded_public_key):
                err_msg = 'Contained public key type does not match the signature suite.'
                raise ValueError(err_msg)

            if self.application_certificate_template == ApplicationCertificateTemplateNames.TLS_CLIENT:
                issuer = LocalTlsClientCredentialIssuer(device=self.device, domain=self.device.domain)
                issued_app_cred = issuer.issue_tls_client_certificate(
                    common_name=common_name_value, validity_days=validity_in_days, public_key=loaded_public_key
                )
            elif self.application_certificate_template == ApplicationCertificateTemplateNames.TLS_SERVER:
                if cert_req_template['extensions'].hasValue():
                    san_extensions = [
                        extension
                        for extension in cert_req_template['extensions']
                        if str(extension['extnID']) == ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string
                    ]
                    if len(san_extensions) != 1:
                        raise ValueError
                    san_extension = san_extensions[0]
                    san_critical = str(san_extension['critical']) == 'True'
                    san_extension_bytes = bytes(san_extension['extnValue'])
                    san_asn1, _ = decoder.decode(san_extension_bytes, asn1Spec=rfc2459.SubjectAltName())

                    dns_names = []
                    ipv4_addresses = []
                    ipv6_addresses = []

                    for general_name in san_asn1:
                        name_type = general_name.getName()
                        value = general_name.getComponent()

                        if name_type == 'iPAddress':
                            try:
                                ipv4_addresses.append(ipaddress.IPv4Address(value.asOctets()))
                            except (ValueError, TypeError):
                                ipv6_addresses.append(ipaddress.IPv6Address(value.asOctets()))

                        elif name_type == 'dNSName':
                            dns_names.append(str(value))
                else:
                    raise ValueError

                tls_server_issuer = LocalTlsServerCredentialIssuer(device=self.device, domain=self.device.domain)
                issued_app_cred = tls_server_issuer.issue_tls_server_certificate(
                    common_name=common_name_value,
                    validity_days=validity_in_days,
                    ipv4_addresses=ipv4_addresses,
                    ipv6_addresses=ipv6_addresses,
                    san_critical=san_critical,
                    domain_names=dns_names,
                    public_key=loaded_public_key,
                )
            elif self.application_certificate_template == ApplicationCertificateTemplateNames.OPCUA_SERVER:
                if cert_req_template['extensions'].hasValue():
                    san_extensions = [
                        extension
                        for extension in cert_req_template['extensions']
                        if str(extension['extnID']) == ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string
                    ]
                    if len(san_extensions) != 1:
                        raise ValueError('Invalid SAN extension count')

                    san_extension = san_extensions[0]
                    # san_critical = str(san_extension['critical']) == 'True'
                    san_extension_bytes = bytes(san_extension['extnValue'])
                    san_asn1, _ = decoder.decode(san_extension_bytes, asn1Spec=rfc2459.SubjectAltName())

                    dns_names = []
                    ipv4_addresses = []
                    ipv6_addresses = []
                    application_uri = None

                    for general_name in san_asn1:
                        name_type = general_name.getName()
                        value = general_name.getComponent()

                        if name_type == 'iPAddress':
                            try:
                                ipv4_addresses.append(ipaddress.IPv4Address(value.asOctets()))
                            except (ValueError, TypeError):
                                ipv6_addresses.append(ipaddress.IPv6Address(value.asOctets()))

                        elif name_type == 'dNSName':
                            dns_names.append(str(value))

                        elif name_type == 'uniformResourceIdentifier':
                            application_uri = str(value)

                    if not application_uri:
                        raise ValueError('Missing OPC UA Application URI in SAN extension')

                else:
                    raise ValueError('SAN extension is required for OPC UA Server Certificates')

                issuer = OpcUaServerCredentialIssuer(device=self.device, domain=self.device.domain)
                issued_app_cred = issuer.issue_opcua_server_certificate(
                    common_name=common_name_value,
                    application_uri=application_uri,
                    ipv4_addresses=ipv4_addresses,
                    ipv6_addresses=ipv6_addresses,
                    domain_names=dns_names,
                    validity_days=validity_in_days,
                    public_key=loaded_public_key,
                )

            elif self.application_certificate_template == ApplicationCertificateTemplateNames.OPCUA_CLIENT:
                if cert_req_template['extensions'].hasValue():
                    san_extensions = [
                        extension
                        for extension in cert_req_template['extensions']
                        if str(extension['extnID']) == ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string
                    ]
                    if len(san_extensions) != 1:
                        raise ValueError('Invalid SAN extension count')

                    san_extension = san_extensions[0]
                    # san_critical = str(san_extension['critical']) == 'True'
                    san_extension_bytes = bytes(san_extension['extnValue'])
                    san_asn1, _ = decoder.decode(san_extension_bytes, asn1Spec=rfc2459.SubjectAltName())

                    application_uri = None

                    for general_name in san_asn1:
                        name_type = general_name.getName()
                        value = general_name.getComponent()

                        if name_type == 'uniformResourceIdentifier':
                            application_uri = str(value)

                    if not application_uri:
                        raise ValueError('Missing OPC UA Application URI in SAN extension')

                else:
                    raise ValueError('SAN extension is required for OPC UA Client Certificates')

                issuer = OpcUaClientCredentialIssuer(device=self.device, domain=self.device.domain)
                issued_app_cred = issuer.issue_opcua_client_certificate(
                    common_name=common_name_value,
                    application_uri=application_uri,
                    validity_days=validity_in_days,
                    public_key=loaded_public_key,
                )
            else:
                raise ValueError

            cp_header = rfc4210.PKIHeader()

            cp_header['pvno'] = CMP_MESSAGE_VERSION

            issuing_ca_cert = self.requested_domain.issuing_ca.credential.get_certificate()
            raw_issuing_ca_subject = issuing_ca_cert.subject.public_bytes()
            name, _ = decoder.decode(raw_issuing_ca_subject, asn1spec=rfc2459.Name())
            sender = rfc2459.GeneralName()
            sender['directoryName'][0] = name
            cp_header['sender'] = sender

            cp_header['recipient'] = self.serialized_pyasn1_message['header']['sender']

            current_time = datetime.datetime.now(datetime.UTC).strftime('%Y%m%d%H%M%SZ')
            cp_header['messageTime'] = useful.GeneralizedTime(current_time).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )

            cp_header['protectionAlg'] = self.serialized_pyasn1_message['header']['protectionAlg']

            ski = x509.SubjectKeyIdentifier.from_public_key(issuing_ca_cert.public_key())
            cp_header['senderKID'] = rfc2459.KeyIdentifier(ski.digest).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
            )

            cp_header['transactionID'] = self.serialized_pyasn1_message['header']['transactionID']

            cp_header['senderNonce'] = univ.OctetString(secrets.token_bytes(SENDER_NONCE_LENGTH)).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)
            )

            cp_header['recipNonce'] = univ.OctetString(self.serialized_pyasn1_message['header']['senderNonce']).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
            )

            cp_header['generalInfo'] = self.serialized_pyasn1_message['header']['generalInfo']

            cp_extra_certs = univ.SequenceOf()

            certificate_chain = [
                self.requested_domain.issuing_ca.credential.get_certificate(),
                *self.requested_domain.issuing_ca.credential.get_certificate_chain(),
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
            # TODO(AlexHx8472): Add TLS Server Certificate Root CA

            cert_response = rfc4210.CertResponse()
            cert_response['certReqId'] = 0

            pki_status_info = rfc4210.PKIStatusInfo()
            pki_status_info['status'] = 0
            cert_response['status'] = pki_status_info

            cmp_cert = rfc4210.CMPCertificate().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            )

            encoded_cert = issued_app_cred.credential.get_certificate().public_bytes(encoding=Encoding.DER)
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

            protected_part = rfc4210.ProtectedPart()
            protected_part['header'] = cp_message['header']
            protected_part['infoValue'] = cp_message['body']

            encoded_protected_part = encoder.encode(protected_part)

            private_key = load_pem_private_key(
                self.device.domain.issuing_ca.credential.private_key.encode(), password=None
            )
            # TODO(AlexHx8472): Algo support

            if isinstance(private_key, rsa.RSAPrivateKey):
                signature = private_key.sign(
                    encoded_protected_part,
                    padding.PKCS1v15(),
                    signature_suite.algorithm_identifier.hash_algorithm.hash_algorithm(),
                )
            elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                signature = private_key.sign(
                    encoded_protected_part,
                    ec.ECDSA(signature_suite.algorithm_identifier.hash_algorithm.hash_algorithm()),
                )
            else:
                raise TypeError

            cp_message['protection'] = rfc4210.PKIProtection(univ.BitString.fromOctetString(signature)).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )

            encoded_cp_message = encoder.encode(cp_message)
            decoded_cp_message, _ = decoder.decode(encoded_cp_message, asn1Spec=rfc4210.PKIMessage())

        return HttpResponse(encoded_cp_message, content_type='application/pkixcmp', status=200)


def convert_rfc2459_time(time_obj: rfc2459.Time) -> datetime.datetime:
    """Convert a pyasn1_modules.rfc2459.Time object to a timezone-aware datetime (UTC).

    The Time object is a CHOICE between:
      - utcTime:  YYMMDDHHMMSSZ
      - generalizedTime: YYYYMMDDHHMMSSZ

    Returns:
        A datetime object in UTC.

    Raises:
        ValueError: If the time format is unexpected.
    """
    time_field = time_obj.getName()
    time_str = str(time_obj.getComponent())

    if time_field == 'utcTime':
        dt = datetime.datetime.strptime(time_str, '%y%m%d%H%M%SZ').astimezone(tz=datetime.UTC)
        if dt.year >= UTC_TIME_THRESHOLD:
            dt = dt.replace(year=dt.year - UTC_TIME_CORRECTION)
    elif time_field == 'generalTime':
        dt = datetime.datetime.strptime(time_str, '%Y%m%d%H%M%SZ').astimezone(tz=datetime.UTC)
    else:
        err_msg = f'Unexpected time field: {time_field}'
        raise ValueError(err_msg)

    return dt
