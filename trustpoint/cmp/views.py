"""This module contains the CMP endpoints (views)."""

from __future__ import annotations

import datetime
import enum
import ipaddress
import secrets
from typing import TYPE_CHECKING, Protocol, cast, get_args

from aoki.views import AokiServiceMixin
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
from devices.models import (
    DeviceModel,
    IssuedCredentialModel,
    NoOnboardingPkiProtocol,
    OnboardingPkiProtocol,
    OnboardingProtocol,
    OnboardingStatus,
)
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from pki.models.domain import DomainModel
from pki.util.idevid import IDevIDAuthenticator
from pyasn1.codec.der import decoder, encoder  # type: ignore[import-untyped]
from pyasn1.type import tag, univ, useful  # type: ignore[import-untyped]
from pyasn1_modules import rfc2459, rfc2511, rfc4210  # type: ignore[import-untyped]
from trustpoint_core.crypto_types import PublicKey
from trustpoint_core.oid import AlgorithmIdentifier, HashAlgorithm, HmacAlgorithm, SignatureSuite

from cmp.util import NameParser

if TYPE_CHECKING:
    from typing import Any, TypeGuard

    from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
    from devices.models import NoOnboardingConfigModel, OnboardingConfigModel
    from django.http import HttpRequest
    from pki.models.credential import CredentialModel


UTC_TIME_THRESHOLD = 2050
UTC_TIME_CORRECTION = 100
CERT_TEMPLATE_VERSION = 2
DEFAULT_VALIDITY_DAYS = 10
CMP_MESSAGE_VERSION = 2
SENDER_NONCE_LENGTH = 16
TRANSACTION_ID_LENGTH = 16


def is_supported_public_key(public_key: PublicKeyTypes) -> TypeGuard[PublicKey]:
    """TypeGuard function that narrows down the public key type.

    Args:
        public_key: The loaded public key to check if it is supported.

    Returns:
        True if it is supported, False otherwise.
    """
    return isinstance(public_key, get_args(PublicKey))


def load_supported_public_key_type(der_bytes: bytes) -> PublicKey:
    """Tries to load the public key from bytes and checks if it is a supported key.

    Args:
        der_bytes: The bytes containing the key.

    Raises:
        ValueError: If loading of the public key failed.
        TypeError: If the loaded public key is of an unsupported type.

    Returns:
        The loaded public key.
    """
    try:
        loaded_key = load_der_public_key(der_bytes)

    except Exception as exception:
        err_msg = 'Failed to load private key.'
        raise ValueError(err_msg) from exception

    if not is_supported_public_key(loaded_key):
        err_msg = f'Key of type {type(loaded_key)} found, but expected one of {PublicKey}.'
        raise TypeError(err_msg)

    return loaded_key


class ApplicationCertificateTemplateNames(enum.Enum):
    """Application Certificate Template."""

    TLS_CLIENT = 'tls-client'
    TLS_SERVER = 'tls-server'
    OPCUA_SERVER = 'opc-ua-server'
    OPCUA_CLIENT = 'opc-ua-client'


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

        parent = cast('Dispatchable', super())
        return parent.dispatch(request, *args, **kwargs)


class CmpRequestedDomainExtractorMixin:
    """Domain name extractor."""

    requested_domain: DomainModel
    is_aoki: bool = False

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Dispatch method."""
        domain_name = cast('str', kwargs.get('domain'))
        if domain_name == '.aoki' and '/initialization/.aoki' in request.path: # basing this on URL is hacky
            self.is_aoki = True
        else:
            try:
                self.requested_domain = DomainModel.objects.get(unique_name=domain_name)
            except DomainModel.DoesNotExist:
                return HttpResponse('Domain does not exist.', status=404)

        parent = cast('Dispatchable', super())
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

        parent = cast('Dispatchable', super())
        return parent.dispatch(request, *args, **kwargs)


class CmpRequestTemplateExtractorMixin:
    """CMP template extractor."""

    application_certificate_template: ApplicationCertificateTemplateNames | None = None

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Dispatch method."""
        self.template_name = cast('None | str', kwargs.get('template'))
        parent = cast('Dispatchable', super())

        if self.template_name is None:
            return parent.dispatch(request, *args, **kwargs)

        try:
            self.application_certificate_template = ApplicationCertificateTemplateNames(self.template_name.lower())
        except (ValueError, TypeError):
            return HttpResponse('Template does not exist.', status=404)

        return parent.dispatch(request, *args, **kwargs)

    @staticmethod
    def _check_header(serialized_pyasn1_message: rfc4210.PKIMessage) -> None:
        """Checks some parts of the header."""
        if serialized_pyasn1_message['header']['pvno'] != CMP_MESSAGE_VERSION:
            err_msg = 'pvno fail'
            raise ValueError(err_msg)

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

    def _extract_cert_req_template(self, pki_body: rfc4210.PKIBody) -> rfc2511.CertTemplate:
        """Extracts the certificate request template from the PKI (IR/CR) message body."""
        cert_req_msg = pki_body[0]['certReq']

        if cert_req_msg['certReqId'] != 0:
            err_msg = 'certReqId must be 0.'
            raise ValueError(err_msg)

        if not cert_req_msg['certTemplate'].hasValue():
            err_msg = 'certTemplate must be contained in IR/CR CertReqMessage.'
            raise ValueError(err_msg)

        cert_req_template = cert_req_msg['certTemplate']

        if cert_req_template['version'].hasValue() and cert_req_template['version'] != CERT_TEMPLATE_VERSION:
            err_msg = 'Version must be 2 if supplied in certificate request.'
            raise ValueError(err_msg)

        return cert_req_template

    @staticmethod
    def get_subject_common_name(cert_req_template: rfc2511.CertTemplate) -> str:
        """Extracts the common name from the subject in the certificate request template."""
        if not cert_req_template['subject'].isValue:
            err_msg = 'subject missing in CertReqMessage.'
            raise ValueError(err_msg)

        # ignores subject request for now and forces values to set
        subject = NameParser.parse_name(cert_req_template['subject'])

        common_names = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if len(common_names) != 1:
            exc_msg = 'Exactly one common name must be present in the subject.'
            raise ValueError(exc_msg)

        common_name = common_names[0]

        if isinstance(common_name.value, str):
            return common_name.value
        if isinstance(common_name.value, bytes):
            return common_name.value.decode()

        err_msg = 'Failed to parse common name value'
        raise TypeError(err_msg)

    def _load_cert_req_public_key(self, cert_req_template: rfc2511.CertTemplate) -> PublicKey:
        # only local key-gen supported currently -> public key must be present
        asn1_public_key = cert_req_template['publicKey']
        if not asn1_public_key.hasValue():
            err_msg = 'Public key missing in CertTemplate.'
            raise ValueError(err_msg)

        spki = rfc2511.SubjectPublicKeyInfo()
        spki.setComponentByName('algorithm', cert_req_template['publicKey']['algorithm'])
        spki.setComponentByName('subjectPublicKey', cert_req_template['publicKey']['subjectPublicKey'])
        return load_supported_public_key_type(encoder.encode(spki))

    @staticmethod
    def _verify_protection_shared_secret(
            serialized_pyasn1_message: rfc4210.PKIMessage, shared_secret: str) -> hmac.HMAC:
        """Verifies the HMAC-based protection of a CMP message using a shared secret.

        Returns a new HMAC object that can be used to sign the response message.
        """
        pbm_parameters_bitstring = serialized_pyasn1_message['header']['protectionAlg']['parameters']
        decoded_pbm, _ = decoder.decode(pbm_parameters_bitstring, asn1Spec=rfc4210.PBMParameter())

        salt = decoded_pbm['salt'].asOctets()
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

        encoded_protected_part = get_encoded_protected_part(serialized_pyasn1_message)
        protection_value = serialized_pyasn1_message['protection'].asOctets()

        hmac_gen = hmac.HMAC(hmac_key, hmac_algorithm.hash_algorithm.hash_algorithm())
        hmac_gen.update(encoded_protected_part)

        try:
            hmac_gen.verify(protection_value)
        except InvalidSignature as exception:
            err_msg = 'hmac verification failed.'
            raise ValueError(err_msg) from exception

        return hmac.HMAC(hmac_key, hmac_algorithm.hash_algorithm.hash_algorithm())

    @staticmethod
    def _verify_protection_signature(
            serialized_pyasn1_message: rfc4210.PKIMessage, cmp_signer_cert: x509.Certificate) -> None:
        """Verifies the message signature of a CMP message using signature-based protection."""
        encoded_protected_part = get_encoded_protected_part(serialized_pyasn1_message)
        protection_value = serialized_pyasn1_message['protection'].asOctets()
        signature_suite = SignatureSuite.from_certificate(cmp_signer_cert)

        hash_algorithm = signature_suite.algorithm_identifier.hash_algorithm
        if hash_algorithm is None:
            err_msg = 'Failed to get the corresponding hash algorithm.'
            raise ValueError(err_msg)

        public_key = cmp_signer_cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature=protection_value,
                data=encoded_protected_part,
                padding=padding.PKCS1v15(),
                algorithm=hash_algorithm.hash_algorithm(),
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature=protection_value,
                data=encoded_protected_part,
                signature_algorithm=ec.ECDSA(hash_algorithm.hash_algorithm()),
            )
        else:
            err_msg = 'Cannot verify signature due to unsupported public key type.'
            raise TypeError(err_msg)


class CmpResponseBuilderMixin:
    """Mixin for CMP response message building shared between request types."""

    @staticmethod
    def _parse_san_extension(cert_req_template: rfc2511.CertTemplate) -> dict[str, Any]:
        """Parses the (mandatory) SAN extension from the certificate request template.

        Returns a dictionary with the following keys:
            - 'dns_names': List of DNS/domain names.
            - 'ipv4_addresses': List of IPv4 addresses.
            - 'ipv6_addresses': List of IPv6 addresses.
            - 'uris': List of URIs.
            - 'san_critical': Boolean indicating if the SAN extension is critical.
        """
        if not cert_req_template['extensions'].hasValue():
            exc_msg = 'No extensions found in the request template.'
            raise ValueError(exc_msg)

        san_extensions = [
            extension
            for extension in cert_req_template['extensions']
            if str(extension['extnID']) == ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string
        ]
        if len(san_extensions) != 1:
            exc_msg = 'Exactly one SAN extension must be present in the request.'
            raise ValueError(exc_msg)
        san_extension = san_extensions[0]
        san_critical = str(san_extension['critical']) == 'True'
        san_extension_bytes = bytes(san_extension['extnValue'])
        san_asn1, _ = decoder.decode(san_extension_bytes, asn1Spec=rfc2459.SubjectAltName())

        dns_names = []
        ipv4_addresses = []
        ipv6_addresses = []
        uris = []

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
                uris.append(str(value))

        return {
            'dns_names': dns_names,
            'ipv4_addresses': ipv4_addresses,
            'ipv6_addresses': ipv6_addresses,
            'uris': uris,
            'san_critical': san_critical,
        }

    @staticmethod
    def _issue_application_credential(
            cert_req_template: rfc2511.CertReq,
            public_key: PublicKey,
            device: DeviceModel,
            application_certificate_template: ApplicationCertificateTemplateNames
    ) -> IssuedCredentialModel:
        """Issues an application certificate for CMP CR."""
        common_name = CmpRequestTemplateExtractorMixin.get_subject_common_name(cert_req_template)
        domain = device.domain
        if not domain:
            err_msg = 'Device domain is not set.'
            raise ValueError(err_msg)

        # noinspection PyBroadException
        try:
            validity_not_before = convert_rfc2459_time(cert_req_template['validity']['notBefore'])
            validity_not_after = convert_rfc2459_time(cert_req_template['validity']['notAfter'])
            validity_in_days = (validity_not_after - validity_not_before).days
        except Exception:  # noqa: BLE001
            validity_in_days = DEFAULT_VALIDITY_DAYS

        if application_certificate_template == ApplicationCertificateTemplateNames.TLS_CLIENT:
            issuer = LocalTlsClientCredentialIssuer(device=device, domain=domain)
            return issuer.issue_tls_client_certificate(
                common_name=common_name, validity_days=validity_in_days, public_key=public_key
            )
        # Below certificate templates require the SubjectAltName extension
        san = CmpResponseBuilderMixin._parse_san_extension(cert_req_template)
        if application_certificate_template == ApplicationCertificateTemplateNames.TLS_SERVER:
            tls_server_issuer = LocalTlsServerCredentialIssuer(device=device, domain=domain)
            return tls_server_issuer.issue_tls_server_certificate(
                common_name=common_name,
                validity_days=validity_in_days,
                ipv4_addresses=san['ipv4_addresses'],
                ipv6_addresses=san['ipv6_addresses'],
                san_critical=san['san_critical'],
                domain_names=san['dns_names'],
                public_key=public_key,
            )

        # OPC UA
        if (application_certificate_template in
            [ApplicationCertificateTemplateNames.OPCUA_SERVER, ApplicationCertificateTemplateNames.OPCUA_CLIENT]):
            application_uri = str(san['uris'][0]) if san['uris'] else None
            if not application_uri:
                err_msg = 'Missing OPC UA Application URI in SAN extension'
                raise ValueError(err_msg)

            if application_certificate_template == ApplicationCertificateTemplateNames.OPCUA_SERVER:
                opc_ua_server_cred_issuer = OpcUaServerCredentialIssuer(device=device, domain=domain)
                return opc_ua_server_cred_issuer.issue_opc_ua_server_certificate(
                    common_name=common_name,
                    application_uri=application_uri,
                    ipv4_addresses=san['ipv4_addresses'],
                    ipv6_addresses=san['ipv6_addresses'],
                    # TODO (FHKatCSW): san_critical not supported in OpcUaServerCredentialIssuer    # noqa: FIX002
                    #san_critical=san['san_critical'],  # noqa: ERA001
                    domain_names=san['dns_names'],
                    validity_days=validity_in_days,
                    public_key=public_key,
                )

            if application_certificate_template == ApplicationCertificateTemplateNames.OPCUA_CLIENT:
                opc_ua_client_cred_issuer = OpcUaClientCredentialIssuer(device=device, domain=domain)
                return opc_ua_client_cred_issuer.issue_opc_ua_client_certificate(
                    common_name=common_name,
                    application_uri=application_uri,
                    # TODO (FHKatCSW): san_critical not supported in OpcUaClientCredentialIssuer    # noqa: FIX002
                    #san_critical=san['san_critical'],  # noqa: ERA001
                    validity_days=validity_in_days,
                    public_key=public_key,
                )

        exc_msg = f'The app cert template {application_certificate_template} is not supported.'
        raise ValueError(exc_msg)

    @staticmethod
    def _build_response_message_header(
            serialized_pyasn1_message: rfc4210.PKIMessage,
            sender_kid: rfc2459.KeyIdentifier,
            issuer_credential: CredentialModel) -> rfc4210.PKIHeader:
        """Builds the PKI response message header for the IP and CP response messages."""
        header = rfc4210.PKIHeader()

        header['pvno'] = CMP_MESSAGE_VERSION

        issuing_ca_cert = issuer_credential.get_certificate()
        raw_issuing_ca_subject = issuing_ca_cert.subject.public_bytes()
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
            pki_message: rfc4210.PKIMessage, hmac_gen: hmac.HMAC,
    ) -> rfc4210.PKIMessage:
        """Adds HMAC-based shared-secret protection to the base PKI message."""
        # TODO(AlexHx8472): Use fresh salt! # noqa: FIX002
        encoded_protected_part = get_encoded_protected_part(pki_message)

        hmac_gen.update(encoded_protected_part)
        hmac_digest = hmac_gen.finalize()

        binary_stuff = bin(int.from_bytes(hmac_digest, byteorder='big'))[2:].zfill(160)
        pki_message['protection'] = rfc4210.PKIProtection(univ.BitString(binary_stuff)).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )

        return pki_message

    def _sign_pki_message(
            self, pki_message: rfc4210.PKIMessage, signer_credential: CredentialModel
            ) -> rfc4210.PKIMessage:
        """Applies signature-based protection to the base PKI message."""
        encoded_protected_part = get_encoded_protected_part(pki_message)

        private_key = load_pem_private_key(
            signer_credential.private_key.encode(), password=None
        )
        signature_suite = SignatureSuite.from_certificate(signer_credential.get_certificate())
        hash_algorithm = signature_suite.algorithm_identifier.hash_algorithm
        if hash_algorithm is None:
            err_msg = 'Failed to get the corresponding hash algorithm.'
            raise ValueError(err_msg)

        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(
                encoded_protected_part,
                padding.PKCS1v15(),
                hash_algorithm.hash_algorithm(),
            )
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            signature = private_key.sign(
                encoded_protected_part,
                ec.ECDSA(hash_algorithm.hash_algorithm()),
            )
        else:
            exc_msg = 'Cannot sign due to unsupported private key type.'
            raise TypeError(exc_msg)

        pki_message['protection'] = rfc4210.PKIProtection(univ.BitString.fromOctetString(signature)).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )

        return pki_message


def get_encoded_protected_part(cmp_message: rfc4210.PKIMessage) -> Any: # bytes?
    """Encode the protected part of the CMP message."""
    protected_part = rfc4210.ProtectedPart()
    protected_part['header'] = cmp_message['header']
    protected_part['infoValue'] = cmp_message['body']
    return encoder.encode(protected_part)


@method_decorator(csrf_exempt, name='dispatch')
class CmpInitializationRequestView(
    CmpHttpMixin,
    CmpRequestedDomainExtractorMixin,
    CmpPkiMessageSerializerMixin,
    CmpRequestTemplateExtractorMixin,
    CmpResponseBuilderMixin,
    View
):
    """Handles CMP Initialization Request Messages."""

    http_method_names = ('post',)

    raw_message: bytes
    serialized_pyasn1_message: rfc4210.PKIMessage
    requested_domain: DomainModel
    device: None | DeviceModel = None

    def _extract_ir_body(self) -> rfc4210.PKIBody:
        message_body_name = self.serialized_pyasn1_message['body'].getName()
        if message_body_name != 'ir':
            err_msg = f'Expected CMP IR body, but got CMP {message_body_name.upper()} body.'
            raise ValueError(err_msg)

        ir_body = self.serialized_pyasn1_message['body']['ir']
        if len(ir_body) > 1:
            err_msg = 'multiple CertReqMessages found for IR.'
            raise ValueError(err_msg)

        if len(ir_body) < 1:
            err_msg = 'no CertReqMessages found for IR.'
            raise ValueError(err_msg)

        return ir_body


    def _build_base_ip_message(
            self,
            issued_cred: IssuedCredentialModel,
            issuer_credential: CredentialModel,
            sender_kid: rfc2459.KeyIdentifier,
            signer_credential: CredentialModel | None = None,
            ) -> rfc4210.PKIMessage:
        """Builds the IP response message (without the protection)."""
        ip_header = self._build_response_message_header(
            serialized_pyasn1_message=self.serialized_pyasn1_message,
            sender_kid=sender_kid,
            issuer_credential=signer_credential if signer_credential else issuer_credential)

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

        encoded_cert = issued_cred.credential.get_certificate().public_bytes(encoding=Encoding.DER)
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


    def _handle_shared_secret_initialization_request(
            self) -> HttpResponse:
        """Handles IR for initial certificate requests with shared secret protection."""
        if TYPE_CHECKING: # mypy does not know we only get here if self.device is not None
            assert self.device is not None

        if self.device.domain != self.requested_domain:
            err_msg = 'The device domain does not match the requested domain.'
            raise ValueError(err_msg)

        config: OnboardingConfigModel | NoOnboardingConfigModel | None = None
        shared_secret = None

        if self.device.onboarding_config:
            config = self.device.onboarding_config
            shared_secret = config.cmp_shared_secret
        elif self.device.no_onboarding_config:
            config = self.device.no_onboarding_config
            shared_secret = config.cmp_shared_secret
        else:
            err_msg = 'Device is not configured for shared secret authentication.'
            raise ValueError(err_msg)

        if not shared_secret:
            err_msg = 'Device is misconfigured: shared secret is missing or empty.'
            raise ValueError(err_msg)

        req_message_body = self._extract_ir_body()

        cert_req_template = self._extract_cert_req_template(req_message_body)

        loaded_public_key = self._load_cert_req_public_key(cert_req_template)

        # TODO(AlexHx8472): verify popo / process popo: popo = req_message_body[0]['pop'].prettyPrint()  # noqa: FIX002

        hmac_gen = self._verify_protection_shared_secret(
            serialized_pyasn1_message=self.serialized_pyasn1_message,
            shared_secret=shared_secret,
        )

        # Checks regarding contained public key and corresponding signature suite of the issuing CA
        issuing_ca_credential = self.requested_domain.get_issuing_ca_or_value_error().credential
        issuing_ca_cert = issuing_ca_credential.get_certificate()
        signature_suite = SignatureSuite.from_certificate(issuing_ca_cert)
        if not signature_suite.public_key_matches_signature_suite(loaded_public_key):
            err_msg = 'Contained public key type does not match the signature suite.'
            raise ValueError(err_msg)

        # Issue the credential
        if self.application_certificate_template: # application credential request
            issued_cred = self._issue_application_credential(
                cert_req_template=cert_req_template,
                public_key=loaded_public_key,
                device=self.device,
                application_certificate_template=self.application_certificate_template
            )
        else: # domain credential request
            issuer_domain_credential = LocalDomainCredentialIssuer(device=self.device, domain=self.device.domain)
            issued_cred = issuer_domain_credential.issue_domain_credential_certificate(
                public_key=loaded_public_key
            )

        # Build the IP response message
        sender_kid = self.serialized_pyasn1_message['header']['senderKID']
        ip_message = self._build_base_ip_message(
            issued_cred=issued_cred, sender_kid=sender_kid, issuer_credential=issuing_ca_credential
        )

        ip_message = self._add_protection_shared_secret(
            pki_message=ip_message, hmac_gen=hmac_gen
        )

        encoded_ip_message = encoder.encode(ip_message)
        _decoded_ip_message, _ = decoder.decode(encoded_ip_message, asn1Spec=rfc4210.PKIMessage())

        return HttpResponse(encoded_ip_message, content_type='application/pkixcmp', status=200)


    def _handle_signature_based_initialization_request(  # noqa: C901
            self) -> HttpResponse:
        """Handles IR for initial certificate requests with signature-based protection."""
        # different protection algorithm than password-based MAC - certificate-based protection
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

        if not cmp_signer_cert: # was 'loaded_extra_cert', does that make any sense?
            err_msg = 'CMP signer certificate missing in extra certs.'
            raise ValueError(err_msg)

        self.device = IDevIDAuthenticator.authenticate_idevid_from_x509(
            idevid_cert=cmp_signer_cert,
            intermediate_cas=intermediate_certs,
            domain=None if self.is_aoki else self.requested_domain,
            onboarding_protocol=OnboardingProtocol.CMP_IDEVID,
            pki_protocol=OnboardingPkiProtocol.CMP,
        )

        if not self.device.domain:
            return HttpResponse('Device domain is not set.', status=422)

        self.requested_domain = self.device.domain

        # device sanity checks
        if not self.device.onboarding_config:
            return HttpResponse(
                'The corresponding device is not configured to use the onboarding mechanism.', status=404
            )

        if self.device.onboarding_config.onboarding_protocol != OnboardingProtocol.CMP_IDEVID:
            return HttpResponse('Wrong onboarding protocol.')

        req_message_body = self._extract_ir_body()

        cert_req_template = self._extract_cert_req_template(req_message_body)

        # Ensure subject common name is present
        _common_name = self.get_subject_common_name(cert_req_template)

        loaded_public_key = self._load_cert_req_public_key(cert_req_template)

        # TODO(AlexHx8472): verify popo / process popo: popo = req_message_body[0]['pop'].prettyPrint()  # noqa: FIX002

        self._verify_protection_signature(
            serialized_pyasn1_message=self.serialized_pyasn1_message,
            cmp_signer_cert=cmp_signer_cert
        )

        # Checks regarding contained public key and corresponding signature suite of the issuing CA
        issuing_ca_credential = self.requested_domain.get_issuing_ca_or_value_error().credential
        issuing_ca_cert = issuing_ca_credential.get_certificate()
        signer_credential = issuing_ca_credential
        if (self.is_aoki):
            owner_credential = AokiServiceMixin.get_owner_credential(cmp_signer_cert)
            if not owner_credential:
                return HttpResponse('No DevOwnerID present for this IDevID.', status=403)
            signer_credential = owner_credential
        signature_suite = SignatureSuite.from_certificate(issuing_ca_cert)
        if not signature_suite.public_key_matches_signature_suite(loaded_public_key):
            err_msg = 'Contained public key type does not match the signature suite.'
            raise ValueError(err_msg)

        issuer_domain_credential = LocalDomainCredentialIssuer(device=self.device, domain=self.requested_domain)
        issued_cred = issuer_domain_credential.issue_domain_credential_certificate(
            public_key=loaded_public_key
        )

        # Build the response PKI message
        ski = x509.SubjectKeyIdentifier.from_public_key(signer_credential.get_certificate().public_key())
        sender_kid = rfc2459.KeyIdentifier(ski.digest).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        )

        pki_message = self._build_base_ip_message(
            issued_cred=issued_cred,
            sender_kid=sender_kid,
            issuer_credential=issuing_ca_credential,
            signer_credential=signer_credential
        )
        pki_message = self._sign_pki_message(
            pki_message=pki_message, signer_credential=signer_credential
        )

        encoded_message = encoder.encode(pki_message)
        decoded_message, _ = decoder.decode(encoded_message, asn1Spec=rfc4210.PKIMessage())

        self.device.onboarding_config.onboarding_status = OnboardingStatus.ONBOARDED
        self.device.save()

        return HttpResponse(encoded_message, content_type='application/pkixcmp', status=200)


    def post(  # noqa: PLR0911
        self,
        request: HttpRequest,
        *args: Any,
        **kwargs: Any,
    ) -> HttpResponse:
        """Handles the POST requests to the CMP IR endpoint."""
        del args, kwargs, request  # request not accessed directly
        self._check_header(serialized_pyasn1_message=self.serialized_pyasn1_message)

        protection_algorithm = AlgorithmIdentifier.from_dotted_string(
            self.serialized_pyasn1_message['header']['protectionAlg']['algorithm'].prettyPrint()
        )
        if protection_algorithm == AlgorithmIdentifier.PASSWORD_BASED_MAC:
            if self.is_aoki:
                return HttpResponse('AOKI only supported with signature-based protection (IDevID).', status=400)
            try:
                sender_kid = int(self.serialized_pyasn1_message['header']['senderKID'].prettyPrint())
                self.device = DeviceModel.objects.get(pk=sender_kid)
            except (DeviceModel.DoesNotExist, Exception):
                return HttpResponse('Device not found.', status=404)

            if (
                self.device.no_onboarding_config
                and self.device.no_onboarding_config.has_pki_protocol(NoOnboardingPkiProtocol.CMP_SHARED_SECRET)
            ):

                if not self.application_certificate_template:
                    return HttpResponse('Missing application certificate template.', status=404)


                return self._handle_shared_secret_initialization_request()
            if (
                self.device.onboarding_config
                and self.device.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.CMP)
            ):
                if self.application_certificate_template:
                    return HttpResponse(
                        'Found application certificate template for domain credential certificate request.', status=404
                    )

                return self._handle_shared_secret_initialization_request()

            return HttpResponse('Invalid Request for corresponding device.', status=460)

        return self._handle_signature_based_initialization_request()


@method_decorator(csrf_exempt, name='dispatch')
class CmpCertificationRequestView(
    CmpHttpMixin,
    CmpRequestedDomainExtractorMixin,
    CmpPkiMessageSerializerMixin,
    CmpRequestTemplateExtractorMixin,
    CmpResponseBuilderMixin,
    View
):
    """Handles CMP Certification Request Messages."""

    http_method_names = ('post',)

    raw_message: bytes
    serialized_pyasn1_message: rfc4210.PKIMessage
    requested_domain: DomainModel
    device: DeviceModel
    application_certificate_template: None | ApplicationCertificateTemplateNames = None

    def _extract_cr_body(self) -> rfc4210.PKIBody:
        message_body_name = self.serialized_pyasn1_message['body'].getName()
        if message_body_name != 'cr':
            err_msg = f'Expected CMP CR body, but got CMP {message_body_name.upper()} body.'
            raise ValueError(err_msg)

        cr_body = self.serialized_pyasn1_message['body']['cr']
        if len(cr_body) > 1:
            err_msg = 'multiple CertReqMessages found for CR.'
            raise ValueError(err_msg)

        if len(cr_body) < 1:
            err_msg = 'no CertReqMessages found for CR.'
            raise ValueError(err_msg)

        return cr_body


    def _build_base_cp_message(
            self,
            issued_cred: IssuedCredentialModel,
            issuer_credential: CredentialModel,
            sender_kid: rfc2459.KeyIdentifier
    ) -> rfc4210.PKIMessage:
        """Builds the CR response message (without the protection)."""
        cp_header = self._build_response_message_header(
            serialized_pyasn1_message=self.serialized_pyasn1_message,
            sender_kid=sender_kid,
            issuer_credential=issuer_credential)

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

        encoded_cert = issued_cred.credential.get_certificate().public_bytes(encoding=Encoding.DER)
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


    def _handle_shared_secret_certificate_request(self) -> HttpResponse:
        """Handles CMP CR for application certificates with shared secret protection."""
        if not self.application_certificate_template:
            return HttpResponse('Missing application certificate template.', status=404)

        try:
            sender_kid = int(self.serialized_pyasn1_message['header']['senderKID'].prettyPrint())
            self.device = DeviceModel.objects.get(pk=sender_kid)
        except (DeviceModel.DoesNotExist, Exception):
            return HttpResponse('Device not found.', status=404)

        if not self.device.no_onboarding_config:
            return HttpResponse(
                'Password based MAC protected CMP messages while using CMP '
                'CR message types are not allowed for onboarded devices. '
                'Use signature based protection utilizing the domain credential',
                status=422,
            )

        if not self.device.no_onboarding_config.has_pki_protocol(NoOnboardingPkiProtocol.CMP_SHARED_SECRET):
            return HttpResponse(
                'Received a password based MAC protected CMP message for a device that does not use the '
                f'pki-protocol {NoOnboardingPkiProtocol.CMP_SHARED_SECRET.label}.',
                status=422,
            )

        if self.device.domain != self.requested_domain:
            exc_msg = 'The device domain does not match the requested domain.'
            raise ValueError(exc_msg)

        if self.device.no_onboarding_config.cmp_shared_secret == '':
            err_msg = 'Device is misconfigured.'
            raise ValueError(err_msg)

        req_message_body = self._extract_cr_body()

        cert_req_template = self._extract_cert_req_template(req_message_body)

        # only local key-gen supported currently -> public key must be present
        loaded_public_key = self._load_cert_req_public_key(cert_req_template)

        # TODO(AlexHx8472): verify popo / process popo: popo = req_message_body[0]['pop'].prettyPrint()  # noqa: FIX002

        hmac_gen = self._verify_protection_shared_secret(
            serialized_pyasn1_message=self.serialized_pyasn1_message,
            shared_secret=self.device.no_onboarding_config.cmp_shared_secret,
        )

        # Checks regarding contained public key and corresponding signature suite of the issuing CA
        issuing_ca_credential = self.requested_domain.get_issuing_ca_or_value_error().credential
        issuing_ca_cert = issuing_ca_credential.get_certificate()
        signature_suite = SignatureSuite.from_certificate(issuing_ca_cert)
        if not signature_suite.public_key_matches_signature_suite(loaded_public_key):
            err_msg = 'Contained public key type does not match the signature suite.'
            raise ValueError(err_msg)

        issued_app_cred = self._issue_application_credential(
            cert_req_template=cert_req_template,
            public_key=loaded_public_key,
            device=self.device,
            application_certificate_template=self.application_certificate_template
        )

        cp_message = self._build_base_cp_message(
            issued_cred=issued_app_cred,
            issuer_credential=issuing_ca_credential,
            sender_kid=self.serialized_pyasn1_message['header']['senderKID']
        )

        cp_message = self._add_protection_shared_secret(
            pki_message=cp_message, hmac_gen=hmac_gen,
        )

        encoded_cp_message = encoder.encode(cp_message)
        decoded_cp_message, _ = decoder.decode(encoded_cp_message, asn1Spec=rfc4210.PKIMessage())

        return HttpResponse(encoded_cp_message, content_type='application/pkixcmp', status=200)


    def _handle_signature_based_certificate_request( # noqa: PLR0912, PLR0915, C901
            self) -> HttpResponse:
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
            raise TypeError(err_msg)

        if common_name_value != LocalDomainCredentialIssuer.DOMAIN_CREDENTIAL_CN:
            err_msg = 'Not a domain credential.'
            raise ValueError(err_msg)

        try:
            self.device = DeviceModel.objects.get(pk=device_id)
        except DeviceModel.DoesNotExist:
            return HttpResponse('Device not found.', status=404)

        if device_serial_number != self.device.serial_number:
            err_msg = 'SN mismatch'
            raise ValueError(err_msg)

        if not self.device.domain:
            err_msg = 'The device is not part of any domain.'
            raise ValueError(err_msg)

        if domain_name != self.device.domain.unique_name:
            err_msg = 'Domain mismatch.'
            raise ValueError(err_msg)

        issuing_ca_credential = self.device.domain.get_issuing_ca_or_value_error().credential
        issuing_ca_cert = issuing_ca_credential.get_certificate()

        # verifies the domain credential signature
        cmp_signer_cert.verify_directly_issued_by(issuing_ca_cert)

        if not self.device.onboarding_config:
            return HttpResponse(
                'The corresponding device is not configured to use the onboarding mechanism.', status=404
            )

        if not self.device.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.CMP):
            return HttpResponse('PKI protocol CMP client certificate expected, but got something else.')

        req_message_body = self._extract_cr_body()

        cert_req_template = self._extract_cert_req_template(req_message_body)

        loaded_public_key = self._load_cert_req_public_key(cert_req_template)

        # TODO(AlexHx8472): verify popo / process popo: popo = req_message_body[0]['pop'].prettyPrint()  # noqa: FIX002

        self._verify_protection_signature(
            serialized_pyasn1_message=self.serialized_pyasn1_message,
            cmp_signer_cert=cmp_signer_cert,
        )

        # Checks regarding contained public key and corresponding signature suite of the issuing CA
        signature_suite = SignatureSuite.from_certificate(issuing_ca_cert)
        if not signature_suite.public_key_matches_signature_suite(loaded_public_key):
            err_msg = 'Contained public key type does not match the signature suite.'
            raise ValueError(err_msg)

        issued_cred = self._issue_application_credential(
            cert_req_template=cert_req_template,
            public_key=loaded_public_key,
            device=self.device,
            application_certificate_template=self.application_certificate_template
        )

        # Build the response PKI message
        ski = x509.SubjectKeyIdentifier.from_public_key(issuing_ca_cert.public_key())
        sender_kid = rfc2459.KeyIdentifier(ski.digest).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        )

        pki_message = self._build_base_cp_message(
            issued_cred=issued_cred,
            issuer_credential=issuing_ca_credential,
            sender_kid=sender_kid
        )

        pki_message = self._sign_pki_message(
            pki_message=pki_message, signer_credential=issuing_ca_credential)

        encoded_message = encoder.encode(pki_message)
        decoded_message, _ = decoder.decode(encoded_message, asn1Spec=rfc4210.PKIMessage())

        return HttpResponse(encoded_message, content_type='application/pkixcmp', status=200)


    def post(
        self,
        request: HttpRequest,
        *args: Any,
        **kwargs: Any,
    ) -> HttpResponse:
        """Handles the POST requests to the CMP CR endpoint."""
        del args, kwargs, request  # request not accessed directly
        self._check_header(serialized_pyasn1_message=self.serialized_pyasn1_message)

        protection_algorithm = AlgorithmIdentifier.from_dotted_string(
            self.serialized_pyasn1_message['header']['protectionAlg']['algorithm'].prettyPrint()
        )
        if protection_algorithm == AlgorithmIdentifier.PASSWORD_BASED_MAC:
            return self._handle_shared_secret_certificate_request()

        return self._handle_signature_based_certificate_request()


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
