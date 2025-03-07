"""Views for EST (Enrollment over Secure Transport) handling authentication and certificate issuance."""

import base64
import datetime
import ipaddress
import traceback
from calendar import error
from dataclasses import dataclass
from typing import Any, ClassVar, Protocol, cast

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from pyasn1_modules.rfc2459 import common_name

from devices.issuer import LocalDomainCredentialIssuer, LocalTlsClientCredentialIssuer, LocalTlsServerCredentialIssuer
from devices.models import DeviceModel, IssuedCredentialModel
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from pki.models.certificate import CertificateModel, RevokedCertificateModel
from pki.models.credential import CredentialModel
from pki.models.domain import DomainModel
from pki.models.issuing_ca import IssuingCaModel
from pyasn1.type.univ import ObjectIdentifier  # type: ignore[import-untyped]
from trustpoint_core import oid  # type: ignore[import-untyped]
from trustpoint_core.oid import SignatureSuite  # type: ignore[import-untyped]
from trustpoint_core.serializer import CertificateCollectionSerializer  # type: ignore[import-untyped]

from trustpoint.views.base import LoggerMixin


class ClientCertificateAuthenticationError(Exception):
    """Exception raised for client certificate authentication failures."""


class IDevIDAuthenticationError(Exception):
    """Exception raised for IDevID authentication failures."""


class UsernamePasswordAuthenticationError(Exception):
    """Exception raised for username and password authentication failures."""


class Dispatchable(Protocol):
    """Protocol defining a dispatch method for handling HTTP requests."""

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle the dispatching of an HTTP request."""
        ...


class LoggedHttpResponse(HttpResponse):
    """Custom HttpResponse that logs and prints error messages automatically."""

    def __init__(self, content='', status=None, *args, **kwargs):
        if status and status >= 400:
            print(f"HTTP {status} Response: {content}")
        super().__init__(content, status=status, *args, **kwargs)


@dataclass
class CredentialRequest:
    """Encapsulates the details extracted from a CSR."""
    common_name: str
    serial_number: str | None
    ipv4_addresses: list[ipaddress.IPv4Address]
    ipv6_addresses: list[ipaddress.IPv6Address]
    dns_names: list[str]
    public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey


class EstAuthenticationMixin:
    """Checks for HTTP Basic Authentication before processing the request."""

    def get_credential_for_certificate(self, cert: x509.Certificate) -> tuple[CredentialModel, DeviceModel]:
        """Retrieve a CredentialModel and associated DeviceModel instance for the given certificate.

        :param cert: x509.Certificate to search for.
        :return: Tuple containing CredentialModel and DeviceModel instances.
        :raises ClientCertificateAuthenticationError: if no matching credential is found.
        """
        cert_fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
        credential = CredentialModel.objects.filter(certificates__sha256_fingerprint=cert_fingerprint).first()
        if not credential:
            error_message = f'No credential found for certificate with fingerprint {cert_fingerprint}'
            raise ClientCertificateAuthenticationError(error_message)

        issued_credential = IssuedCredentialModel.objects.get(credential=credential)
        device = issued_credential.device

        return credential, device

    def authenticate_username_password(self, request: HttpRequest) -> DeviceModel:
        """Authenticate a user using HTTP Basic credentials and return associated DeviceModel.

        :param request: Django HttpRequest containing the headers.
        :return: Authenticated DeviceModel instance.
        :raises UsernamePasswordAuthenticationError: if authentication fails.
        """
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            raise UsernamePasswordAuthenticationError('Invalid auth header')

        try:
            decoded_credentials = base64.b64decode(auth_header.split(' ', 1)[1].strip()).decode('utf-8')
            username, password = decoded_credentials.split(':', 1)
        except Exception:
            raise UsernamePasswordAuthenticationError('Malformed authentication credentials')

        device = DeviceModel.objects.filter(est_password=password, unique_name=username).first()
        if not device:
            raise UsernamePasswordAuthenticationError('Invalid authentication credentials')

        return device

    def authenticate_domain_credential(self, request: HttpRequest) -> DeviceModel:
        """Authenticate the client using an SSL/TLS certificate (Mutual TLS) and return the associated DeviceModel."""
        print(request.META)
        cert_data = request.META.get('SSL_CLIENT_CERT')

        if not cert_data:
            raise ClientCertificateAuthenticationError('Missing SSL_CLIENT_CERT header')

        try:
            client_cert = x509.load_pem_x509_certificate(cert_data.encode('utf-8'), default_backend())
        except Exception as e:
            raise ClientCertificateAuthenticationError(f'Invalid SSL_CLIENT_CERT header: {e}')

        credential, device = self.get_credential_for_certificate(client_cert)
        is_valid, reason = credential.is_valid_domain_credential()
        if not is_valid:
            raise ClientCertificateAuthenticationError(f'Invalid SSL_CLIENT_CERT header: {reason}')

        return device

    def authenticate_idev_id(self) -> None:
        """Placeholder for IDevID authentication.

        :raises IDevIDAuthenticationError: Always, since IDevID authentication is not implemented.
        """
        error_message = 'IDevID authentication not implemented'
        raise IDevIDAuthenticationError(error_message)

    def authenticate_request(self, request: HttpRequest, domain: DomainModel, cert_template_str: str) -> tuple[
        DeviceModel | None, LoggedHttpResponse | None]:
        """Authenticate the request and return a DeviceModel if authentication succeeds."""
        if cert_template_str == 'domaincredential':
            device, http_response = self._authenticate_domain_credential_request(request, domain)
        else:
            device, http_response = self._authenticate_application_certificate_request(request, domain)

        if device is None and http_response is None:
            return None, LoggedHttpResponse("Authentication failed: No valid authentication method used", status=400)

        return device, http_response

    def _authenticate_domain_credential_request(self, request: HttpRequest, domain: DomainModel) -> tuple[
        DeviceModel | None, LoggedHttpResponse | None]:
        """Authenticate requests for 'domaincredential' certificates and return the associated DeviceModel."""
        if not (domain.allow_idevid_registration or domain.allow_username_password_registration):
            return None, LoggedHttpResponse('Both IDevID registration and username:password registration are disabled',
                                            status=400)

        if domain.allow_idevid_registration:
            try:
                self.authenticate_idev_id()
            except IDevIDAuthenticationError as e:
                return None, LoggedHttpResponse(f'Error validating the IDevID: {e!s}', status=400)

        if domain.allow_username_password_registration:
            try:
                device = self.authenticate_username_password(request)
                return device, None
            except UsernamePasswordAuthenticationError as e:
                return None, LoggedHttpResponse(f'Error validating the credentials: {e!s}', status=400)

        return None, None

    def _authenticate_application_certificate_request(self, request: HttpRequest, domain: DomainModel) -> tuple[
        DeviceModel | None, LoggedHttpResponse | None]:
        """Authenticate requests for application certificate templates and return the associated DeviceModel."""
        if not (domain.domain_credential_auth or domain.username_password_auth):
            return None, LoggedHttpResponse('Domain credential and username:password authentication are disabled',
                                            status=400)

        if domain.domain_credential_auth:
            try:
                device = self.authenticate_domain_credential(request)
                return device, None
            except ClientCertificateAuthenticationError as e:
                return None, LoggedHttpResponse(f'Error validating the client certificate: {e!s}', status=400)

        if domain.username_password_auth:
            try:
                device = self.authenticate_username_password(request)
                return device, None
            except UsernamePasswordAuthenticationError as e:
                return None, LoggedHttpResponse(f'Error validating the credentials: {e!s}', status=400)

        return None, None


class EstHttpMixin:
    """Mixin for processing HTTP requests for EST endpoints.

    This mixin reads the raw message from the request, verifies that the payload:
      - Does not exceed the maximum allowed size.
      - Contains the expected content type.
      - Is optionally decoded from base64 if required.

    Upon successful validation, the mixin delegates the request handling to the parent dispatch method.
    """
    expected_content_type = 'application/pkcs10'
    max_payload_size = 131072
    raw_message: bytes

    def _error_response(self, message: str, status: int) -> LoggedHttpResponse:
        """Helper method to generate an HTTP error response."""
        return LoggedHttpResponse(message, status=status)

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> LoggedHttpResponse:
        """Process the incoming HTTP request for EST enrollment.

        The method performs the following checks in order:
          1. Reads the raw request message and ensures it does not exceed the maximum allowed size.
          2. Verifies that the request contains a Content-Type header matching the expected type.
          3. If the request includes a 'Content-Transfer-Encoding' header set to 'base64',
             decodes the raw message from base64.
          4. Delegates the remaining request processing to the parent class's dispatch method.

        :param request: The incoming HttpRequest.
        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.
        :return: An LoggedHttpResponse, either an error response or the result of the parent dispatch.
        """
        self.raw_message = request.read()
        if len(self.raw_message) > self.max_payload_size:
            return self._error_response('Message is too large.', 413)

        content_type = request.headers.get('Content-Type')
        if content_type != self.expected_content_type:
            message = ('Message is missing the content type.'
                       if content_type is None
                       else f'Message does not have the expected content type: {self.expected_content_type}.')
            return self._error_response(message, 415)

        if request.headers.get('Content-Transfer-Encoding', '').lower() == 'base64':
            try:
                self.raw_message = base64.b64decode(self.raw_message)
            except Exception:  # noqa: BLE001
                return self._error_response('Invalid base64 encoding in message.', 400)

        parent = cast('Dispatchable', super())
        return parent.dispatch(request, *args, **kwargs)


class EstRequestedDomainExtractorMixin:
    """Mixin to extract the requested domain.

    This mixin sets:
      - self.requested_domain: The DomainModel instance based on the 'domain' parameter.
      - self.issuing_ca_certificate: The CA certificate for the requested domain.
      - self.signature_suite: The signature suite derived from the CA certificate.
    """

    requested_domain: DomainModel
    issuing_ca_certificate: x509.Certificate
    signature_suite: SignatureSuite

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> LoggedHttpResponse:
        """Extracts the requested domain and sets the relevant certificate and signature suite.

        :param request: The HTTP request object.
        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments, specifically the 'domain' parameter.

        :return: The response from the parent class's dispatch method.
        """
        domain_name = cast(str, kwargs.get('domain'))

        try:
            self.requested_domain = DomainModel.objects.get(unique_name=domain_name)
        except DomainModel.DoesNotExist:
            return LoggedHttpResponse('Domain does not exist.', status=404)

        self.issuing_ca_certificate = self.requested_domain.issuing_ca.credential.get_certificate()
        self.signature_suite = SignatureSuite.from_certificate(self.issuing_ca_certificate)

        return cast(Dispatchable, super()).dispatch(request, *args, **kwargs)


class EstRequestedCertTemplateExtractorMixin:
    """Mixin to extract and validate the certificate template from request parameters."""
    requested_cert_template_str: str
    allowed_cert_templates: ClassVar[list[str]] = ['tlsserver', 'tlsclient', 'domaincredential']

    cert_template_classes: ClassVar[dict[str, type[object]]] = {
        'tlsserver': LocalTlsServerCredentialIssuer,
        'tlsclient': LocalTlsClientCredentialIssuer,
        'domaincredential': LocalDomainCredentialIssuer,
    }

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> LoggedHttpResponse:
        """Extract and validate the 'certtemplate' parameter, then delegate request processing."""
        cert_template = kwargs.get('certtemplate')

        if cert_template not in self.allowed_cert_templates:
            allowed = ', '.join(self.allowed_cert_templates)
            return LoggedHttpResponse(
                f'Invalid or missing cert template. Allowed values are: {allowed}.',
                status=404
            )

        self.requested_cert_template_str = cert_template

        return cast(Dispatchable, super()).dispatch(request, *args, **kwargs)


class EstPkiMessageSerializerMixin:
    """Mixin to handle serialization and deserialization of PKCS#10 certificate signing requests"""

    def extract_details_from_csr(self,
                                 csr: x509.CertificateSigningRequest
                                 ) -> CredentialRequest:
        """Loads the CSR (x509.CertificateSigningRequest) and extracts subject and SAN"""
        subject_attributes = list(csr.subject)
        serial_number = self._extract_serial_number(subject_attributes)
        dns_names, ipv4_addresses, ipv6_addresses = self._extract_san(csr)
        public_key = csr.public_key()

        return CredentialRequest(
            common_name=common_name,
            serial_number=serial_number,
            ipv4_addresses=ipv4_addresses,
            ipv6_addresses=ipv6_addresses,
            dns_names=dns_names,
            public_key=public_key
        )

    def _extract_serial_number(self, subject_attributes: list[x509.NameAttribute]) -> str | None:
        print("Serial number start")
        serial_number_attrs = [attr for attr in subject_attributes if attr.oid == x509.NameOID.SERIAL_NUMBER]
        print("Serial number 1")

        if not serial_number_attrs:
            return None
        if len(serial_number_attrs) > 1:
            error_message = 'CSR subject must contain only one serial number attribute.'
            raise ValueError(error_message)

        serial_number = serial_number_attrs[0].value

        if isinstance(serial_number, bytes):
            serial_number = serial_number.decode('utf-8')

        return serial_number

    def _extract_common_name(self, subject_attributes: list[x509.NameAttribute]) -> str:
        """Extracts the common name from the subject attributes."""
        common_name_attrs = [attr for attr in subject_attributes if attr.oid == x509.NameOID.COMMON_NAME]
        if not common_name_attrs:
            error_message = 'CSR subject must contain a Common Name attribute.'
            raise ValueError(error_message)
        if len(common_name_attrs) > 1:
            error_message = 'CSR subject must contain only one Common Name attribute.'
            raise ValueError(error_message)

        common_name = common_name_attrs[0].value

        if isinstance(common_name, bytes):
            common_name = common_name.decode('utf-8')

        return common_name

    def _extract_san(self,
                     csr: x509.CertificateSigningRequest
                     ) -> tuple[
        list[str],
        list[ipaddress.IPv4Address],
        list[ipaddress.IPv6Address]
    ]:
        """Extract SAN (Subject Alternative Name) extension values."""
        try:
            san_extension = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            return [], [], []

        san = san_extension.value

        dns_names = san.get_values_for_type(x509.DNSName)
        ip_addresses = san.get_values_for_type(x509.IPAddress)
        ipv4_addresses = [ip for ip in ip_addresses if isinstance(ip, ipaddress.IPv4Address)]
        ipv6_addresses = [ip for ip in ip_addresses if isinstance(ip, ipaddress.IPv6Address)]

        return dns_names, ipv4_addresses, ipv6_addresses

    def deserialize_pki_message(self, data: bytes) -> tuple[CredentialRequest | None, LoggedHttpResponse | None]:
        """Deserializes a DER-encoded PKCS#10 certificate signing request

        :param data: DER-encoded PKCS#10 request bytes.
        :param requested_cert_template: Certificate template string.
        :return: An CredentialRequest object.
        :raises ValueError: If deserialization fails.
        """
        try:
            csr = x509.load_der_x509_csr(data, default_backend())
        except Exception as e:
            error_message = 'Failed to deserialize PKCS#10 certificate signing request'
            return None, LoggedHttpResponse(error_message, status=500)

        try:
            self.verify_csr_signature(csr)
        except Exception as e:
            error_message = 'Failed to verify PKCS#10 certificate signing request'
            return None, LoggedHttpResponse(error_message, status=500)

        try:
            cert_details = self.extract_details_from_csr(csr)
        except Exception as e:
            error_message = f'Failed to extract information from CSR: {e}'
            return None, LoggedHttpResponse(error_message, status=500)

        return cert_details, None


    def verify_csr_signature(self, csr: x509.CertificateSigningRequest) -> None:
        """Verifies that the CSR's signature is valid by using the public key contained in the CSR.

        Supports RSA, ECDSA, and DSA public keys.
        """
        public_key = csr.public_key()

        signature_hash_algorithm = csr.signature_hash_algorithm
        if signature_hash_algorithm is None:
            error_message = 'CSR signature hash algorithm is missing.'
            raise ValueError(error_message)

        if not isinstance(public_key, rsa.RSAPublicKey | ec.EllipticCurvePublicKey):
            error_message = 'Unsupported public key type for CSR signature verification.'
            raise TypeError(error_message)

        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature=csr.signature,
                    data=csr.tbs_certrequest_bytes,
                    padding=padding.PKCS1v15(),
                    algorithm=signature_hash_algorithm,
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature=csr.signature,
                    data=csr.tbs_certrequest_bytes,
                    signature_algorithm=ec.ECDSA(signature_hash_algorithm)
                )
        except Exception as e:
            error_message = 'CSR signature verification failed.'
            raise ValueError(error_message) from e


class DeviceHandlerMixin:
    """Extract the serial number from an X.509 CSR and retrieve or create a DeviceModel instance.

    This mixin assumes the CSR is already deserialized into a cryptography.x509.CertificateSigningRequest object.
    """

    def get_or_create_device_from_csr(self,
                                      credential_request: CredentialRequest,
                                      domain: DomainModel,
                                      cert_template: str,
                                      device: DeviceModel) -> tuple[DeviceModel | None, LoggedHttpResponse | None]:
        """Retrieves a DeviceModel instance using the serial number extracted from the provided CSR.

        If a device with that serial number does not exist, a new one is created.

        :param csr: A cryptography.x509.CertificateSigningRequest instance.
        :param domain: The DomainModel instance associated with this device.
        :param cert_template: The X509 Certificate Template to use for this device.
        :param device: The DeviceModel instance associated with this device.
        :return: A DeviceModel instance corresponding to the extracted serial number.
        """
        if device:
            return device, None

        if not domain.auto_create_new_device:
            error_message = 'Creating a new device for this domain is permitted'
            return None, LoggedHttpResponse(error_message, status=400)

        if cert_template == 'domaincredential':
            if domain.allow_username_password_registration:
                onboarding_protocol = DeviceModel.OnboardingProtocol.EST_PASSWORD
                onboarding_status = DeviceModel.OnboardingStatus.PENDING
            elif domain.allow_idevid_registration:
                error_message = 'IDevID registration is not supported implemented'
                return None, LoggedHttpResponse(error_message, status=400)
            else:
                error_message = 'For registering a new device activate Username:Password registration or IDevid registration'
                return None, LoggedHttpResponse(error_message, status=400)

        else:
            onboarding_protocol = DeviceModel.OnboardingProtocol.NO_ONBOARDING
            onboarding_status = DeviceModel.OnboardingStatus.NO_ONBOARDING

        serial_number = credential_request.serial_number

        return DeviceModel.objects.create(
            serial_number=serial_number,
            unique_name=f'Auto-Create-Device-{serial_number}',
            domain=domain,
            onboarding_protocol=onboarding_protocol,
            onboarding_status=onboarding_status,
        ), None


class CredentialIssuanceMixin:
    """Mixin to handle issuing credentials based on a given certificate template input.

    Required inputs for the `issue_credential` method:
      - cert_template_str: A string indicating the certificate template type.
          Supported values: 'tlsserver', 'tlsclient', or 'domaincredential'.
      - cert_template_class: The class responsible for issuing the credential.
      - device: The device instance for which the credential is issued.
      - domain: The domain instance used during credential issuance.
      - csr: The certificate signing request (used only for 'domaincredential').

    Additional parameters are used by the specific issuance methods:
      - common_name: Used for 'tlsclient' and 'tlsserver' credentials.
      - validity_days: Used for 'tlsclient' and 'tlsserver' credentials.
      - ipv4_addresses, ipv6_addresses, domain_names: Used for 'tlsserver' credentials.
    """

    cert_template_classes: ClassVar[dict[str, type]] = {
        'tlsserver': LocalTlsServerCredentialIssuer,
        'tlsclient': LocalTlsClientCredentialIssuer,
        'domaincredential': LocalDomainCredentialIssuer,
    }

    def _validate_subject_attributes(self,
                                     subject_attributes: list[x509.NameAttribute],
                                     allowed_subject_oids: set[ObjectIdentifier]) -> None:
        """Helper method to validate subject attributes."""
        for attr in subject_attributes:
            if attr.oid not in allowed_subject_oids:
                oid_name = getattr(attr.oid, 'name', None) or attr.oid.dotted_string
                error_message = f'Unsupported subject attribute: {oid_name}'
                raise ValueError(error_message)

    def issue_credential(self,
                         cert_template_str: str,
                         device: DeviceModel,
                         domain: DomainModel,
                         credential_request: CredentialRequest) -> IssuedCredentialModel | None:
        """Issues a credential based on the specified certificate template and CSR.

        This method handles the credential issuance process, which includes extracting
        the necessary details from the CSR and domain, and then issuing the requested
        certificate. The method supports both new certificate issuance and reenrollment.

        Args:
            cert_template_str (str): The certificate template string indicating the type
                                      of certificate to issue (e.g., 'tlsserver', 'tlsclient', etc.).
            device (DeviceModel): The device for which the certificate is being issued.
            domain (DomainModel): The domain associated with the certificate issuance.
            credential_request (CredentialRequest): A CredentialRequest object containing processed information
                about the CSR

        Returns:
            IssuedCredentialModel: The issued credential model that contains the issued certificate and related data.

        Raises:
            ValueError: If the certificate template is invalid or any other error occurs during issuance.
        """
        if cert_template_str not in self.cert_template_classes:
            error_message = f'Unknown certificate template type: {cert_template_str}'
            raise ValueError(error_message)

        return self._issue_based_on_template(cert_template_str=cert_template_str,
                                             credential_request=credential_request,
                                             device=device,
                                             domain=domain)

    def _issue_based_on_template(self,
                                 cert_template_str: str,
                                 credential_request: CredentialRequest,
                                 device: DeviceModel,
                                 domain: DomainModel) -> IssuedCredentialModel | None:
        """Issues the credential based on the selected template."""

        if cert_template_str == 'domaincredential':
            domain_credential = LocalDomainCredentialIssuer(device=device, domain=domain)
            return domain_credential.issue_domain_credential_certificate(
                public_key=credential_request.public_key
            )

        if cert_template_str == 'tlsclient':
            tls_client_credential = LocalTlsClientCredentialIssuer(device=device, domain=domain)

            return tls_client_credential.issue_tls_client_certificate(
                common_name=credential_request.common_name,
                public_key=credential_request.public_key,
                validity_days=365
            )
        if cert_template_str == 'tlsserver':
            tls_server_credential = LocalTlsServerCredentialIssuer(device=device, domain=domain)
            return tls_server_credential.issue_tls_server_certificate(
                common_name=credential_request.common_name,
                ipv4_addresses=credential_request.ipv4_addresses,
                ipv6_addresses=credential_request.ipv6_addresses,
                domain_names=credential_request.dns_names,
                san_critical=False,
                public_key=credential_request.public_key,
                validity_days=365
            )
        return None


@method_decorator(csrf_exempt, name='dispatch')
class EstSimpleEnrollmentView(EstAuthenticationMixin,
                              EstHttpMixin,
                              EstRequestedDomainExtractorMixin,
                              EstRequestedCertTemplateExtractorMixin,
                              EstPkiMessageSerializerMixin,
                              DeviceHandlerMixin,
                              CredentialIssuanceMixin,
                              LoggerMixin,
                              View):
    """Handles simple EST (Enrollment over Secure Transport) enrollment requests.

    This view processes certificate signing requests (CSRs), authenticates the client using
    either Mutual TLS or username/password, validates the device, and issues the requested certificate
    based on the certificate template specified in the request.
    """
    device: DeviceModel
    requested_domain: DomainModel
    requested_cert_template_str: str
    issued_credential: IssuedCredentialModel
    issuing_ca_certificate: x509.Certificate

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> LoggedHttpResponse:
        """Handle POST requests for simple enrollment."""
        del args, kwargs, request
        credential_request = None

        device, http_response = self.authenticate_request(
            request=self.request,
            domain=self.requested_domain,
            cert_template_str=self.requested_cert_template_str,
        )

        if not http_response:
            credential_request, http_response = self.deserialize_pki_message(self.raw_message)

        if not http_response and credential_request and device:
            self.get_or_create_device_from_csr(
                credential_request=credential_request,
                domain=self.requested_domain,
                cert_template=self.requested_cert_template_str,
                device=device
            )

        if not http_response and credential_request and device:
            http_response = self._validate_onboarding(device, credential_request)

        if not http_response and credential_request and device:
            http_response = self._issue_and_respond(device, credential_request)

        return http_response

    def _validate_onboarding(self,
                             device: DeviceModel,
                             credential_request: CredentialRequest) -> LoggedHttpResponse | None:
        """Validates if the device's onboarding status is appropriate for credential issuance."""

        try:
            issued_credential = IssuedCredentialModel.objects.get(device=device,
                                                                  common_name=credential_request.common_name)
        except IssuedCredentialModel.DoesNotExist as e:
            issued_credential = None

        if issued_credential:
            return LoggedHttpResponse('A device with the same CN already exists. '
                                      'Not allowed for method /simpleenroll', status=400)

        if self.requested_cert_template_str == 'domaincredential':
            if device.onboarding_status == DeviceModel.OnboardingStatus.ONBOARDED:
                return LoggedHttpResponse('The device is already onboarded.', status=400)
            if device.onboarding_status == DeviceModel.OnboardingStatus.NO_ONBOARDING:
                return LoggedHttpResponse('Requested domain credential for device which '
                                          'does not require onboarding.',
                                          status=400)
        return None

    def _issue_and_respond(self, device: DeviceModel, credential_request: CredentialRequest) -> LoggedHttpResponse:
        """Handles the credential issuance and raises an error if issuance fails."""
        try:
            issued_credential: IssuedCredentialModel | None = self.issue_credential(
                cert_template_str=self.requested_cert_template_str,
                device=device,
                domain=self.requested_domain,
                credential_request=credential_request
            )
        except ValueError as e:
            error_message = f'Error while issuing credential ({type(e).__name__}): {e!s}'
            return LoggedHttpResponse(error_message, status=400)
        except Exception as e:
            error_message = f'Error while issuing credential ({type(e).__name__}): {e!s}'
            return LoggedHttpResponse(error_message, status=400)

        if issued_credential is None:
            error_message = 'Credential cannot be found'
            return LoggedHttpResponse(error_message, 400)

        encoded_cert = issued_credential.credential.get_certificate().public_bytes(encoding=Encoding.DER)

        if self.requested_cert_template_str == 'domaincredential':
            device.onboarding_status = DeviceModel.OnboardingStatus.ONBOARDED
            device.save()

        return LoggedHttpResponse(encoded_cert, status=200, content_type='application/pkix-cert')



@method_decorator(csrf_exempt, name='dispatch')
class EstCACertsView(EstAuthenticationMixin, EstRequestedDomainExtractorMixin, View):
    """View to handle the EST /cacerts endpoint.

    Returns the CA certificate chain in a (simplified) PKCS#7 MIME format.

    URL pattern should supply the 'domain' parameter (e.g., /cacerts/<domain>/)
    """

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> LoggedHttpResponse:
        """Handle GET requests for the /cacerts endpoint.

        This method retrieves the CA certificate chain and returns it in PKCS#7 MIME format.
        """
        del request, args, kwargs

        try:
            ca_credential = self.requested_domain.issuing_ca.credential

            ca_cert = ca_credential.get_certificate()
            certificate_chain = [ca_cert, *ca_credential.get_certificate_chain()]
            pkcs7_certs = CertificateCollectionSerializer(certificate_chain).as_pkcs7_der()

            pkcs7_certs_b64 = base64.b64encode(pkcs7_certs)

            return LoggedHttpResponse(
                pkcs7_certs_b64,
                status=200,
                content_type='application/pkcs7-mime',
                headers={'Content-Transfer-Encoding': 'base64'}
            )
        except Exception as e:  # noqa:BLE001
            return LoggedHttpResponse(
                f'Error retrieving CA certificates: {e!s}', status=500
            )


@method_decorator(csrf_exempt, name='dispatch')
class EstSimpleReenrollmentView(EstAuthenticationMixin,
                                EstHttpMixin,
                                EstRequestedDomainExtractorMixin,
                                EstRequestedCertTemplateExtractorMixin,
                                EstPkiMessageSerializerMixin,
                                CredentialIssuanceMixin,
                                View):
    """EST Simple Reenrollment View (RFC 7030) supporting both client certificate and username:password authentication.

    This view allows an already enrolled client to request a new certificate (reenrollment) using one of two
    authentication methods:
      - **Mutual TLS (client certificate):** The client presents its existing certificate.
      - **Username:password:** The client provides credentials via HTTP Basic authentication.

    Processing steps:
      1. **Authentication:**
         Determines the authentication method based on the request headers and domain configuration.
         Validates the client using either:
           - Username:password authentication (if allowed and provided), or
           - Client certificate authentication (if allowed).
      2. **CSR Deserialization:**
         Deserializes and verifies the provided DER-encoded PKCS#10 CSR.
      3. **Device Verification:**
         Extracts the device serial number from the CSR and confirms that the device is already enrolled.
      4. **Credential Issuance:**
         Issues a new certificate based on the CSR.
      5. **Response:**
         Returns the new certificate in DER format with the content type "application/pkix-cert".
    """

    requested_domain: DomainModel
    requested_cert_template_str: str
    issued_credential: IssuedCredentialModel
    issuing_ca_certificate: x509.Certificate
    device: DeviceModel
    csr: x509.CertificateSigningRequest
    renewal_type: str

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> LoggedHttpResponse:
        """Handle POST requests for simple re-enrollment.

        This method processes the PKCS#10 CSR, authenticates the request, validates the device,
        and issues the requested certificate based on the certificate template.
        """
        del args, kwargs

        auth_response = self.authenticate_request(request=request,
                                                  domain=self.requested_domain,
                                                  cert_template_str=self.requested_cert_template_str)
        if auth_response:
            return auth_response

        try:
            self.csr = self.deserialize_pki_message(self.raw_message)
        except ValueError as e:
            return LoggedHttpResponse(f'Invalid PKCS#10 request: {e!s}', status=400)

        existing_certificate = self._retrieve_existing_certificate(self.csr)
        if isinstance(existing_certificate, LoggedHttpResponse):
            return existing_certificate

        self.renewal_type = self._determine_renewal_type(existing_certificate, self.csr)

        device = self._get_device_from_certificate(certificate=existing_certificate)

        if device is None:
            return LoggedHttpResponse('No associated device found for the certificate.', status=400)

        self.device = device

        self._revoke_existing_certificate(certificate=existing_certificate)

        if self.device is None:
            return LoggedHttpResponse('No associated device found for the certificate.', status=400)

        return self._handle_credential_issue()

    def _find_certificate_by_public_key(self, csr: x509.CertificateSigningRequest) -> CertificateModel | None:
        """Searches for an existing certificate in the database with the same public key as the CSR.

        :param csr: The Certificate Signing Request.
        :return: The matching CertificateModel instance or None.
        """
        public_key_pem = csr.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        if public_key_pem is None:
            return None

        certificate: CertificateModel = CertificateModel.objects.filter(public_key_pem=public_key_pem).first()

        if certificate is None:
            return None

        return certificate

    def _find_certificate_by_subject_and_san(self, csr: x509.CertificateSigningRequest) -> CertificateModel | None:
        """Searches for an existing certificate in the database with the same Subject and SAN as the CSR.

        :param csr: The Certificate Signing Request.
        :return: The matching CertificateModel instance or None.
        """
        csr_subject = csr.subject.public_bytes(serialization.Encoding.DER).hex().upper()

        # Extract SAN from CSR
        try:
            csr_san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            dns_names: set[str] = set(csr_san_ext.get_values_for_type(x509.DNSName))
            ip_addresses: set[str] = {str(ip) for ip in csr_san_ext.get_values_for_type(x509.IPAddress)}
            csr_san_list: set[str] = dns_names | ip_addresses
        except x509.ExtensionNotFound:
            csr_san_list = set()

        matching_certs = CertificateModel.objects.filter(subject_public_bytes=csr_subject)
        matched_cert: CertificateModel | None = matching_certs.first()

        if matched_cert is None:
            return None

        # Further filter by SAN
        try:
            cert_san_ext = matched_cert.subject_alternative_name_extension
            if cert_san_ext:
                cert_san_list_from_cert = set(cert_san_ext.get_values_for_type(x509.DNSName)) | {
                    str(ip) for ip in cert_san_ext.get_values_for_type(x509.IPAddress)
                }
                if csr_san_list == cert_san_list_from_cert:
                    return matched_cert
        except AttributeError:
            if not csr_san_list:
                return matched_cert

        return None

    def _revoke_existing_certificate(self, certificate: CertificateModel) -> None:
        """Revokes the existing certificate.

        :param certificate: The CertificateModel instance to be revoked.
        """
        credential = CredentialModel.objects.filter(primarycredentialcertificate__certificate=certificate).first()

        if credential and credential.credential_type == CredentialModel.CredentialTypeChoice.ISSUING_CA:
            issuing_ca_model = IssuingCaModel.objects.filter(credential=credential).first()

            if not issuing_ca_model:
                error_message = f'Could not determine issuing CA for certificate {certificate.common_name}.'
                raise ValueError(error_message)

            RevokedCertificateModel.objects.create(
                certificate=certificate,
                revocation_reason=RevokedCertificateModel.ReasonCode.SUPERSEDED,
                ca=issuing_ca_model,
                revoked_at=datetime.datetime.now(datetime.UTC)
            )

            issuing_ca_model.issue_crl()
        else:
            error_message = f'Certificate {certificate.common_name} is not issued by a known Issuing CA.'
            raise ValidationError(error_message)

    def _get_device_from_certificate(self, certificate: CertificateModel) -> DeviceModel | None:
        """Retrieves the device associated with the given certificate.

        :param certificate: The CertificateModel instance.
        :return: DeviceModel instance if found, else None.
        """
        try:
            credential: CredentialModel = (
                CredentialModel.objects.filter(
                    primarycredentialcertificate__certificate=certificate,
                    primarycredentialcertificate__is_primary=True
                )
                .select_related('issuedcredential')
                .first()
            )

            if credential is None:
                return None

            issued_credential: IssuedCredentialModel | None = IssuedCredentialModel.objects.filter(
                credential=credential
            ).first()

            if not issued_credential:
                return None

            device: DeviceModel | None = issued_credential.device

        except Exception:  # noqa: BLE001
            return None
        else:
            return device

    def _determine_renewal_type(self, existing_certificate: CertificateModel,
                                csr: x509.CertificateSigningRequest) -> str:
        """Determines whether the request is for renewal (same key) or rekey (new key)."""
        is_renewal = existing_certificate.public_key_pem == csr.public_key().public_bytes(
            serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        return 'Renewal (same public key)' if is_renewal else 'Rekey (new public key)'

    def _retrieve_existing_certificate(self,
                                       csr: x509.CertificateSigningRequest) -> CertificateModel | LoggedHttpResponse:
        """Finds an existing certificate matching the CSR."""
        existing_certificate = self._find_certificate_by_public_key(csr)

        if not existing_certificate:
            existing_certificate = self._find_certificate_by_subject_and_san(csr)

        if not existing_certificate:
            return LoggedHttpResponse('No existing certificate found matching the CSR.', status=400)

        if existing_certificate.certificate_status in [
            CertificateModel.CertificateStatus.REVOKED,
            CertificateModel.CertificateStatus.EXPIRED
        ]:
            return LoggedHttpResponse(f'Cannot reenroll: Certificate is {existing_certificate.certificate_status}.',
                                      status=400)

        return existing_certificate

    def _handle_credential_issue(self) -> LoggedHttpResponse:
        """Handles credential issuance and raises an error if issuance fails."""
        allowed_subject_oids = {
            x509.NameOID.COMMON_NAME.dotted_string,
            x509.NameOID.SERIAL_NUMBER.dotted_string
        }
        self._validate_subject_attributes(list(self.csr.subject), allowed_subject_oids)

        issued_credential = self.issue_credential(
            cert_template_str=self.requested_cert_template_str,
            device=self.device,
            domain=self.requested_domain,
            csr=self.csr
        )

        if issued_credential is None:
            return LoggedHttpResponse('Error: Credential not found', status=400)

        encoded_cert = issued_credential.credential.get_certificate().public_bytes(Encoding.DER)
        return LoggedHttpResponse(
            encoded_cert,
            status=200,
            content_type='application/pkix-cert',
            headers={'X-EST-Renewal-Type': self.renewal_type}
        )
