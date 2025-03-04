import base64
import ipaddress
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Protocol, cast, Any, Optional, Type

from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives.serialization import pkcs7
from django.core.exceptions import ValidationError

from core.oid import AlgorithmIdentifier, HashAlgorithm, HmacAlgorithm, SignatureSuite

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, padding
from django.contrib.auth import authenticate
from django.http import HttpRequest, HttpResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from core.serializer import CertificateCollectionSerializer
from devices.issuer import LocalDomainCredentialIssuer, LocalTlsServerCredentialIssuer, LocalTlsClientCredentialIssuer
from devices.models import TrustpointClientOnboardingProcessModel, DeviceModel, IssuedCredentialModel
from pki.models import DomainModel, CertificateModel, CredentialModel

if TYPE_CHECKING:
    from django.http import HttpRequest
    from typing import Any

class ClientCertificateAuthenticationError(Exception):
    pass

class IDevIDAuthenticationError(Exception):
    pass

class UsernamePasswordAuthenticationError(Exception):
    pass


class Dispatchable(Protocol):
    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        ...


class EstAuthenticationMixin:
    """
    Checks for HTTP Basic Authentication before processing the request.
    """

    def get_credential_for_certificate(self, cert: x509.Certificate) -> "CredentialModel":
        """Retrieve a CredentialModel instance associated with the given certificate.

        :param cert: x509.Certificate to search for.
        :return: Matching CredentialModel instance.
        :raises ClientCertificateAuthenticationError: if no matching credential is found.
        """
        cert_fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
        credential = CredentialModel.objects.filter(certificates__sha256_fingerprint=cert_fingerprint).first()
        if not credential:
            raise ClientCertificateAuthenticationError(
                f"No credential found for certificate with fingerprint {cert_fingerprint}"
            )
        return credential

    def authenticate_username_password(self, request: HttpRequest) -> None:
        """Authenticate a user using HTTP Basic credentials provided in the request headers.

        The credentials must be provided in the format:
            Authorization: Basic base64(username:password)

        :param request: Django HttpRequest containing the headers.
        :raises UsernamePasswordAuthenticationError: if authentication fails due to missing,
            invalid, or malformed credentials.
        """
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            raise UsernamePasswordAuthenticationError('Authentication required')

        try:
            decoded_credentials = base64.b64decode(auth_header.split(" ", 1)[1].strip()).decode("utf-8")
            username, password = decoded_credentials.split(":", 1)
        except Exception:
            raise UsernamePasswordAuthenticationError("Malformed authentication credentials")

        if not authenticate(request, username=username, password=password):
            raise UsernamePasswordAuthenticationError("Invalid credentials")

    def authenticate_idev_id(self) -> None:
        """Placeholder for IDevID authentication.

        :raises IDevIDAuthenticationError: Always, since IDevID authentication is not implemented.
        """
        raise IDevIDAuthenticationError('IDevID Registration is not implemented')

    def authenticate_domain_credential(self, request: HttpRequest) -> None:
        """Authenticate the client using an SSL/TLS certificate (Mutual TLS)."""
        cert_data = request.META.get('SSL_CLIENT_CERT')

        if not cert_data:
            raise ClientCertificateAuthenticationError("No client certificate provided")

        try:
            client_cert = x509.load_pem_x509_certificate(cert_data.encode('utf-8'), default_backend())
        except Exception as e:
            raise ClientCertificateAuthenticationError(f'Failed to load client certificate: {e}')

        credential = self.get_credential_for_certificate(client_cert)
        is_valid, reason = credential.is_valid_domain_credential()
        if not is_valid:
            raise ClientCertificateAuthenticationError(f"Invalid domain credential: {reason}")


    def authenticate_request(self, request: HttpRequest, domain: DomainModel, cert_template_str: str, issuing_ca_certificate: x509.Certificate) -> Optional[HttpResponse]:
        """
        Helper method to authenticate the request based on the requested certificate template.
        Returns an HttpResponse if an error occurs; otherwise, returns None.
        """
        if cert_template_str == 'domaincredential':
            # Check that at least one registration method is enabled.
            if not (domain.allow_idevid_registration or
                    domain.allow_username_password_registration):
                return HttpResponse(
                    'Both IDevID registration and username:password registration are disabled',
                    status=400
                )
            # Try IDevID authentication if enabled.
            if domain.allow_idevid_registration:
                try:
                    self.authenticate_idev_id()
                except IDevIDAuthenticationError as e:
                    return HttpResponse(f'Error validating the IDevID: {str(e)}', status=400)
            # Try username:password authentication if enabled.
            if domain.allow_username_password_registration:
                try:
                    self.authenticate_username_password(request=request)
                except UsernamePasswordAuthenticationError as e:
                    return HttpResponse(f'Error validating the credentials: {str(e)}', status=400)
        else:
            # For non-domaincredential requests, check that at least one authentication method is enabled.
            if not (domain.domain_credential_auth or
                    domain.username_password_auth):
                return HttpResponse(
                    'Domain credential and username:password authentication are disabled',
                    status=400
                )
            # Try domain credential (client certificate) authentication if enabled.
            print(domain.domain_credential_auth)
            print(domain.unique_name)
            if domain.domain_credential_auth:
                try:
                    self.authenticate_domain_credential(
                        request=request,
                    )
                except ClientCertificateAuthenticationError as e:
                    return HttpResponse(f"Error validating the client certificate: {str(e)}", status=400)
            # Try username:password authentication if enabled.
            if domain.username_password_auth:
                try:
                    self.authenticate_username_password(request=request)
                except UsernamePasswordAuthenticationError as e:
                    return HttpResponse(f"Error validating the credentials: {str(e)}", status=400)
        return None


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

    def _error_response(self, message: str, status: int) -> HttpResponse:
        """Helper method to generate an HTTP error response."""
        return HttpResponse(message, status=status)

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Process the incoming HTTP request for EST enrollment.

        The method performs the following checks in order:
          1. Reads the raw request message and ensures it does not exceed the maximum allowed size.
          2. Verifies that the request contains a Content-Type header matching the expected type.
          3. If the request includes a 'Content-Transfer-Encoding' header set to 'base64',
             decodes the raw message from base64.
          4. Delegates the remaining request processing to the parent class's dispatch method.

        :param request: The incoming HttpRequest.
        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.
        :return: An HttpResponse, either an error response or the result of the parent dispatch.
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

        print(self.raw_message.hex())

        if request.headers.get('Content-Transfer-Encoding', '').lower() == 'base64':
            try:
                self.raw_message = base64.b64decode(self.raw_message)
            except Exception:
                return self._error_response('Invalid base64 encoding in message.', 400)

        parent = cast("Dispatchable", super())
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

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        domain_name = cast(str, kwargs.get('domain'))

        try:
            self.requested_domain = DomainModel.objects.get(unique_name=domain_name)
        except DomainModel.DoesNotExist:
            return HttpResponse('Domain does not exist.', status=404)

        self.issuing_ca_certificate = self.requested_domain.issuing_ca.credential.get_certificate()
        self.signature_suite = SignatureSuite.from_certificate(self.issuing_ca_certificate)

        return cast(Dispatchable, super()).dispatch(request, *args, **kwargs)


class EstRequestedCertTemplateExtractorMixin:
    """Mixin to extract and validate the certificate template from request parameters."""
    requested_cert_template_str: str
    allowed_cert_templates = ['tlsserver', 'tlsclient', 'domaincredential']

    cert_template_classes: dict[str, Type] = {
        'tlsserver': LocalTlsServerCredentialIssuer,
        'tlsclient': LocalTlsClientCredentialIssuer,
        'domaincredential': LocalDomainCredentialIssuer,
    }
    requested_cert_template_class: LocalTlsServerCredentialIssuer | LocalTlsClientCredentialIssuer | LocalDomainCredentialIssuer

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Extract and validate the 'certtemplate' parameter, then delegate request processing."""
        cert_template = kwargs.get('certtemplate')

        if cert_template not in self.allowed_cert_templates:
            allowed = ', '.join(self.allowed_cert_templates)
            return HttpResponse(
                f'Invalid or missing cert template. Allowed values are: {allowed}.',
                status=404
            )

        self.requested_cert_template_str = cert_template
        self.requested_cert_template_class = self.cert_template_classes[cert_template]

        return cast(Dispatchable, super()).dispatch(request, *args, **kwargs)


class EstPkiMessageSerializerMixin:
    """
    Mixin to handle serialization and deserialization of PKCS#10 certificate signing requests,
    and to generate a DER-encoded certificate response.
    """

    def deserialize_pki_message(self, data: bytes) -> x509.CertificateSigningRequest:
        """
        Deserializes a DER-encoded PKCS#10 certificate signing request into a
        cryptography.x509.CertificateSigningRequest object.

        :param data: DER-encoded PKCS#10 request bytes.
        :return: An x509.CertificateSigningRequest object.
        :raises ValueError: If deserialization fails.
        """
        try:
            csr = x509.load_der_x509_csr(data, default_backend())
        except Exception as e:
            raise ValueError("Failed to deserialize PKCS#10 certificate signing request") from e

        self.verify_csr_signature(csr)
        return csr

    def verify_csr_signature(self, csr: x509.CertificateSigningRequest) -> None:
        """
        Verifies that the CSR's signature is valid by using the public key contained in the CSR.
        Supports RSA, ECDSA, and DSA public keys.
        """
        public_key = csr.public_key()
        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature=csr.signature,
                    data=csr.tbs_certrequest_bytes,
                    padding=padding.PKCS1v15(),
                    algorithm=csr.signature_hash_algorithm,
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature=csr.signature,
                    data=csr.tbs_certrequest_bytes,
                    signature_algorithm=ec.ECDSA(csr.signature_hash_algorithm)
                )
            elif isinstance(public_key, dsa.DSAPublicKey):
                public_key.verify(
                    signature=csr.signature,
                    data=csr.tbs_certrequest_bytes,
                    algorithm=csr.signature_hash_algorithm
                )
            else:
                raise ValueError("Unsupported public key type for CSR signature verification.")
        except Exception as e:
            raise ValueError("CSR signature verification failed.") from e

class DeviceHandlerMixin:
    """
    Mixin that provides functionality to extract the serial number from an X.509 CSR
    and to retrieve or create a DeviceModel instance based on that serial number.

    This mixin assumes the CSR is already deserialized into a cryptography.x509.CertificateSigningRequest object.
    """

    def extract_serial_number_from_csr(self, csr) -> str:
        """
        Extracts the serial number from the provided CSR's subject.

        Looks for the attribute with OID NameOID.SERIAL_NUMBER.

        :param csr: A cryptography.x509.CertificateSigningRequest instance.
        :return: The serial number as a string.
        :raises ValidationError: If the serial number attribute is not found.
        """
        attributes = csr.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
        if not attributes:
            raise ValidationError("Serial number not found in CSR subject.")
        return attributes[0].value

    def get_or_create_device_from_csr(self, csr, domain, cert_template) -> DeviceModel:
        """
        Retrieves a DeviceModel instance using the serial number extracted from the provided CSR.
        If a device with that serial number does not exist, a new one is created.

        :param csr: A cryptography.x509.CertificateSigningRequest instance.
        :param domain: The DomainModel instance associated with this device.
        :return: A DeviceModel instance corresponding to the extracted serial number.
        """
        serial_number = self.extract_serial_number_from_csr(csr)

        device = DeviceModel.objects.filter(serial_number=serial_number, domain=domain).first()
        if device:
            return device

        if not domain.auto_create_new_device:
            ValueError('Creating a new device for this domain is permitted')

        if domain.allow_username_password_registration:
            ValueError('Not implemented')

        if cert_template == 'domaincredential':
            onboarding_protocol = DeviceModel.OnboardingProtocol.CLI
            onboarding_status = DeviceModel.OnboardingStatus.PENDING
        else:
            onboarding_protocol = DeviceModel.OnboardingProtocol.NO_ONBOARDING
            onboarding_status = DeviceModel.OnboardingStatus.NO_ONBOARDING

        device = DeviceModel.objects.create(
            serial_number=serial_number,
            unique_name=f"Device-{serial_number}",
            domain=domain,
            onboarding_protocol=onboarding_protocol,
            onboarding_status=onboarding_status,
        )
        return device


class CredentialIssuanceMixin:
    """
    Mixin to handle issuing credentials based on a given certificate template input.

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

    cert_template_classes: dict[str, Type] = {
        'tlsserver': LocalTlsServerCredentialIssuer,
        'tlsclient': LocalTlsClientCredentialIssuer,
        'domaincredential': LocalDomainCredentialIssuer,
    }

    def extract_details_from_csr(self, csr: x509.CertificateSigningRequest, reenrollment: bool = False) -> str:
        """
        Loads the CSR (x509.CertificateSigningRequest) and extracts the common name,
        IPv4 addresses, IPv6 addresses, DNS names, and public key.
        """
        allowed_subject_oids = {x509.NameOID.COMMON_NAME, x509.NameOID.SERIAL_NUMBER}
        subject_attributes = list(csr.subject)
        if not reenrollment:
            for attr in subject_attributes:
                if attr.oid not in allowed_subject_oids:
                    raise ValueError(
                        f"Unsupported subject attribute: {attr.oid._name if hasattr(attr.oid, '_name') else attr.oid.dotted_string}"
                    )

        common_name_attrs = [attr for attr in subject_attributes if attr.oid == x509.NameOID.COMMON_NAME]
        if not common_name_attrs:
            raise ValueError("CSR subject must contain a Common Name attribute.")
        if len(common_name_attrs) > 1:
            raise ValueError("CSR subject must contain only one Common Name attribute.")
        common_name = common_name_attrs[0].value

        try:
            san_extension = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = san_extension.value

            for entry in san:
                if not isinstance(entry, (x509.DNSName, x509.IPAddress)):
                    raise ValueError(f"Unsupported SAN type: {type(entry).__name__}")

            dns_names = san.get_values_for_type(x509.DNSName)
            ip_addresses = san.get_values_for_type(x509.IPAddress)
            ipv4_addresses = []
            ipv6_addresses = []
            for ip in ip_addresses:
                if isinstance(ip, ipaddress.IPv4Address):
                    ipv4_addresses.append(ip)
                elif isinstance(ip, ipaddress.IPv6Address):
                    ipv6_addresses.append(ip)
        except x509.ExtensionNotFound:
            dns_names = []
            ipv4_addresses = []
            ipv6_addresses = []

        public_key = csr.public_key()

        return common_name, ipv4_addresses, ipv6_addresses, dns_names, public_key

    def issue_credential(
            self,
            cert_template_str: str,
            device: DeviceModel,
            domain: DomainModel,
            csr: x509.CertificateSigningRequest,
            validity_days: int = 365,
            reenrollment: bool = False
    ):

        common_name, ipv4_addresses, ipv6_addresses, dns_names, public_key = self.extract_details_from_csr(csr, reenrollment=reenrollment)

        cert_template_class = self.cert_template_classes[cert_template_str]
        issuer_instance = cert_template_class(device=device, domain=domain)

        # Call the appropriate issuance method based on the certificate template.
        if cert_template_str == 'domaincredential':

            if common_name != 'Trustpoint Domain Credential':
                raise ValueError('Domain Credentials must use the Common Name >Trustpoint Domain Credential<')
            issued_credential = issuer_instance.issue_domain_credential(public_key=public_key)

        elif cert_template_str == 'tlsclient':
            issued_credential = issuer_instance.issue_tls_client_credential(
                common_name=common_name,
                validity_days=validity_days
            )

        elif cert_template_str == 'tlsserver':
            issued_credential = issuer_instance.issue_tls_server_credential(
                common_name=common_name,
                ipv4_addresses=ipv4_addresses,
                ipv6_addresses=ipv6_addresses,
                domain_names=dns_names,
                validity_days=validity_days
            )
        else:
            raise ValueError(f"Unsupported certificate template: {cert_template_str}")

        return issued_credential


@method_decorator(csrf_exempt, name='dispatch')
class EstSimpleEnrollmentView(EstAuthenticationMixin,
                              EstHttpMixin,
                              EstRequestedDomainExtractorMixin,
                              EstRequestedCertTemplateExtractorMixin,
                              EstPkiMessageSerializerMixin,
                              DeviceHandlerMixin,
                              CredentialIssuanceMixin,
                              View):
    onboarding_process: None | TrustpointClientOnboardingProcessModel
    device: DeviceModel
    requested_domain: DomainModel
    requested_cert_template_str: str
    issued_credential: IssuedCredentialModel
    issuing_ca_certificate: x509.Certificate


    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle POST requests for simple enrollment.

        :param request: The HttpRequest object containing enrollment data.
        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments (e.g., domain and certtemplate parameters).
        :return: An HttpResponse with the issued certificate (content type "application/pkix-cert") if successful,
                 or an HttpResponse with an error message.
        """

        auth_response = self.authenticate_request(request=request,
                                                  domain=self.requested_domain,
                                                  cert_template_str=self.requested_cert_template_str,
                                                  issuing_ca_certificate=self.issuing_ca_certificate)
        if auth_response:
            return auth_response

        try:
            csr = self.deserialize_pki_message(self.raw_message)
        except ValueError as e:
            return HttpResponse(f"Invalid PKCS#10 request: {str(e)}", status=400)

        try:
            device = self.get_or_create_device_from_csr(csr, self.requested_domain, self.requested_cert_template_str)
        except Exception as e:
            return HttpResponse(f'Device lookup/creation error: {str(e)}', status=400)


        if self.requested_cert_template_str == 'domaincredential':
            if device.onboarding_status == DeviceModel.OnboardingStatus.ONBOARDED:
                return HttpResponse(f'The device is already onboarded.', status=400)
            if device.onboarding_status == DeviceModel.OnboardingStatus.NO_ONBOARDING:
                return HttpResponse(f'Requested domain credential for device which does not require onboarding.', status=400)

        try:
            issued_credential = self.issue_credential(cert_template_str=self.requested_cert_template_str,
            device=device,
            domain=self.requested_domain,
            csr=csr)

            encoded_cert = issued_credential.credential.get_certificate().public_bytes(
                encoding=Encoding.DER)

        except Exception as e:
            return HttpResponse(f'Error while issuing credential: {str(e)}', status=400)

        if self.requested_cert_template_str == 'domaincredential':
            device.onboarding_status = DeviceModel.OnboardingStatus.ONBOARDED
            device.save()

        return HttpResponse(encoded_cert, status=200, content_type="application/pkix-cert")


@method_decorator(csrf_exempt, name="dispatch")
class EstCACertsView(EstAuthenticationMixin, EstRequestedDomainExtractorMixin, View):
    """
    View to handle the EST /cacerts endpoint.
    Returns the CA certificate chain in a (simplified) PKCS#7 MIME format.

    URL pattern should supply the 'domain' parameter (e.g., /cacerts/<domain>/)
    """

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        try:
            ca_credential = self.requested_domain.issuing_ca.credential

            ca_cert = ca_credential.get_certificate()
            certificate_chain = [ca_cert] + ca_credential.get_certificate_chain()

            pkcs7_certs = CertificateCollectionSerializer(certificate_chain).as_pkcs7_der()

            pkcs7_certs_b64 = base64.b64encode(pkcs7_certs)

            return HttpResponse(
                pkcs7_certs_b64,
                status=200,
                content_type="application/pkcs7-mime",
                headers={"Content-Transfer-Encoding": "base64"}
            )
        except Exception as e:
            print(e)
            return HttpResponse(
                f"Error retrieving CA certificates: {str(e)}", status=500
            )

@method_decorator(csrf_exempt, name='dispatch')
class EstSimpleReenrollmentView(EstAuthenticationMixin,
                                EstHttpMixin,
                                EstRequestedDomainExtractorMixin,
                                EstRequestedCertTemplateExtractorMixin,
                                EstPkiMessageSerializerMixin,
                                CredentialIssuanceMixin,
                                View):
    """
    EST Simple Reenrollment View (RFC 7030) supporting both client certificate and username:password authentication.

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

    def _find_certificate_by_public_key(self, csr: x509.CertificateSigningRequest) -> Optional[CertificateModel]:
        """
        Searches for an existing certificate in the database with the same public key as the CSR.

        :param csr: The Certificate Signing Request.
        :return: The matching CertificateModel instance or None.
        """
        public_key_pem = csr.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        return CertificateModel.objects.filter(public_key_pem=public_key_pem).first()

    def _find_certificate_by_subject_and_san(self, csr: x509.CertificateSigningRequest) -> Optional[CertificateModel]:
        """
        Searches for an existing certificate in the database with the same Subject and SAN as the CSR.

        :param csr: The Certificate Signing Request.
        :return: The matching CertificateModel instance or None.
        """

        print(csr)
        print(type(csr))
        print(csr.subject)
        csr_subject = csr.subject.public_bytes(serialization.Encoding.PEM)
        csr_subject = csr.subject.public_bytes(serialization.Encoding.DER).hex().upper()

        # Extract SAN from CSR
        try:
            csr_san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            csr_san_list = set(csr_san_ext.get_values_for_type(x509.DNSName) +
                               csr_san_ext.get_values_for_type(x509.IPAddress))
        except x509.ExtensionNotFound:
            csr_san_list = set()

        # Check certificates with matching subject
        matching_certs = CertificateModel.objects.filter(subject_public_bytes=csr_subject)

        # Further filter by SAN
        for cert in matching_certs:
            try:
                cert_san_ext = cert.subject_alternative_name_extension
                if cert_san_ext:
                    cert_san_list = set(cert_san_ext.get_values_for_type(x509.DNSName) +
                                        cert_san_ext.get_values_for_type(x509.IPAddress))
                    if csr_san_list == cert_san_list:
                        return cert
            except AttributeError:
                if not csr_san_list:  # If neither have SAN, it's a match
                    return cert

        return None

    def _revoke_existing_certificate(self, certificate: CertificateModel) -> None:
        """Revokes the existing certificate.

        :param certificate: The CertificateModel instance to be revoked.
        """
        certificate.set_status(CertificateModel.CertificateStatus.REVOKED)

    def _get_device_from_certificate(self, certificate: CertificateModel) -> Optional[DeviceModel]:
        """Retrieves the device associated with the given certificate.

        :param certificate: The CertificateModel instance.
        :return: DeviceModel instance if found, else None.
        """
        try:
            credential = CredentialModel.objects.filter(
                primarycredentialcertificate__certificate=certificate,
                primarycredentialcertificate__is_primary=True
            ).first()

            if not credential:
                return None

            issued_credential = IssuedCredentialModel.objects.filter(credential=credential).first()

            return issued_credential.device if issued_credential else None

        except Exception as e:
            return None

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:

        auth_response = self.authenticate_request(request=request,
                                                  domain=self.requested_domain,
                                                  cert_template_str=self.requested_cert_template_str,
                                                  issuing_ca_certificate=self.issuing_ca_certificate)
        if auth_response:
            return auth_response

        try:
            csr = self.deserialize_pki_message(self.raw_message)
        except ValueError as e:
            return HttpResponse(f"Invalid PKCS#10 request: {str(e)}", status=400)

        existing_certificate_model = self._find_certificate_by_public_key(csr)

        if not existing_certificate_model:
            existing_certificate_model = self._find_certificate_by_subject_and_san(csr)

        if not existing_certificate_model:
            return HttpResponse("No existing certificate found matching the CSR.", status=400)

        if existing_certificate_model.certificate_status in [CertificateModel.CertificateStatus.REVOKED,
                                                             CertificateModel.CertificateStatus.EXPIRED]:
            return HttpResponse(f"Cannot reenroll: Certificate is {existing_certificate_model.certificate_status}.",
                                status=400)

        is_renewal = existing_certificate_model.public_key_pem == csr.public_key().public_bytes(
            serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        renewal_type = "Renewal (same public key)" if is_renewal else "Rekey (new public key)"

        self._revoke_existing_certificate(certificate=existing_certificate_model)

        device = self._get_device_from_certificate(certificate=existing_certificate_model)

        try:
            issued_credential = self.issue_credential(
                cert_template_str=self.requested_cert_template_str,
                device=device,
                domain=self.requested_domain,
                csr=csr,
                reenrollment=True
            )

            encoded_cert = issued_credential.credential.get_certificate().public_bytes(Encoding.DER)

        except Exception as e:
            return HttpResponse(f"Error while issuing credential: {str(e)}", status=400)

        return HttpResponse(
            encoded_cert,
            status=200,
            content_type="application/pkix-cert",
            headers={"X-EST-Renewal-Type": renewal_type}
        )
