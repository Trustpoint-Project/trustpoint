"""Provides the `EstAuthentication` class using the Composite pattern for modular EST authentication."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from cryptography import x509
from devices.models import DeviceModel, IssuedCredentialModel
from pki.util.idevid import IDevIDAuthenticationError, IDevIDAuthenticator

from request.request_context import RequestContext

if TYPE_CHECKING:
    from pki.models import CredentialModel



class AuthenticationComponent(ABC):
    """Abstract base class for authentication components."""

    @abstractmethod
    def authenticate(self, context: RequestContext) -> DeviceModel | None:
        """Authenticate a request using specific logic."""


class UsernamePasswordAuthentication(AuthenticationComponent):
    """Handles authentication via username/password credentials."""

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate using username and password from the context."""
        if context.est_username is not None and context.est_password is not None:
            username = context.est_username
            password = context.est_password
            device = DeviceModel.objects.filter(est_password=password, common_name=username).first()

            if not device:
                error_message = 'Authentication failed: Invalid username or password.'
                raise ValueError(error_message)

            context.device = device

class ClientCertificateAuthentication(AuthenticationComponent):
    """Handles authentication via client certificates."""

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate using the client certificate from the context."""
        if context.client_certificate is not None:
            client_certificate = context.client_certificate
            try:
                issued_credential = IssuedCredentialModel.get_credential_for_certificate(client_certificate)
            except IssuedCredentialModel.DoesNotExist as e:
                raise ValueError from e
            is_valid, reason = issued_credential.is_valid_domain_credential()
            if not is_valid:
                error_message = f'Invalid SSL_CLIENT_CERT header: {reason}'
                raise ValueError(error_message)

            context.device = issued_credential.device


class ReenrollmentAuthentication(AuthenticationComponent):
    """Handles authentication for EST reenrollment using an Application Credential."""

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate the client for reenrollment."""
        client_cert = context.client_certificate
        if not client_cert:
            error_message = 'Client certificate is missing in the context.'
            raise ValueError(error_message)

        csr = context.cert_requested
        if not csr:
            error_message = 'CSR is missing in the context.'
            raise ValueError(error_message)

        # Get the issued credential corresponding to the client certificate
        try:
            issued_credential = IssuedCredentialModel.get_credential_for_certificate(client_cert)
        except IssuedCredentialModel.DoesNotExist as e:
            error_message = 'Issued credential not found for client certificate.'
            raise ValueError(error_message) from e

        credential_model: CredentialModel = issued_credential.credential

        # Verify the issued credential's validity
        is_valid, reason = credential_model.is_valid_issued_credential()
        if not is_valid:
            error_message = f'Invalid client certificate: {reason}'
            raise ValueError(error_message)


        # Verify that the client certificate and CSR subjects match the existing issued credential
        if (
            not credential_model.certificate.subjects_match(csr.subject) or
            not credential_model.certificate.subjects_match(client_cert.subject)
        ):
            error_message = "CSR/client subject does not match the credential certificate's subject."
            raise ValueError(error_message)

        try:
            credential_cert = credential_model.certificate.get_certificate_serializer().as_crypto()
            credential_cert_san = credential_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            credential_cert_san = None

        try:
            csr_san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            csr_san = None

        try:
            client_san = client_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            client_san = None

        if (client_san != csr_san or credential_cert_san != csr_san):
            error_message = 'CSR/client SAN does not match the credential certificate SAN.'
            raise ValueError(error_message)

        context.device = issued_credential.device

class IDevIDAuthentication(AuthenticationComponent):
    """Handles authentication via IDevID certificates."""

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate the request using the IDevID mechanism."""
        domain = context.domain

        if not domain:
            error_message = 'domain is missing in the context.'
            raise ValueError(error_message)

        if context.raw_message is None:
            error_message = 'raw_message is missing in the context.'
            raise ValueError(error_message)

        try:
            device_or_none = IDevIDAuthenticator.authenticate_idevid(context.raw_message, domain)
        except IDevIDAuthenticationError as e:
            error_message = f'Error validating the IDevID: {e!s}'
            raise ValueError(error_message) from e

        if device_or_none:
            context.device = device_or_none
        else:
            error_message = 'IDevID authentication failed: No device associated.'
            raise ValueError(error_message)


class CompositeAuthentication(AuthenticationComponent):
    """Composite authenticator for grouping and executing multiple authentication methods."""

    def __init__(self) -> None:
        """Initialize the composite authenticator with a set of authentication components."""
        self.components: list[AuthenticationComponent] = []

    def add(self, component: AuthenticationComponent) -> None:
        """Add an authentication component to the composite."""
        self.components.append(component)

    def remove(self, component: AuthenticationComponent) -> None:
        """Remove an authentication component from the composite."""
        self.components.remove(component)

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate the request using all registered components."""
        for component in self.components:
            try:
                component.authenticate(context)
                if context.device is not None:
                    return
            except ValueError:
                continue
        error_message = 'Authentication failed: All authentication methods were unsuccessful.'
        raise ValueError(error_message)

class EstAuthentication(CompositeAuthentication):
    """Composite authenticator specifically for EST requests, combining various authentication methods."""

    def __init__(self) -> None:
        """Initialize the EST authenticator with a set of authentication methods."""
        super().__init__()
        self.add(ReenrollmentAuthentication())
        self.add(UsernamePasswordAuthentication())
        self.add(ClientCertificateAuthentication())
        self.add(IDevIDAuthentication())
