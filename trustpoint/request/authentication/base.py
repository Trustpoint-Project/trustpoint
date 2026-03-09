"""Provides base authentication class using the Composite pattern for modular authentication."""

from abc import ABC, abstractmethod
from typing import Never

from cryptography import x509

from devices.models import DeviceModel
from pki.models import CredentialModel, IssuedCredentialModel
from pki.util.idevid import IDevIDAuthenticationError, IDevIDAuthenticator
from request.request_context import BaseCertificateRequestContext, BaseRequestContext, HttpBaseRequestContext
from trustpoint.logger import LoggerMixin


class AuthenticationComponent(ABC):
    """Abstract base class for authentication components."""

    @abstractmethod
    def authenticate(self, context: BaseRequestContext) -> DeviceModel | None:
        """Authenticate a request using specific logic."""


class ClientCertificateAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles authentication via client certificates."""

    domain_credential_only: bool = True

    def __init__(self, *, domain_credential_only: bool = True) -> None:
        """Initialize the client certificate authentication component."""
        self.domain_credential_only = domain_credential_only

    def authenticate(self, context: BaseRequestContext) -> None:
        """Authenticate using the client certificate from the context."""
        if not context.client_certificate:
            return

        client_certificate = context.client_certificate

        try:
            issued_credential = IssuedCredentialModel.get_credential_for_certificate(client_certificate)

            if self.domain_credential_only:
                is_valid, reason = issued_credential.is_valid_domain_credential()
            else:
                is_valid, reason = issued_credential.credential.is_valid_issued_credential()
            if not is_valid:
                self.logger.warning('Invalid client certificate: %s', reason)
                error_message = f'Invalid HTTP_SSL_CLIENT_CERT header: {reason}'
                self._raise_certificate_error(error_message)

            self.logger.info('Successfully authenticated device via client certificate')
            context.device = issued_credential.device

        except IssuedCredentialModel.DoesNotExist:
            self.logger.warning('Client certificate not found in issued credentials')
            error_message = 'Client certificate not recognized'
            self._raise_certificate_error(error_message)
        except ValueError:
            raise
        except Exception as e:
            self.logger.exception('Certificate authentication error')
            error_message = 'Certificate authentication failed'
            self._raise_certificate_error(error_message, e)

    def _raise_certificate_error(self, message: str, cause: Exception | None = None) -> Never:
        """Raise certificate authentication error with proper exception chaining."""
        if cause:
            raise ValueError(message) from cause
        raise ValueError(message)


class ReenrollmentAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles authentication for reenrollment using an existing Application Credential."""

    def authenticate(self, context: BaseRequestContext) -> None:
        """Authenticate the client for reenrollment.

        In reenrollment, the client must present a valid certificate that was previously
        issued by the system. The CSR subject must match the certificate subject, and
        all certificate extensions (particularly SAN) must match.

        Args:
            context: The request context. Must be a subclass of BaseCertificateRequestContext.

        Raises:
            TypeError: If context is not a BaseCertificateRequestContext.
            ValueError: If authentication fails or validation fails.
        """
        if not isinstance(context, BaseCertificateRequestContext):
            return

        if not self._validate_context(context):
            return

        if not context.client_certificate:
            error_message = 'Client certificate is required for reenrollment.'
            self.logger.warning(error_message)
            raise ValueError(error_message)

        issued_credential = self._get_issued_credential(context.client_certificate)
        credential_model: CredentialModel = issued_credential.credential

        if not isinstance(context.cert_requested, x509.CertificateSigningRequest):
            error_message = 'CSR is not a valid CertificateSigningRequest for reenrollment.'
            self.logger.warning(error_message)
            raise TypeError(error_message)

        self._validate_credential(credential_model, context.cert_requested, context.client_certificate)
        self._validate_certificate_extensions_safe(credential_model, context.client_certificate, context.cert_requested)

        self.logger.info('Successfully authenticated device for reenrollment')
        context.device = issued_credential.device

    def _validate_context(self, context: BaseCertificateRequestContext) -> bool:
        """Validate the context for reenrollment."""
        if not context.client_certificate:
            return False

        if not isinstance(context.client_certificate, x509.Certificate):
            error_message = 'Invalid client certificate type for reenrollment.'
            self.logger.warning(error_message)
            raise TypeError(error_message)

        if not context.cert_requested:
            error_message = 'CSR is missing in the context for reenrollment.'
            self.logger.warning(error_message)
            raise ValueError(error_message)

        return True

    def _get_issued_credential(self, client_cert: x509.Certificate) -> IssuedCredentialModel:
        """Retrieve the issued credential for the client certificate."""
        try:
            return IssuedCredentialModel.get_credential_for_certificate(client_cert)
        except IssuedCredentialModel.DoesNotExist:
            error_message = 'Issued credential not found for client certificate during reenrollment'
            self.logger.warning(error_message)
            raise ValueError(error_message) from None

    def _validate_credential(
        self, credential_model: CredentialModel, csr: x509.CertificateSigningRequest, client_cert: x509.Certificate
    ) -> None:
        """Validate the credential model against the CSR and client certificate."""
        is_valid, reason = credential_model.is_valid_issued_credential()
        if not is_valid:
            error_message = f'Invalid client certificate for reenrollment: {reason}'
            self.logger.warning(error_message)
            raise ValueError(error_message)

        cert = credential_model.certificate_or_error

        if (
            not cert.subjects_match(csr.subject) or
            not cert.subjects_match(client_cert.subject)
        ):
            error_message = "CSR/client subject does not match the credential certificate's subject"
            self.logger.warning(error_message)
            raise ValueError(error_message)

    def _validate_certificate_extensions(
        self,
        credential_cert: x509.Certificate,
        client_cert: x509.Certificate,
        csr: x509.CertificateSigningRequest
    ) -> None:
        """Validate that certificate extensions match between credential, client cert, and CSR."""
        try:
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

        if client_san != csr_san or credential_cert_san != csr_san:
            error_message = 'CSR/client SAN does not match the credential certificate SAN.'
            raise ValueError(error_message)

    def _validate_certificate_extensions_safe(
        self, credential_model: CredentialModel, client_cert: x509.Certificate, csr: x509.CertificateSigningRequest
    ) -> None:
        """Safely validate certificate extensions."""
        try:
            credential_cert = credential_model.certificate_or_error.get_certificate_serializer().as_crypto()
            self._validate_certificate_extensions(credential_cert, client_cert, csr)
        except TypeError:
            raise
        except Exception as e:
            self.logger.warning('Certificate extension validation failed: %s', e)
            error_message = 'Certificate extension validation failed'
            raise ValueError(error_message) from e


class IDevIDAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles authentication via IDevID certificates."""

    def authenticate(self, context: BaseRequestContext) -> None:
        """Authenticate the request using the IDevID mechanism."""
        # Early return if raw_message is missing
        if not isinstance(context, HttpBaseRequestContext) or not context.raw_message:
            return

        try:
            # domain can be None, in that case IDevIDAuthenticator will infer it from registration pattern
            device_or_none = IDevIDAuthenticator.authenticate_idevid(context.raw_message, context.domain)

            if device_or_none:
                self.logger.info('Successfully authenticated device via IDevID')
                context.device = device_or_none
                if not context.domain:
                    device_domain = context.device.domain
                    if not device_domain:
                        error_message = 'IDevID authentication failed: Device domain is not set.'
                        self.logger.warning('IDevID authentication failed: Device domain is not set')
                        self._raise_idevid_error(error_message)
                    context.domain = device_domain
                    context.domain_str = device_domain.unique_name
            else:
                error_message = 'IDevID authentication failed: No device associated.'
                self.logger.warning('IDevID authentication failed: No device associated')
                self._raise_idevid_error(error_message)

        except IDevIDAuthenticationError as e:
            error_message = f'Error validating the IDevID: {e}'
            self.logger.warning('Error validating the IDevID: %s', e)
            raise ValueError(error_message) from e
        except ValueError:
            raise
        except Exception as e:
            error_message = 'IDevID authentication failed due to unexpected error'
            self.logger.exception('Unexpected error during IDevID authentication')
            raise ValueError(error_message) from e

    def _raise_idevid_error(self, message: str) -> Never:
        """Raise IDevID authentication error."""
        raise ValueError(message)


class CompositeAuthentication(AuthenticationComponent, LoggerMixin):
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

    def authenticate(self, context: BaseRequestContext) -> None:
        """Authenticate the request using all registered components."""
        authentication_errors = []

        self.logger.debug('Authentication components to try: %s',
                          [component.__class__.__name__ for component in self.components])
        for component in self.components:
            try:
                component.authenticate(context)
                if context.device is not None:
                    self.logger.info('Authentication successful using %s', component.__class__.__name__)
                    return
            except ValueError as e:
                authentication_errors.append(f'{component.__class__.__name__}: {e}')
                continue
            except Exception:
                self.logger.exception('Unexpected error in %s', component.__class__.__name__)
                authentication_errors.append(f'{component.__class__.__name__}: Unexpected error')
                continue
        error_message = 'Authentication failed: All authentication methods were unsuccessful.'
        self.logger.warning('Authentication failed for all methods: %s', authentication_errors)
        context.http_response_content = 'Authentication failed.'
        context.http_response_status = 403
        raise ValueError(error_message)
