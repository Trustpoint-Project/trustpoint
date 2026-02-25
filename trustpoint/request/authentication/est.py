"""Provides the 'EstAuthentication' class using the Composite pattern for modular EST authentication."""

from typing import Never

from cryptography import x509

from devices.models import DeviceModel, IssuedCredentialModel
from pki.models import CredentialModel
from request.request_context import BaseRequestContext, EstBaseRequestContext, EstCertificateRequestContext
from trustpoint.logger import LoggerMixin

from .base import (
    AuthenticationComponent,
    ClientCertificateAuthentication,
    CompositeAuthentication,
    IDevIDAuthentication,
)


class UsernamePasswordAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles authentication via username/password credentials."""

    def authenticate(self, context: BaseRequestContext) -> None:
        """Authenticate using username and password from the context."""
        if not isinstance(context, EstBaseRequestContext):
            exc_msg = 'UsernamePasswordAuthentication requires an EstBaseRequestContext.'
            raise TypeError(exc_msg)

        if not (context.est_username and context.est_password):
            return

        username = context.est_username
        password = context.est_password

        try:
            device = DeviceModel.objects.select_related().filter(
                common_name=username
            ).first()

            if not device:
                self.logger.warning('Authentication failed: Unknown username %s', username)
                self._raise_authentication_error()

            device_config = device.onboarding_config or device.no_onboarding_config

            if not isinstance(device, DeviceModel) or not device_config:
                self.logger.warning('Authentication failed: Invalid device model for %s', username)
                self._raise_authentication_error()

            if not device_config.est_password:
                self.logger.warning('Authentication failed: No EST password set for %s', username)
                self._raise_authentication_error()

            # Use proper password hashing instead of plaintext comparison
            if password != device_config.est_password:
                self.logger.warning('Authentication failed: Invalid password for %s', username)
                self._raise_authentication_error()

            self.logger.info('Successfully authenticated device %s', username)
            context.device = device

        except Exception as e:
            self.logger.exception('Authentication error for user %s', username)
            error_message = 'Authentication failed: Invalid username or password.'
            raise ValueError(error_message) from e

    def _raise_authentication_error(self) -> Never:
        """Raise authentication error with standardized message."""
        error_message = 'Authentication failed: Invalid username or password.'
        raise ValueError(error_message)


class ReenrollmentAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles authentication for EST reenrollment using an Application Credential."""

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

    def _raise_value_error(self, message: str) -> Never:
        """Raise a ValueError with the given message."""
        raise ValueError(message)

    def authenticate(self, context: BaseRequestContext) -> None:
        """Authenticate the client for reenrollment."""
        if not isinstance(context, EstCertificateRequestContext):
            exc_msg = 'ReenrollmentAuthentication requires an EstCertificateRequestContext.'
            raise TypeError(exc_msg)

        if not self._validate_context(context):
            return

        if not context.client_certificate:
            error_message = 'Client certificate is required for reenrollment.'
            self.logger.warning(error_message)
            self._raise_value_error(error_message)

        issued_credential = self._get_issued_credential(context.client_certificate)
        credential_model: CredentialModel = issued_credential.credential

        if not isinstance(context.cert_requested, x509.CertificateSigningRequest):
            error_message = 'Invalid credential model for reenrollment.'
            self.logger.warning(error_message)
            self._raise_value_error(error_message)

        self._validate_credential(credential_model, context.cert_requested, context.client_certificate)
        self._validate_certificate_extensions_safe(credential_model, context.client_certificate, context.cert_requested)

        self.logger.info('Successfully authenticated device for reenrollment')
        context.device = issued_credential.device

    def _validate_context(self, context: EstCertificateRequestContext) -> bool:
        """Validate the context for reenrollment."""
        if not context.client_certificate:
            return False

        if not isinstance(context.client_certificate, x509.Certificate):
            error_message = 'Invalid client certificate type for reenrollment.'
            self.logger.warning(error_message)
            self._raise_value_error(error_message)

        if not context.cert_requested:
            error_message = 'CSR is missing in the context for reenrollment.'
            self.logger.warning(error_message)
            self._raise_value_error(error_message)

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

    def _validate_certificate_extensions_safe(
        self, credential_model: CredentialModel, client_cert: x509.Certificate, csr: x509.CertificateSigningRequest
    ) -> None:
        """Safely validate certificate extensions."""
        try:
            credential_cert = credential_model.certificate_or_error.get_certificate_serializer().as_crypto()
            self._validate_certificate_extensions(credential_cert, client_cert, csr)
        except Exception as e:
            self.logger.warning('Certificate extension validation failed: %s', e)
            error_message = 'Certificate extension validation failed'
            raise ValueError(error_message) from e


class EstAuthentication(CompositeAuthentication):
    """Composite authenticator specifically for EST requests, combining various authentication methods."""

    def __init__(self) -> None:
        """Initialize the EST authenticator with a set of authentication methods."""
        super().__init__()
        self.add(ReenrollmentAuthentication())
        self.add(UsernamePasswordAuthentication())
        self.add(ClientCertificateAuthentication())
        self.add(IDevIDAuthentication())

