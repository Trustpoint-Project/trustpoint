# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Provides the 'EstAuthentication' class using the Composite pattern for modular EST authentication."""

from typing import Never

from cryptography import x509

from pki.models import CredentialModel
from request.request_context import (
    BaseCertificateRequestContext,
    BaseRequestContext,
    EstBaseRequestContext,
    EstCertificateRequestContext,
)

from .base import (
    ClientCertificateAuthentication,
    CompositeAuthentication,
    DevicePasswordAuthentication,
    IDevIDAuthentication,
)
from .base import ReenrollmentAuthentication as BaseReenrollmentAuthentication


class UsernamePasswordAuthentication(DevicePasswordAuthentication):
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
            self._authenticate_credentials(context, username, password)

        except Exception as e:
            self.logger.exception('Authentication error for user %s', username)
            error_message = 'Authentication failed: Invalid username or password.'
            raise ValueError(error_message) from e


class ReenrollmentAuthentication(BaseReenrollmentAuthentication):
    """Handles authentication for EST reenrollment using an Application Credential."""

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

    def _validate_context(self, context: BaseCertificateRequestContext) -> bool:
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
