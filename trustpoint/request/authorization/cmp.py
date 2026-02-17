"""Provides the 'CmpAuthorization' class using the Composite pattern for modular CMP authorization."""

from typing import Never

from pyasn1_modules.rfc4210 import PKIMessage  # type: ignore[import-untyped]

from cmp.util import PKIFailureInfo
from devices.models import IssuedCredentialModel
from request.request_context import BaseRequestContext, CmpBaseRequestContext, CmpRevocationRequestContext
from trustpoint.logger import LoggerMixin

from .base import (
    AuthorizationComponent,
    CertificateProfileAuthorization,
    CompositeAuthorization,
    DevOwnerIDAuthorization,
    DomainScopeValidation,
    ProtocolAuthorization,
)


class CmpRevocationAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensures the request is authorized for revocation operation."""

    def authorize(self, context: BaseRequestContext) -> None:
        """Authorize the request based on revocation specifics."""
        if context.operation != 'revocation':
            # Not a revocation operation; skip revocation-specific authorization
            return

        if not isinstance(context, CmpRevocationRequestContext):
            exc_msg = 'CmpRevocationAuthorization requires a CmpRevocationRequestContext.'
            raise TypeError(exc_msg)

        if not context.cert_serial_number:
            error_message = 'Certificate serial number is missing. Revocation authorization denied.'
            self.logger.warning('Revocation authorization failed: Certificate serial number is missing')
            self._raise_authorization_error(error_message, context)

        if not context.client_certificate:
            error_message = 'Client certificate is missing. Revocation authorization denied.'
            self.logger.warning('Revocation authorization failed: Client certificate is missing')
            self._raise_authorization_error(error_message, context)

        if not context.domain:
            error_message = 'Domain information is missing. Revocation authorization denied.'
            self.logger.warning('Revocation authorization failed: Domain information is missing')
            self._raise_authorization_error(error_message, context)

        # Ensure that either A) the client_certificate (CMP signer) equals the cert to be revoked (self-revocation)
        # or B) the client_certificate is the domain credential for the device the cert was issued to.
        try:
            signer_credential = IssuedCredentialModel.get_credential_for_certificate(context.client_certificate)
            signer_cert = signer_credential.credential.certificate_or_error
            if signer_cert.serial_number == str(context.cert_serial_number):
                context.credential_to_revoke = signer_credential
                self.logger.debug('Revocation authorized: Self-revocation of credential %s',
                                  context.credential_to_revoke.common_name)
                return
            valid, _reason = signer_credential.is_valid_domain_credential()
            if valid:
                signer_device = signer_credential.device
                if signer_device != context.device:
                    error_message = (
                        'Unauthorized revocation request: Signer device does not match the device '
                        'associated with the certificate to be revoked.'
                    )
                    self.logger.warning(
                        'Revocation authorization failed: Signer device does not match target device'
                    )
                    self._raise_authorization_error(error_message, context)

                context.credential_to_revoke = IssuedCredentialModel.get_credential_for_serial_number(
                    context.domain, context.device, context.cert_serial_number
                )
                self.logger.info('Revocation authorized: Domain credential revocation of credential %s',
                                 context.credential_to_revoke.common_name)
                return
            error_message = (
                'Unauthorized revocation request: Signer certificate does not match '
                'the certificate to be revoked or the device domain credential.'
            )
            self.logger.warning(
                'Revocation authorization failed: Signer certificate unauthorized for revocation'
            )
            self._raise_authorization_error(error_message, context)
        except IssuedCredentialModel.DoesNotExist:
            error_message = 'Signer certificate is not associated with any issued credential. Authorization denied.'
            self.logger.warning('Revocation authorization failed: Signer certificate not found in issued credentials')
            self._raise_authorization_error(error_message, context)

        self.logger.debug('Revocation authorization successful.')

    def _raise_authorization_error(self, message: str, context: BaseRequestContext) -> Never:
        """Raise a ValueError with the given message and sets generic Unauthorized as external response."""
        context.error('Unauthorized', http_status=403, cmp_code=PKIFailureInfo.NOT_AUTHORIZED)
        raise ValueError(message)


class CmpOperationAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensures the request is authorized for the specified operation."""

    def __init__(self, allowed_operations: list[str]) -> None:
        """Initialize the authorization component with a list of allowed operations."""
        self.allowed_operations = allowed_operations

    def authorize(self, context: BaseRequestContext) -> None:
        """Authorize the request based on the operation type."""
        if not isinstance(context, CmpBaseRequestContext):
            exc_msg = 'CmpOperationAuthorization requires a CmpBaseRequestContext.'
            raise TypeError(exc_msg)

        operation = context.operation

        if not operation:
            error_message = 'Operation information is missing. Authorization denied.'
            self.logger.warning('Operation authorization failed: Operation information is missing')
            raise ValueError(error_message)

        if operation not in self.allowed_operations:
            error_message = (
                f"Unauthorized operation: '{operation}'. Allowed operations: {', '.join(self.allowed_operations)}."
            )
            self.logger.warning(
                'Operation authorization failed: %(operation)s not in allowed operations %(allowed_operations)s',
                extra={'operation': operation, 'allowed_operations': self.allowed_operations},
            )
            raise ValueError(error_message)

        if not isinstance(context.parsed_message, PKIMessage):
            error_message = 'Parsed message is missing. Authorization denied.'
            self.logger.warning('Operation authorization failed: Parsed message is missing or invalid')
            self._raise_value_error(error_message)

        body_type = context.parsed_message['body'].getName()

        if context.operation == 'initialization' and body_type == 'ir':
            self.logger.info('CMP body type validation successful: IR body extracted')
        elif context.operation == 'certification' and body_type == 'cr':
            self.logger.info('CMP body type validation successful: CR body extracted')
        elif context.operation == 'revocation' and body_type == 'rr':
            CmpRevocationAuthorization().authorize(context)
            self.logger.info('CMP body type validation successful: RR body extracted')
        else:
            err_msg = f'Expected CMP {context.operation} body, but got CMP {body_type.upper()} body.'
            raise ValueError(err_msg)

        self.logger.debug(
            'Operation authorization successful for operation: %(operation)s', extra={'operation': operation}
        )

    def _raise_value_error(self, message: str) -> Never:
        """Raise a ValueError with the given message."""
        raise ValueError(message)


class CmpAuthorization(CompositeAuthorization):
    """Composite authorization handler for EST requests."""

    def __init__(self, allowed_operations: list[str] | None = None) -> None:
        """Initialize the composite authorization handler with the default set of components.

        Args:
            allowed_operations: List of allowed CMP operations. Defaults to ['cr', 'ir'] if not provided.
        """
        super().__init__()

        if allowed_operations is None:
            allowed_operations = ['certification', 'initialization']

        self.add(DomainScopeValidation())
        self.add(CertificateProfileAuthorization())
        self.add(DevOwnerIDAuthorization())
        self.add(ProtocolAuthorization(['cmp']))
        self.add(CmpOperationAuthorization(allowed_operations))
