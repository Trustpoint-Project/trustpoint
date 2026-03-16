"""Provides the 'CmpAuthorization' class using the Composite pattern for modular CMP authorization."""
from typing import Never

from pyasn1_modules.rfc4210 import PKIMessage  # type: ignore[import-untyped]

from cmp.util import PKIFailureInfo
from pki.models import IssuedCredentialModel
from request.request_context import (
    BaseRequestContext,
    CmpBaseRequestContext,
    CmpCertConfRequestContext,
    CmpRevocationRequestContext,
)
from trustpoint.logger import LoggerMixin

from .base import (
    AuthorizationComponent,
    CertificateProfileAuthorization,
    CompositeAuthorization,
    DevOwnerIDAuthorization,
    DomainScopeValidation,
    OnboardingDomainCredentialAuthorization,
    ProtocolAuthorization,
    SecurityConfigAuthorization,
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
                self._authorize_domain_credential_revocation(context, signer_credential)
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

    def _authorize_domain_credential_revocation(
        self, context: CmpRevocationRequestContext, signer_credential: IssuedCredentialModel
    ) -> None:
        """Authorize revocation via a domain credential and set credential_to_revoke on the context."""
        signer_device = signer_credential.device
        if signer_device != context.device:
            error_message = (
                'Unauthorized revocation request: Signer device does not match the device '
                'associated with the certificate to be revoked.'
            )
            self.logger.warning('Revocation authorization failed: Signer device does not match target device')
            self._raise_authorization_error(error_message, context)

        if context.device is None:
            error_message = 'Device information is missing. Revocation authorization denied.'
            self.logger.warning('Revocation authorization failed: Device information is missing')
            self._raise_authorization_error(error_message, context)

        if context.domain is None:
            error_message = 'Domain information is missing. Revocation authorization denied.'
            self.logger.warning('Revocation authorization failed: Domain information is missing')
            self._raise_authorization_error(error_message, context)

        if context.cert_serial_number is None:
            error_message = 'Certificate serial number is missing. Revocation authorization denied.'
            self.logger.warning('Revocation authorization failed: Certificate serial number is missing')
            self._raise_authorization_error(error_message, context)

        context.credential_to_revoke = IssuedCredentialModel.get_credential_for_serial_number(
            context.domain, context.device, context.cert_serial_number
        )
        self.logger.info(
            'Revocation authorized: Domain credential revocation of credential %s',
            context.credential_to_revoke.common_name,
        )


class CmpCertConfAuthorization(AuthorizationComponent, LoggerMixin):
    """Authorization component for certConf messages.

    When the EE signals rejection (statusInfo.status == 2) the component looks
    up the ``IssuedCredentialModel`` whose certificate hash matches the
    ``cert_hash`` carried in the certConf body and stores it in
    ``context.credential_to_revoke`` so that the operation processor can
    revoke the certificate via the standard revocation pipeline.

    For accepted certConf messages (status == 0 or no statusInfo) the
    component is a no-op from a credential perspective.
    """

    def authorize(self, context: BaseRequestContext) -> None:
        """Authorize and, on rejection, identify the credential to revoke."""
        if context.operation not in ('certconf', 'initialization', 'certification'):
            return
        if not isinstance(context, CmpCertConfRequestContext):
            return

        # PKIStatus value 2 means "rejection" per RFC 4210 Section 5.2.3.
        pki_status_rejection = 2
        if context.cert_conf_status != pki_status_rejection:
            self.logger.debug('certConf: status is accepted (or absent) — no credential lookup required.')
            return

        if not context.cert_hash:
            error_message = 'certConf rejection received but certHash is missing. Authorization denied.'
            self.logger.warning('certConf authorization failed: certHash is missing')
            self._raise_authorization_error(error_message, context)

        # The certHash in RFC 4210 §5.3.18 is computed as SHA-256 over the
        # DER-encoded certificate.
        cert_hash_hex: str = context.cert_hash.hex().upper()

        cert_model = (
            IssuedCredentialModel.objects.filter(
                credential__certificates__sha256_fingerprint=cert_hash_hex
            )
            .select_related('credential', 'device', 'domain')
            .first()
        )

        if cert_model is None:
            error_message = (
                f'certConf rejection: no issued credential found for certHash {cert_hash_hex}. '
                'Authorization denied.'
            )
            self.logger.warning(
                'certConf authorization failed: no credential found for certHash %s', cert_hash_hex
            )
            self._raise_authorization_error(error_message, context)

        context.credential_to_revoke = cert_model
        self.logger.info(
            'certConf rejection: credential %s identified for revocation (certHash=%s)',
            cert_model.common_name,
            cert_hash_hex,
        )

    def _raise_authorization_error(self, message: str, context: BaseRequestContext) -> None:
        """Set a generic error on the context and raise ValueError."""
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
                f"Unauthorized operation: '{operation}'. "
                f"Allowed operations: {', '.join(self.allowed_operations)}."
            )
            self.logger.warning(
                'Operation authorization failed: %(operation)s not in allowed operations %(allowed_operations)s',
                extra={'operation': operation, 'allowed_operations': self.allowed_operations})
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
        elif context.operation in ('initialization', 'certification', 'certconf') and body_type == 'certConf':
            # certConf is sent to the same endpoint as the original enrollment
            # operation (RFC 9483 Section 6.1).  The CmpCertConfAuthorization
            # component handles credential lookup for rejection-case revocation.
            CmpCertConfAuthorization().authorize(context)
            self.logger.info('CMP certConf body received for operation: %s', context.operation)
        else:
            err_msg = f'Expected CMP {context.operation} body, but got CMP {body_type.upper()} body.'
            raise ValueError(err_msg)

        self.logger.debug('Operation authorization successful for operation: %(operation)s',
                          extra={'operation': operation})

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
        self.add(OnboardingDomainCredentialAuthorization())
        self.add(DevOwnerIDAuthorization())
        self.add(ProtocolAuthorization(['cmp']))
        self.add(CmpOperationAuthorization(allowed_operations))
        self.add(SecurityConfigAuthorization())
