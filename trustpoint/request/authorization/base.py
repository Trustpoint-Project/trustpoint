"""Provides the `AuthorizationComponent` class for authorization logic."""
from abc import ABC, abstractmethod

from aoki.views import AokiServiceMixin
from request.profile_validator import ProfileValidator
from request.request_context import BaseCertificateRequestContext, BaseRequestContext
from trustpoint.logger import LoggerMixin


class AuthorizationComponent(ABC):
    """Abstract base class for authorization components."""

    @abstractmethod
    def authorize(self, context: BaseRequestContext) -> None:
        """Execute authorization logic."""

class ProtocolAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensures the request is under the correct protocol: CMP or EST."""

    def __init__(self, allowed_protocols: list[str]) -> None:
        """Initialize the authorization component with a list of allowed protocols."""
        self.allowed_protocols = allowed_protocols

    def authorize(self, context: BaseRequestContext) -> None:
        """Authorize the request based on the protocol."""
        protocol = context.protocol

        if not protocol:
            error_message = 'Protocol information is missing. Authorization denied.'
            self.logger.warning('Protocol authorization failed: Protocol information is missing')
            raise ValueError(error_message)

        if protocol not in self.allowed_protocols:
            error_message = (
                f"Unauthorized protocol: '{protocol}'. "
                f"Allowed protocols: {', '.join(self.allowed_protocols)}."
            )
            self.logger.warning(
                'Protocol authorization failed: %(protocol)s not in allowed protocols %(allowed_protocols)s',
                extra={'protocol': protocol, 'allowed_protocols': self.allowed_protocols})
            raise ValueError(error_message)

        self.logger.debug('Protocol authorization successful for protocol: %(protocol)s',
                          extra={'protocol': protocol})


class CertificateProfileAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensures the device is allowed to use the requested certificate profile."""

    def authorize(self, context: BaseRequestContext) -> None:
        """Authorize the request based on the certificate profile."""
        if not isinstance(context, BaseCertificateRequestContext):
            # Not a certificate request context; skip profile authorization
            return

        requested_profile = context.cert_profile_str

        if not requested_profile:
            error_message = 'Certificate profile is missing in the context. Authorization denied.'
            self.logger.warning('Certificate profile authorization failed: Profile information is missing')
            raise ValueError(error_message)

        if not context.domain:
            error_message = 'Domain information is missing in the context. Authorization denied.'
            self.logger.warning('Certificate profile authorization failed: Domain information is missing')
            raise ValueError(error_message)

        try:
            context.certificate_profile_model = context.domain.get_allowed_cert_profile(requested_profile)
        except ValueError as e:
            context.http_response_content = f'Not authorized for requested certificate profile "{requested_profile}".'
            context.http_response_status = 403
            error_message = (
                f"Unauthorized certificate profile: '{requested_profile}'. "
                f"Allowed profiles: {', '.join(context.domain.get_allowed_cert_profile_names())}."
            )
            self.logger.warning(error_message)
            raise ValueError(error_message) from e

        ProfileValidator.validate(context)

        self.logger.debug(
            'Certificate profile authorization successful for profile: %s',
            requested_profile
        )


class DomainScopeValidation(AuthorizationComponent, LoggerMixin):
    """Ensures the request is within the authorized domain."""

    def authorize(self, context: BaseRequestContext) -> None:
        """Authorize the request based on the domain scope."""
        authenticated_device = context.device
        requested_domain = context.domain

        if not authenticated_device:
            error_message = 'Authenticated device is missing in the context. Authorization denied.'
            self.logger.warning('Domain scope validation failed: Authenticated device is missing')
            raise ValueError(error_message)

        if not requested_domain:
            error_message = 'Requested domain is missing in the context. Authorization denied.'
            self.logger.warning('Domain scope validation failed: Requested domain is missing')
            raise ValueError(error_message)

        device_domain = authenticated_device.domain

        if not device_domain or device_domain != requested_domain:
            error_message = (
                f"Unauthorized requested domain: '{requested_domain}'. "
                f"Device domain: '{device_domain}'."
            )
            self.logger.warning(
                "Domain scope validation failed: Device domain %s doesn't match requested domain %s",
                device_domain, requested_domain
            )
            raise ValueError(error_message)

        self.logger.debug(
            'Domain scope validation successful: Device %s authorized for domain %s',
            authenticated_device.common_name, requested_domain
        )


class DevOwnerIDAuthorization(AuthorizationComponent, LoggerMixin):
    """Ensure that if this is an AOKI request, we have a matching DevOwnerID to the IDevID."""

    def authorize(self, context: BaseRequestContext) -> None:
        """Authorize the request based on the DevOwnerID corresponding to the client certificate."""
        if context.protocol != 'cmp':
            return
        if context.domain_str != '.aoki':
            return

        client_cert = context.client_certificate

        if not client_cert:
            error_message = 'Client certificate is missing in the context. Authorization denied.'
            self.logger.warning('DevOwnerID authorization failed: Client certificate is missing')
            raise ValueError(error_message)

        owner_credential = AokiServiceMixin.get_owner_credential(client_cert)
        if not owner_credential:
            err_msg = 'No DevOwnerID credential present for this IDevID.'
            context.http_response_content = err_msg
            context.http_response_status = 403
            self.logger.warning(err_msg)
            raise ValueError(err_msg)

        context.owner_credential = owner_credential


class CompositeAuthorization(AuthorizationComponent, LoggerMixin):
    """Composite authorization handler for grouping and executing multiple authorization components."""

    def __init__(self) -> None:
        """Initialize the composite authorization handler with an empty list of components."""
        self.components: list[AuthorizationComponent] = []

    def add(self, component: AuthorizationComponent) -> None:
        """Add a new authorization component to the composite."""
        self.components.append(component)

    def remove(self, component: AuthorizationComponent) -> None:
        """Remove an authorization component from the composite."""
        if component in self.components:
            self.components.remove(component)
            self.logger.debug('Removed authorization component', extra={'component_name': component.__class__.__name__})
        else:
            error_message = f'Attempted to remove non-existent authorization component: {component.__class__.__name__}'
            self.logger.warning(error_message)
            raise ValueError(error_message)

    def authorize(self, context: BaseRequestContext) -> None:
        """Iterate through all child authorization components and execute their authorization logic."""
        self.logger.debug('Starting composite authorization with %d components', len(self.components))

        for i, component in enumerate(self.components):
            try:
                component.authorize(context)
                self.logger.debug('Authorization component passed',
                                  extra={'component_name': component.__class__.__name__})
            except ValueError as e:
                error_message = f'{component.__class__.__name__}: {e}'
                self.logger.warning('Authorization component failed',
                                    extra={'component_name': component.__class__.__name__, 'error_message': str(e)})
                self.logger.exception(
                    'Composite authorization failed at component %d/%d: %s',
                    i + 1, len(self.components), component.__class__.__name__)
                raise ValueError(error_message) from e
            except Exception as e:
                error_message = f'Unexpected error in {component.__class__.__name__}: {e}'
                self.logger.exception(
                    'Unexpected error in authorization component %s',
                    component.__class__.__name__
                )
                self.logger.exception(
                    'Composite authorization failed at component %d/%d: %s',
                    i + 1, len(self.components), component.__class__.__name__)
                raise ValueError(error_message) from e

        self.logger.info('Composite authorization successful. All %d components passed', len(self.components))
