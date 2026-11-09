# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Operation authorization shared by HTTP enrollment protocols."""

from typing import ClassVar

from onboarding.models import NoOnboardingPkiProtocol, OnboardingPkiProtocol
from request.request_context import BaseRequestContext, HttpBaseRequestContext
from trustpoint.logger import LoggerMixin

from .base import AuthorizationComponent


class DeviceHttpProtocolAuthorization(AuthorizationComponent):
    """Enforce the selected device's enabled HTTP enrollment protocol."""

    def authorize(self, context: BaseRequestContext) -> None:
        """Reject enrollment after an operator disables its protocol on the device."""
        device = context.device
        if device is None:
            msg = 'A device is required for protocol authorization.'
            raise ValueError(msg)
        if device.onboarding_config:
            onboarding_protocol = {'est': OnboardingPkiProtocol.EST, 'rest': OnboardingPkiProtocol.REST}.get(
                context.protocol or ''
            )
            enabled = onboarding_protocol is not None and device.onboarding_config.has_pki_protocol(onboarding_protocol)
        elif device.no_onboarding_config:
            no_onboarding_protocol = {
                'est': NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD,
                'rest': NoOnboardingPkiProtocol.REST_USERNAME_PASSWORD,
            }.get(context.protocol or '')
            enabled = no_onboarding_protocol is not None and device.no_onboarding_config.has_pki_protocol(
                no_onboarding_protocol
            )
        else:
            enabled = False
        if not enabled:
            msg = 'The requested enrollment protocol is disabled for this device.'
            context.error(msg, http_status=403)
            raise ValueError(msg)


class HttpOperationAuthorization(AuthorizationComponent, LoggerMixin):
    """Allow only the configured operations for a protocol's request context."""

    context_type: ClassVar[type[HttpBaseRequestContext]]
    context_error_message: ClassVar[str]

    def __init__(self, allowed_operations: list[str]) -> None:
        """Store the protocol operations accepted by this authorization component."""
        self.allowed_operations = allowed_operations

    def authorize(self, context: BaseRequestContext) -> None:
        """Reject missing and unlisted operations before request processing."""
        if not isinstance(context, self.context_type):
            raise TypeError(self.context_error_message)

        operation = context.operation
        if not operation:
            msg = 'Operation information is missing. Authorization denied.'
            self.logger.warning('Operation authorization failed: Operation information is missing')
            raise ValueError(msg)
        if operation not in self.allowed_operations:
            msg = f"Unauthorized operation: '{operation}'. Allowed operations: {', '.join(self.allowed_operations)}."
            self.logger.warning('Operation authorization failed: %s not in %s', operation, self.allowed_operations)
            raise ValueError(msg)
        self.logger.debug('Operation authorization successful for operation: %s', operation)
