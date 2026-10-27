# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Operation authorization shared by HTTP enrollment protocols."""

from typing import ClassVar

from request.request_context import BaseRequestContext, HttpBaseRequestContext
from trustpoint.logger import LoggerMixin

from .base import AuthorizationComponent


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
