"""Carries out the requested operation after authentication and authorization."""

from abc import ABC, abstractmethod

from request.request_context import BaseRequestContext


class AbstractOperationProcessor(ABC):
    """Abstract base class for operation processors."""

    @abstractmethod
    def process_operation(self, context: BaseRequestContext) -> None:
        """Execute operation processing logic."""
