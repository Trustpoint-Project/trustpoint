"""Responds to the PKI message according to the original request protocol."""
from abc import ABC, abstractmethod

from request.request_context import BaseRequestContext


class AbstractMessageResponder(ABC):
    """Abstract base class for message responders."""

    @staticmethod
    @abstractmethod
    def build_response(context: BaseRequestContext) -> None:
        """Abstract base method for building a response to a message."""


