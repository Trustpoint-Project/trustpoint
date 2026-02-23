"""Manual-specific message responder classes."""

from onboarding.models import OnboardingStatus
from request.request_context import BaseRequestContext, ManualBaseRequestContext, ManualCredentialRequestContext

from .base import AbstractMessageResponder


class ManualMessageResponder(AbstractMessageResponder):
    """Builds response to manual requests."""

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Respond to a manual message (saves request result - e.g. issued cert - to DB)."""
        if not isinstance(context, ManualBaseRequestContext):
            exc_msg = 'ManualMessageResponder requires a subclass of ManualBaseRequestContext.'
            raise TypeError(exc_msg)

        if isinstance(context, ManualCredentialRequestContext):
            responder = ManualCredentialMessageResponder()
            return responder.build_response(context)
        exc_msg = 'No suitable responder found for this manual message.'
        context.http_response_status = 500
        context.http_response_content = exc_msg
        return ManualErrorMessageResponder().build_response(context)


class ManualCredentialMessageResponder(ManualMessageResponder):
    """Respond to a manual certificate request with the issued certificate."""

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Respond to a manual certificate request with the issued certificate."""
        if not isinstance(context, ManualCredentialRequestContext):
            exc_msg = 'ManualCredentialMessageResponder requires a ManualCredentialRequestContext.'
            raise TypeError(exc_msg)

        if context.device and context.device.onboarding_config:
            context.device.onboarding_config.onboarding_status = OnboardingStatus.ONBOARDED
            context.device.onboarding_config.save()
        context.http_response_status = 200
        #context.http_response_content = cert
        #context.http_response_content_type = content_type


class ManualErrorMessageResponder(ManualMessageResponder):
    """Respond to a manual message with an error."""

    @staticmethod
    def build_response(context: BaseRequestContext) -> None:
        """Respond to a manual message with an error."""
        # Set appropriate HTTP status code and error message in context
        if not isinstance(context, ManualBaseRequestContext):
            exc_msg = 'ManualErrorMessageResponder requires a ManualBaseRequestContext.'
            raise TypeError(exc_msg)
        context.http_response_status = context.http_response_status or 500
        context.http_response_content = (context.http_response_content
                                         or 'An error occurred processing the manual request.')
        #context.http_response_content_type = context.http_response_content_type or 'text/plain'
