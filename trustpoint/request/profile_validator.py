"""Handles Request Conversion to JSON and Profile Validation."""

from pki.util.cert_profile import JSONProfileVerifier, ProfileValidationError
from pki.util.cert_req_converter import JSONCertRequestConverter
from pydantic_core import ValidationError
from trustpoint.logger import LoggerMixin

from request.request_context import RequestContext


class ProfileValidator(LoggerMixin):
    """Converts and validates certificate requests against profiles."""

    @classmethod
    def validate(cls, context: RequestContext) -> None:
        """Validates the certificate request against the profile.

        Args:
            context (RequestContext): The request context containing the certificate request.
        """
        cert_request_json = JSONCertRequestConverter.to_json(context.cert_requested)
        cls.logger.info('Cert Request JSON: %s', cert_request_json)

        # TODO: Get correct profile
        # How this will work eventually:
        # First, we check the requested profile ("template") from the URL.
        # If it is allowed/defined in this domain, proceed to use this profile.
        # If no profile is given as part of the URL or it is not defined in the domain, try domain default profile(s)
        # First domain default profile which successfully validates is used.
        cert_profile = {
            'type': 'cert_profile',
            'subj': {'allow':'*'},
            'ext': {
                'crl': {'uris': ['http://localhost/crl/2']},
            },
            'validity': {
                'days': 30
            }
        }

        try:
            validated_request = JSONProfileVerifier(cert_profile).apply_profile_to_request(cert_request_json)
        except (ValidationError, ProfileValidationError) as e:
            exc_msg = f'Certificate request validation against profile failed: {e}'
            context.http_response_content = 'Request does not match the certificate profile.'
            context.http_response_status = 400
            raise ValueError(exc_msg) from e

        cls.logger.info('Validated Cert Request JSON: %s', validated_request)

        context.cert_requested_profile_validated = JSONCertRequestConverter.from_json(validated_request)
