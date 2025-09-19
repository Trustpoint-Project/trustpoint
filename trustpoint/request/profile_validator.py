"""Handles Request Conversion to JSON and Profile Validation."""

from pki.util.cert_profile import JSONProfileVerifier
from pki.util.cert_req_converter import JSONCertRequestConverter

from request.request_context import RequestContext
from trustpoint.logger import LoggerMixin


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

        validated_req = JSONProfileVerifier.validate_request(cert_request_json)

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

        validated_request = JSONProfileVerifier(cert_profile).apply_profile_to_request(validated_req)
        cls.logger.info('Validated Cert Request JSON: %s', validated_request)

        context.cert_requested_profile_validated = JSONCertRequestConverter.from_json(validated_request)
