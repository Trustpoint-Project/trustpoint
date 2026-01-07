"""Handles Request Conversion to JSON and Profile Validation."""
import json

from pydantic_core import ValidationError

from cmp.util import PKIFailureInfo as CMPErrs
from pki.util.cert_profile import JSONProfileVerifier, ProfileValidationError
from pki.util.cert_req_converter import JSONCertRequestConverter
from request.request_context import BaseCertificateRequestContext
from trustpoint.logger import LoggerMixin


class ProfileValidator(LoggerMixin):
    """Converts and validates certificate requests against profiles."""

    @classmethod
    def validate(cls, context: BaseCertificateRequestContext) -> None:
        """Validates the certificate request against the profile.

        Args:
            context (BaseCertificateRequestContext): The request context containing the certificate request.
        """
        cert_request_json = JSONCertRequestConverter.to_json(context.cert_requested)
        cls.logger.info('Cert Request JSON: %s', cert_request_json)

        if not context.certificate_profile_model:
            exc_msg = 'Certificate profile model is not set in the context.'
            context.error('Corresponding certificate profile is missing.',
                          http_status=422, cmp_code=CMPErrs.UNACCEPTED_POLICY)
            raise ValueError(exc_msg)

        try:
            cert_profile = json.loads(context.certificate_profile_model.profile_json)
        except json.JSONDecodeError as e:
            exc_msg = f'Error decoding certificate profile JSON: {e}'
            context.error('Certificate profile data is corrupted.',
                          http_status=500, cmp_code=CMPErrs.UNACCEPTED_POLICY)
            raise ValueError(exc_msg) from e

        try:
            validated_request = JSONProfileVerifier(cert_profile).apply_profile_to_request(cert_request_json)
        except (ValidationError, ProfileValidationError) as e:
            exc_msg = f'Certificate request validation against profile failed: {e}'
            context.error('Request does not match the certificate profile.',
                          http_status=400, cmp_code=CMPErrs.UNACCEPTED_POLICY)
            raise ValueError(exc_msg) from e

        cls.logger.info('Validated Cert Request JSON: %s', validated_request)

        context.cert_requested_profile_validated = JSONCertRequestConverter.from_json(validated_request)
