# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Views for EST (Enrollment over Secure Transport) handling authentication and certificate issuance."""

import base64
from typing import TYPE_CHECKING, Any, ClassVar, Literal, cast

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from trustpoint_core.serializer import CertificateCollectionSerializer

from est.csrattrs import build_csrattrs
from pki.models.ca_rollover import CaRolloverState
from pki.models.cert_profile import CertificateProfileModel
from pki.models.domain import DomainModel
from pki.services.ca_rollover import CaRolloverService
from request.enrollment import est_enrollment
from request.message_responder import EstErrorMessageResponder
from request.request_context import EstCertificateRequestContext
from trustpoint.logger import LoggerMixin
from workflows2.events.request_events import Events

if TYPE_CHECKING:
    from pki.models.credential import CredentialModel


class UsernamePasswordAuthenticationError(Exception):
    """Exception raised for username and password authentication failures."""


THRESHOLD_LOGGER: int = 400


class LoggedHttpResponse(HttpResponse, LoggerMixin):
    """Custom HttpResponse that logs and prints error messages automatically."""

    def __init__(self, content: str | bytes = b'', status: int | None = None, *args: Any, **kwargs: Any) -> None:
        """Initialize the LoggedHttpResponse instance."""
        if status and status >= THRESHOLD_LOGGER:
            if isinstance(content, bytes):
                content = content.decode('utf-8')
            self.logger.error('EST - ERROR - %s - %s', status, content)
        else:
            self.logger.info('EST - SUCCESS - %s', status)

        super().__init__(content, *args, status=status, **kwargs)


class EstRequestedDomainExtractorMixin:
    """Mixin to extract the requested domain."""

    requested_domain: DomainModel | None

    def extract_requested_domain(self, domain_name: str) -> tuple[DomainModel | None, LoggedHttpResponse | None]:
        """Extract the requested domain."""
        try:
            requested_domain = DomainModel.objects.get(unique_name=domain_name)
        except DomainModel.DoesNotExist:
            return None, LoggedHttpResponse('Domain does not exist.', status=404)
        else:
            return requested_domain, None


class EstSimpleEnrollmentMixin(LoggerMixin):
    """Mixin providing common logic for EST simple enrollment operations."""

    EVENT = Events.est_simpleenroll
    operation: Literal['simpleenroll', 'simplereenroll'] = 'simpleenroll'
    context_error_message = 'Failed to set up EST request context.'
    context_error_response: ClassVar[type[HttpResponse]] = HttpResponse

    def process_enrollment(
        self,
        request: HttpRequest,
        domain_name: str | None,
        cert_profile: str | None,
    ) -> HttpResponse:
        """Process an EST simple enrollment request."""
        self.logger.info('Request received: method=%s path=%s', request.method, request.path)

        try:
            ctx = EstCertificateRequestContext(
                raw_message=request,
                protocol='est',
                operation=self.operation,
                domain_str=domain_name,
                cert_profile_str=cert_profile,
                event=self.EVENT,
            )
        except Exception:
            err_msg = self.context_error_message
            self.logger.exception(err_msg)
            return self.context_error_response(err_msg, status=500)

        orchestrator = est_enrollment(ctx, operation=self.operation)
        try:
            orchestrator.run()
        except Exception:
            self.logger.exception('Error processing EST %s request', self.operation)
            EstErrorMessageResponder.build_response(orchestrator.context)

        return orchestrator.context.to_http_response()


@method_decorator(csrf_exempt, name='dispatch')
class EstSimpleEnrollmentView(EstSimpleEnrollmentMixin, View):
    """Handles simple EST enrollment requests."""

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle POST requests for simple enrollment."""
        del args
        domain_name = cast('str', kwargs.get('domain'))
        cert_profile = cast('str | None', kwargs.get('cert_profile'))
        return self.process_enrollment(request, domain_name, cert_profile)


@method_decorator(csrf_exempt, name='dispatch')
class EstSimpleReEnrollmentView(EstSimpleEnrollmentView):
    """Handle reenrollment through the same EST orchestration as initial enrollment."""

    EVENT = Events.est_simplereenroll
    operation = 'simplereenroll'
    context_error_message = 'Failed to set up request context.'
    context_error_response = LoggedHttpResponse


@method_decorator(csrf_exempt, name='dispatch')
class EstCACertsView(EstRequestedDomainExtractorMixin, View, LoggerMixin):
    """View to handle the EST /cacerts endpoint."""

    @staticmethod
    def _get_domain_ca_chain(domain: DomainModel) -> CertificateCollectionSerializer:
        """Include the current CA chain and any prepared rollover chain."""
        if domain.issuing_ca is None:
            msg = 'The requested domain has no issuing CA configured'
            raise ValueError(msg)
        credential = cast('CredentialModel', domain.issuing_ca.credential).get_credential_serializer()
        chain = credential.get_full_chain_as_serializer()
        rollover = CaRolloverService.get_active_rollover(domain.issuing_ca)
        if (
            rollover
            and rollover.state == CaRolloverState.PREPARATION
            and rollover.new_issuing_ca
            and rollover.new_issuing_ca.credential
        ):
            new_credential = rollover.new_issuing_ca.credential.get_credential_serializer()
            chain = CertificateCollectionSerializer(
                chain.as_crypto() + new_credential.get_full_chain_as_serializer().as_crypto()
            )
        return chain

    def _get_default_ca_certs(self) -> LoggedHttpResponse:
        """Publish all active domains' CA chains when no CA label is supplied."""
        domains = (
            DomainModel.objects.filter(is_active=True, issuing_ca__isnull=False)
            .select_related('issuing_ca__credential')
            .order_by('pk')
        )
        certificates = []
        for domain in domains:
            certificates.extend(self._get_domain_ca_chain(domain).as_crypto())
        if not certificates:
            return LoggedHttpResponse('No CA certificates are available.', status=503)
        # Domains may share an issuing CA or root; publish each certificate once.
        chain = CertificateCollectionSerializer(list(dict.fromkeys(certificates)))
        return LoggedHttpResponse(
            base64.b64encode(chain.as_pkcs7_der()),
            status=200,
            content_type='application/pkcs7-mime',
            headers={'Content-Transfer-Encoding': 'base64'},
        )

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> LoggedHttpResponse:
        """Handle GET requests for the /cacerts endpoint."""
        self.logger.info('Request received: method=%s path=%s', request.method, request.path)
        del request, args
        requested_domain: DomainModel | None

        try:
            domain_name = cast('str | None', kwargs.get('domain'))
            if domain_name is None:
                return self._get_default_ca_certs()
            requested_domain, http_response = self.extract_requested_domain(domain_name=domain_name)

            if not http_response and requested_domain:
                if not requested_domain.issuing_ca:
                    return LoggedHttpResponse('The requested domain has no issuing CA configured', status=500)

                pkcs7_certs = self._get_domain_ca_chain(requested_domain).as_pkcs7_der()

                b64_pkcs7 = base64.b64encode(pkcs7_certs).decode()
                formatted_b64_pkcs7 = '\n'.join(b64_pkcs7[i : i + 64] for i in range(0, len(b64_pkcs7), 64))

                http_response = LoggedHttpResponse(
                    formatted_b64_pkcs7.encode(),
                    status=200,
                    content_type='application/pkcs7-mime',
                    headers={'Content-Transfer-Encoding': 'base64'},
                )

                if 'Vary' in http_response:
                    del http_response['Vary']
                if 'Content-Language' in http_response:
                    del http_response['Content-Language']

            if not http_response:
                http_response = LoggedHttpResponse('Something went wrong during EST getcacerts.', status=500)

        except Exception:
            self.logger.exception('Error retrieving CA certificates')
            return LoggedHttpResponse('Error retrieving CA certificates', status=500)
        else:
            return http_response


@method_decorator(csrf_exempt, name='dispatch')
class EstCsrAttrsView(View, LoggerMixin):
    """View to handle the EST /csrattrs endpoint."""

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Return public CSR requirements for the selected domain and profile."""
        self.logger.info('Request received: method=%s path=%s', request.method, request.path)
        del request, args
        domain_name = kwargs.get('domain')
        profile_name = kwargs.get('cert_profile')
        profile = None
        try:
            if domain_name is not None:
                domain = DomainModel.objects.get(unique_name=domain_name, is_active=True)
                profile_name = profile_name or domain.get_domain_credential_profile_name()
                try:
                    profile = domain.get_allowed_cert_profile(profile_name)
                except ValueError:
                    return LoggedHttpResponse('Certificate profile is not available in this domain.', status=404)
            elif profile_name is not None:
                profile = CertificateProfileModel.objects.get(unique_name=profile_name.removeprefix('~'))
            der = build_csrattrs(
                profile.profile if profile is not None else None,
                require_channel_binding=settings.TRUSTPOINT_EST_REQUIRE_CHANNEL_BINDING,
            )
        except (DomainModel.DoesNotExist, CertificateProfileModel.DoesNotExist):
            return LoggedHttpResponse('Domain or certificate profile does not exist.', status=404)
        except Exception:
            self.logger.exception('Error retrieving CSR attributes')
            return LoggedHttpResponse('Error retrieving CSR attributes.', status=500)
        return LoggedHttpResponse(base64.b64encode(der), status=200, content_type='application/csrattrs')
