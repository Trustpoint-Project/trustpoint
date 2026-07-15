"""DRF API views for the Trustpoint agent job-polling endpoint."""

from __future__ import annotations

import copy
import urllib.parse
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from cryptography import x509
from django.utils import timezone
from drf_spectacular.utils import OpenApiExample, OpenApiResponse, extend_schema
from rest_framework import serializers, status
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import AgentAssignedProfile, TrustpointAgent
from devices.models import DeviceModel
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from rest_framework.request import Request


def _parse_client_cert(request: Request) -> x509.Certificate | None:
    """Extract and parse the client certificate from the Django request META."""
    raw: str | None = request.META.get('HTTP_SSL_CLIENT_CERT')
    if not raw or not raw.strip():
        return None

    try:
        pem_bytes = urllib.parse.unquote(raw).encode('utf-8')
        return x509.load_pem_x509_certificate(pem_bytes)
    except Exception as exc:
        msg = f'Invalid HTTP_SSL_CLIENT_CERT header: {exc}'
        raise AuthenticationFailed(msg) from exc


class AgentCertificateAuthentication(LoggerMixin, BaseAuthentication):
    """Authenticate an agent via its mTLS client certificate (domain credential)."""

    def authenticate(self, request: Request) -> tuple[TrustpointAgent, None] | None:
        """The agent authenticates using its domain credential certificate issued during onboarding."""
        cert = _parse_client_cert(request)
        if cert is None:
            return None

        try:
            from pki.models import IssuedCredentialModel  # noqa: PLC0415

            issued_credential = IssuedCredentialModel.get_credential_for_certificate(cert)

            is_valid, reason = issued_credential.is_valid_domain_credential()
            if not is_valid:
                self._raise_auth_failed(f'Invalid domain credential: {reason}')

            device = issued_credential.device
            if device is None:
                self._raise_auth_failed('No device associated with the client certificate.')

            agent: TrustpointAgent | None = (
                TrustpointAgent.objects.select_related('device__domain')
                .filter(device=device, is_active=True)
                .first()
            )
            if agent is None:
                self._raise_auth_failed('No active agent found for the device associated with the client certificate.')

        except IssuedCredentialModel.DoesNotExist as exc:
            msg = 'Client certificate not found in issued credentials.'
            raise AuthenticationFailed(msg) from exc
        except AuthenticationFailed:
            raise
        except Exception as exc:
            self.logger.exception('Certificate authentication failed due to an internal error.')
            msg = 'Certificate authentication failed.'
            raise AuthenticationFailed(msg) from exc

        if agent is None:
            msg = 'Authentication failed: agent not found.'
            raise AuthenticationFailed(msg)
        return (agent, None)

    @staticmethod
    def _raise_auth_failed(msg: str) -> None:
        """Raise an AuthenticationFailed exception with the given message."""
        raise AuthenticationFailed(msg)

    def authenticate_header(self, request: Request) -> str:  # noqa: ARG002
        """Return the ``WWW-Authenticate`` challenge value for 401 responses."""
        return 'mTLS realm="Trustpoint Agent API"'

def _resolve_enrollment_url(agent: TrustpointAgent, cert_profile: str) -> str | None:
    """Return the server-side enrollment *path* for a 1-to-1 agent, or ``None`` for other types."""
    device = agent.device
    if device is None:
        return None
    if device.device_type != DeviceModel.DeviceType.AGENT_ONE_TO_ONE:
        return None
    domain = device.domain
    if domain is None:
        return None

    return f'/rest/{domain.unique_name}/{cert_profile}/enroll/'


def _build_resolved_profile(
    agent: TrustpointAgent,
    raw_profile: dict[str, Any],
    assigned_profile: AgentAssignedProfile,
) -> dict[str, Any]:
    """Return a deep copy of *raw_profile* with placeholders resolved.

    Resolves:
    - ``certificate_request.path`` → enrollment endpoint path
    - ``certificate_request.subject`` → subject DN from assigned_profile
    - ``certificate_request.subject_alt_name`` → SAN extension from assigned_profile
    - ``certificate_request.public_key_algorithm_oid`` → OID from domain's issuing CA
    - ``certificate_request.key_size`` → RSA key size (if RSA)
    - ``certificate_request.named_curve`` → ECC curve name (if ECC)
    """
    profile = copy.deepcopy(raw_profile)
    cert_req: dict[str, Any] = profile.get('certificate_request', {})
    cert_profile: str = cert_req.get('certificate_profile', 'domain_credential')

    enrollment_path = _resolve_enrollment_url(agent, cert_profile)
    if enrollment_path is not None:
        cert_req['path'] = enrollment_path

    if assigned_profile.subject and assigned_profile.subject.strip():
        cert_req['subject'] = assigned_profile.subject
    else:
        cert_req.pop('subject', None)

    if assigned_profile.subject_alt_name and assigned_profile.subject_alt_name.strip():
        cert_req['subject_alt_name'] = assigned_profile.subject_alt_name
    else:
        cert_req.pop('subject_alt_name', None)

    public_key_info = None
    if agent.device and agent.device.domain:
        public_key_info = agent.device.domain.public_key_info

    if public_key_info:
        cert_req['public_key_algorithm_oid'] = str(public_key_info.public_key_algorithm_oid.dotted_string)
        if public_key_info.key_size:
            cert_req['key_parameter'] = str(public_key_info.key_size)
        elif public_key_info.named_curve:
            cert_req['key_parameter'] = public_key_info.named_curve.name
        else:
            cert_req.pop('key_parameter', None)
    else:
        for key in ('public_key_algorithm_oid', 'key_parameter'):
            cert_req.pop(key, None)

    profile['certificate_request'] = cert_req
    return profile

class IsAuthenticatedAgent(BasePermission):
    """Allow access only to requests authenticated as a :class:`~agents.models.TrustpointAgent`."""

    def has_permission(self, request: Request, view: Any) -> bool:  # noqa: ARG002
        """Return ``True`` iff the request was authenticated as a ``TrustpointAgent``."""
        return isinstance(request.user, TrustpointAgent)


class AgentJobSerializer(serializers.Serializer):  # type: ignore[type-arg]
    """Serializer for a single pending job entry returned by the jobs endpoint."""

    profile_id = serializers.IntegerField(
        help_text='Primary key of the AgentAssignedProfile record.',
    )
    workflow_definition_id = serializers.IntegerField(
        help_text='Primary key of the linked AgentProfileDefinition.',
    )
    workflow_definition_name = serializers.CharField(
        help_text='Human-readable name of the workflow definition.',
    )
    workflow_profile = serializers.DictField(
        child=serializers.JSONField(),
        help_text='Full profile JSON from the AgentProfileDefinition (metadata, device, certificate_request, steps).',
    )
    next_certificate_update = serializers.DateTimeField(
        help_text='ISO-8601 datetime at which renewal was / is due.',
    )


class AgentJobsResponseSerializer(serializers.Serializer):  # type: ignore[type-arg]
    """Response envelope returned by :class:`AgentJobsView`."""

    agent_id = serializers.CharField(
        help_text='Stable identifier of the authenticated agent.',
    )
    poll_interval_seconds = serializers.IntegerField(
        help_text='How many seconds the agent should wait before the next poll.',
    )
    jobs = AgentJobSerializer(
        many=True,
        help_text='List of AgentAssignedProfile records that are currently due for renewal.',
    )


@extend_schema(tags=['Agents'])
class AgentJobsView(LoggerMixin, APIView):
    """Return the list of pending renewal jobs for the authenticated agent."""

    authentication_classes = (AgentCertificateAuthentication,)
    permission_classes = (IsAuthenticatedAgent,)

    @extend_schema(
        summary='Poll for pending certificate-renewal jobs',
        description=(
            'Returns all enabled AgentAssignedProfile records that are due for renewal '
            '(next_certificate_update ≤ now).  The agent should authenticate using its '
            'domain credential certificate; the TLS terminator must forward the '
            'SHA-256 fingerprint via the X-SSL-Client-Fingerprint header.\n\n'
            'After processing the returned jobs the agent should call the '
            'job-acknowledgement endpoint so that last_certificate_update is updated '
            'and the job leaves the pending queue.'
        ),
        responses={
            200: AgentJobsResponseSerializer,
            401: OpenApiResponse(description='Unauthenticated - missing or unknown client certificate fingerprint'),
            403: OpenApiResponse(description='Forbidden - principal is not an active agent'),
        },
        examples=[
            OpenApiExample(
                name='Pending job',
                value={
                    'agent_id': 'cell-a-agent-1',
                    'poll_interval_seconds': 300,
                    'jobs': [
                        {
                            'profile_id': 42,
                            'workflow_definition_id': 7,
                            'workflow_definition_name': 'Domain Credential Update',
                            'workflow_profile': {
                                'metadata': {'agent_type': 'wbm_cert_push', 'version': '1.0.0'},
                                'device': {'vendor': 'Siemens', 'device_family': 'S7-1500'},
                                'certificate_request': {
                                    'certificate_profile': 'tls_client',
                                    'url': 'https://trustpoint.local/api/pki/enroll/',
                                    'path': '/certs/client.pem',
                                },
                                'steps': [],
                            },
                            'next_certificate_update': '2024-01-15T10:00:00Z',
                        }
                    ],
                },
                response_only=True,
            ),
        ],
    )
    def get(self, request: Request) -> Response:
        """Return pending renewal jobs for the authenticated agent."""
        agent: TrustpointAgent = request.user  # type: ignore[assignment]

        TrustpointAgent.objects.filter(pk=agent.pk).update(last_seen_at=timezone.now())

        now = timezone.now()

        assigned_profiles = (
            AgentAssignedProfile.objects.filter(agent=agent, enabled=True)
            .select_related('workflow_definition', 'agent__device__domain')
        )

        pending_jobs: list[dict[str, Any]] = []
        for profile in assigned_profiles:
            due_at = profile.next_certificate_update
            if due_at <= now:
                self.logger.debug(
                    'Agent %s: profile %d (%s) is due since %s',
                    agent.agent_id,
                    profile.pk,
                    profile.workflow_definition.name,
                    due_at.isoformat(),
                )
                resolved_profile = _build_resolved_profile(
                    agent, profile.workflow_definition.profile, profile
                )
                pending_jobs.append({
                    'profile_id': profile.pk,
                    'workflow_definition_id': profile.workflow_definition.pk,
                    'workflow_definition_name': profile.workflow_definition.name,
                    'workflow_profile': resolved_profile,
                    'next_certificate_update': due_at,
                })

        self.logger.info(
            'Agent %s checked in: %d pending job(s)',
            agent.agent_id,
            len(pending_jobs),
        )

        response_data = {
            'agent_id': agent.agent_id,
            'poll_interval_seconds': agent.poll_interval_seconds,
            'jobs': pending_jobs,
        }
        serializer = AgentJobsResponseSerializer(response_data)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AgentJobResultRequestSerializer(serializers.Serializer):  # type: ignore[type-arg]
    """Request body for :class:`AgentJobResultView`."""

    profile_id = serializers.IntegerField(
        help_text='Primary key of the AgentAssignedProfile that was executed.',
    )
    success = serializers.BooleanField(
        help_text=(
            'True when the job completed successfully (certificate was renewed). '
            'False when the job failed and should remain in the pending queue.'
        ),
    )
    error_message = serializers.CharField(
        required=False,
        allow_blank=True,
        default='',
        help_text='Human-readable error description. Only relevant when success is False.',
    )


class AgentJobResultResponseSerializer(serializers.Serializer):  # type: ignore[type-arg]
    """Response body returned by :class:`AgentJobResultView`."""

    profile_id = serializers.IntegerField(
        help_text='Primary key of the AgentAssignedProfile that was updated.',
    )
    last_certificate_update = serializers.DateTimeField(
        allow_null=True,
        help_text='Timestamp of the most recent successful certificate update, or null if none yet.',
    )
    next_certificate_update = serializers.DateTimeField(
        help_text='Computed datetime at which the next renewal will be triggered.',
    )

@extend_schema(tags=['Agents'])
class AgentJobResultView(LoggerMixin, APIView):
    """Accept the outcome of a job execution from an authenticated agent."""

    authentication_classes = (AgentCertificateAuthentication,)
    permission_classes = (IsAuthenticatedAgent,)

    @extend_schema(
        summary='Report the result of a job execution',
        description=(
            'The agent calls this endpoint after attempting to execute a job. '
            'On success Trustpoint stamps last_certificate_update and clears the '
            'scheduled override so the profile moves to its normal renewal cadence. '
            'On failure the profile remains due and will reappear on the next poll.'
        ),
        request=AgentJobResultRequestSerializer,
        responses={
            200: AgentJobResultResponseSerializer,
            400: OpenApiResponse(description='Bad Request - validation error in request body'),
            401: OpenApiResponse(description='Unauthenticated - missing or unrecognised client certificate'),
            403: OpenApiResponse(description='Forbidden - profile does not belong to this agent'),
            404: OpenApiResponse(description='Not Found - profile_id does not exist'),
        },
        examples=[
            OpenApiExample(
                name='Successful job result',
                value={'profile_id': 42, 'success': True},
                request_only=True,
            ),
            OpenApiExample(
                name='Failed job result',
                value={
                    'profile_id': 42,
                    'success': False,
                    'error_message': 'WBM login timed out after 30 s',
                },
                request_only=True,
            ),
            OpenApiExample(
                name='Acknowledgement response',
                value={
                    'profile_id': 42,
                    'last_certificate_update': '2026-03-25T10:00:00Z',
                    'next_certificate_update': '2026-04-24T10:00:00Z',
                },
                response_only=True,
            ),
        ],
    )
    def post(self, request: Request) -> Response:
        """Process a job result posted by the authenticated agent."""
        agent: TrustpointAgent = request.user  # type: ignore[assignment]

        TrustpointAgent.objects.filter(pk=agent.pk).update(last_seen_at=timezone.now())

        serializer = AgentJobResultRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        profile_id: int = serializer.validated_data['profile_id']
        success: bool = serializer.validated_data['success']
        error_message: str = serializer.validated_data.get('error_message', '')

        profile: AgentAssignedProfile | None = (
            AgentAssignedProfile.objects.filter(pk=profile_id)
            .select_related('workflow_definition')
            .first()
        )

        if profile is None:
            return Response(
                {'detail': f'AgentAssignedProfile {profile_id} not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        if profile.agent_id != agent.pk:
            self.logger.warning(
                'Agent %s attempted to report result for profile %d owned by agent %d',
                agent.agent_id,
                profile_id,
                profile.agent_id,
            )
            return Response(
                {'detail': 'This profile does not belong to the authenticated agent.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        if success:
            now = timezone.now()
            profile.last_certificate_update = now
            # Calculate next update based on renewal threshold
            next_update = now + timedelta(days=profile.renewal_threshold_days)
            profile.next_certificate_update_scheduled = next_update
            profile.save(update_fields=['last_certificate_update', 'next_certificate_update_scheduled'])
            self.logger.info(
                'Agent %s: profile %d (%s) completed successfully at %s, next update: %s',
                agent.agent_id,
                profile_id,
                profile.workflow_definition.name,
                now.isoformat(),
                next_update.isoformat(),
            )
        else:
            self.logger.warning(
                'Agent %s: profile %d (%s) reported failure: %s',
                agent.agent_id,
                profile_id,
                profile.workflow_definition.name,
                error_message or '(no message)',
            )

        response_data = {
            'profile_id': profile.pk,
            'last_certificate_update': profile.last_certificate_update,
            'next_certificate_update': profile.next_certificate_update,
        }
        return Response(
            AgentJobResultResponseSerializer(response_data).data,
            status=status.HTTP_200_OK,
        )
