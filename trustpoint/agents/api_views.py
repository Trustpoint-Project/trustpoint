# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""DRF API views for the Trustpoint agent job-polling endpoint."""

from __future__ import annotations

import copy
import re
import urllib.parse
import uuid
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from cryptography import x509
from django.db.models import Q
from django.utils import timezone
from drf_spectacular.extensions import OpenApiAuthenticationExtension
from drf_spectacular.utils import OpenApiExample, OpenApiResponse, extend_schema
from rest_framework import serializers, status
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import AgentAssignedProfile, TrustpointAgent
from agents.security import AgentSecurity
from devices.models import DeviceModel
from request.request_validator.http_req import TrustedProxyHeadersValidation
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from collections.abc import Callable

    from rest_framework.request import Request

JOB_LEASE_SECONDS = 1800
MAX_ERROR_LENGTH = 2000


class AgentCertificateAuthenticationScheme(OpenApiAuthenticationExtension):  # type: ignore[no-untyped-call]
    """Describe the proxy-forwarded agent client certificate in the generated schema."""

    target_class = 'agents.api_views.AgentCertificateAuthentication'
    name = 'agentProxyCertificate'

    def get_security_definition(self, auto_schema: object) -> dict[str, str]:  # noqa: ARG002
        """Return the forwarded client-certificate security scheme."""
        return {
            'type': 'apiKey',
            'in': 'header',
            'name': 'SSL-Client-Cert',
            'description': (
                'mTLS client certificate added by the trusted TLS proxy after validating the client. '
                'Clients must not send this header directly.'
            ),
        }


_SECRET_PLACEHOLDER = re.compile(r'\{\{\s*secret:([A-Za-z0-9_.-]+)\s*\}\}')
_PLACEHOLDER = re.compile(r'\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}')


def _parse_client_cert(request: Request) -> x509.Certificate | None:
    """Extract and parse the client certificate from the Django request META."""
    raw: str | None = request.META.get('HTTP_SSL_CLIENT_CERT')
    if not raw or not raw.strip():
        return None

    try:
        TrustedProxyHeadersValidation().validate_request_peer(request)
        pem_bytes = urllib.parse.unquote(raw).encode('utf-8')
        return x509.load_pem_x509_certificate(pem_bytes)
    except Exception as exc:
        msg = 'Invalid HTTP_SSL_CLIENT_CERT header.'
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
                TrustpointAgent.objects.select_related('device__domain').filter(device=device, is_active=True).first()
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


def _map_strings(value: Any, mapper: Callable[[str], str]) -> Any:
    """Recursively apply *mapper* to every string in a JSON-like value."""
    if isinstance(value, str):
        return mapper(value)
    if isinstance(value, list):
        return [_map_strings(item, mapper) for item in value]
    if isinstance(value, dict):
        return {key: _map_strings(item, mapper) for key, item in value.items()}
    return value


def _resolve_named_placeholders(value: Any, mapping: dict[str, Any]) -> Any:
    """Recursively replace known ``{{ name }}`` placeholders."""
    return _map_strings(
        value,
        lambda text: _PLACEHOLDER.sub(lambda match: str(mapping.get(match.group(1), match.group(0))), text),
    )


def _resolve_secrets(value: Any, secrets: dict[str, str]) -> Any:
    """Recursively replace ``{{ secret:name }}`` references with decrypted values."""
    return _map_strings(
        value,
        lambda text: _SECRET_PLACEHOLDER.sub(lambda match: str(secrets.get(match.group(1), '')), text),
    )


def _build_resolved_profile(  # noqa: C901, PLR0912 - one pass over the profile's known fields.
    agent: TrustpointAgent,
    raw_profile: dict[str, Any],
    assigned_profile: AgentAssignedProfile,
) -> dict[str, Any]:
    """Return a deep copy of *raw_profile* with placeholders and secrets resolved.

    Resolves:
    - ``certificate_request.path`` → enrollment endpoint path
    - ``certificate_request.subject`` → subject DN from assigned_profile
    - ``certificate_request.subject_alt_name`` → SAN extension from assigned_profile
    - ``certificate_request.public_key_algorithm_oid`` → OID from domain's issuing CA
    - ``certificate_request.key_parameter`` → RSA key size or ECC curve name
    - ``local_storage`` paths → ``os_path``, ``certificate_profile``, and ``profile_id``
    - ``{{ secret:name }}`` → decrypted value from the profile's encrypted secrets
    """
    profile = copy.deepcopy(raw_profile) if isinstance(raw_profile, dict) else {}
    raw_cert_req = profile.get('certificate_request')
    cert_req: dict[str, Any] = raw_cert_req if isinstance(raw_cert_req, dict) else {}
    cert_profile_value = cert_req.get('certificate_profile', 'domain_credential')
    cert_profile: str = cert_profile_value if isinstance(cert_profile_value, str) else 'domain_credential'

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

    domain_name = agent.device.domain.unique_name if agent.device and agent.device.domain else ''
    mapping = {
        'os_path': agent.os_path,
        'certificate_profile': cert_profile,
        'profile_id': assigned_profile.pk,
        'agent_id': agent.agent_id,
        'domain': domain_name,
    }
    if isinstance(cert_req.get('url'), str) and '{{' in cert_req['url']:
        cert_req.pop('url', None)
    profile['certificate_request'] = _resolve_named_placeholders(cert_req, mapping)

    local_storage = profile.get('local_storage')
    if isinstance(local_storage, dict):
        resolved_storage = _resolve_named_placeholders(local_storage, mapping)
        profile['local_storage'] = {
            key: value for key, value in resolved_storage.items() if not (isinstance(value, str) and '{{' in value)
        }

    workflow_definition = getattr(assigned_profile, 'workflow_definition', None)
    secrets = getattr(workflow_definition, 'secrets', None) if workflow_definition is not None else None
    if not isinstance(secrets, dict):
        secrets = {}
    resolved = _resolve_secrets(profile, secrets)
    return resolved if isinstance(resolved, dict) else {}


def next_update_after_success(
    assigned_profile: AgentAssignedProfile,
    now: datetime,
) -> datetime:
    """Schedule the next renewal from certificate expiry, with a safe fallback."""
    next_update = assigned_profile.next_update_from_certificate(now)
    if next_update is not None:
        return next_update
    return now + timedelta(days=max(int(assigned_profile.renewal_threshold_days), 1))


def _failure_backoff_seconds(assigned_profile: AgentAssignedProfile) -> int:
    """Return an increasing retry delay capped at one hour."""
    poll_interval = max(int(assigned_profile.agent.poll_interval_seconds), 60)
    return int(min(2 ** min(assigned_profile.failure_count, 6) * poll_interval, 3600))


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
    job_token = serializers.UUIDField(
        required=False,
        allow_null=True,
        help_text='Return this token in the job-result request to acknowledge this claim.',
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
            '(next_certificate_update ≤ now).  The agent authenticates with its '
            'domain credential using mutual TLS.  The trusted TLS terminator must forward '
            'the URL-encoded client certificate PEM in the SSL-Client-Cert header, and '
            'the direct peer must be listed in TRUSTPOINT_TRUSTED_PROXY_IPS.\n\n'
            'Each returned job is claimed by the agent.  After processing it, call the '
            'job-acknowledgement endpoint with the returned job_token so that '
            'last_certificate_update is updated and the job leaves the pending queue.'
        ),
        responses={
            200: AgentJobsResponseSerializer,
            401: OpenApiResponse(description='Unauthenticated - missing or unknown client certificate'),
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
                            'job_token': '6f3f1e0e-5b8a-4c1f-9f3a-3f1c2b7a9d10',
                        }
                    ],
                },
                response_only=True,
            ),
        ],
    )
    def get(self, request: Request) -> Response:
        """Return pending renewal jobs for the authenticated agent."""
        if not AgentSecurity.is_agent_protocol_permitted():
            return Response(
                {'detail': 'Agent functionality is disabled by the current security configuration.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        agent: TrustpointAgent = request.user  # type: ignore[assignment]

        TrustpointAgent.objects.filter(pk=agent.pk).update(last_seen_at=timezone.now())

        now = timezone.now()

        assigned_profiles = (
            AgentAssignedProfile.objects.filter(
                agent=agent,
                enabled=True,
                workflow_definition__is_active=True,
            )
            .select_related('workflow_definition', 'agent__device__domain')
            .defer('workflow_definition__secrets')
        )

        lease_cutoff = now - timedelta(seconds=JOB_LEASE_SECONDS)
        pending_jobs: list[dict[str, Any]] = []
        for profile in assigned_profiles:
            due_at = profile.next_certificate_update
            if due_at > now:
                continue
            claim_token = uuid.uuid4()
            claimed = (
                AgentAssignedProfile.objects.filter(
                    pk=profile.pk,
                    enabled=True,
                    workflow_definition__is_active=True,
                )
                .filter(Q(claimed_at__isnull=True) | Q(claimed_at__lt=lease_cutoff))
                .update(claimed_at=now, claim_token=claim_token)
            )
            if not claimed:
                continue

            self.logger.debug(
                'Agent %s: profile %d (%s) is due since %s',
                agent.agent_id,
                profile.pk,
                profile.workflow_definition.name,
                due_at.isoformat(),
            )
            try:
                resolved_profile = _build_resolved_profile(agent, profile.workflow_definition.profile, profile)
            except Exception:
                AgentAssignedProfile.objects.filter(pk=profile.pk, claim_token=claim_token).update(
                    claimed_at=None,
                    claim_token=None,
                )
                self.logger.exception('Agent %s: could not build profile %d', agent.agent_id, profile.pk)
                continue

            pending_jobs.append(
                {
                    'profile_id': profile.pk,
                    'workflow_definition_id': profile.workflow_definition.pk,
                    'workflow_definition_name': profile.workflow_definition.name,
                    'workflow_profile': resolved_profile,
                    'next_certificate_update': due_at,
                    'job_token': claim_token,
                }
            )
            # One claim per poll: a slow first job must not let later claims expire.
            break

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
    job_token = serializers.UUIDField(
        required=False,
        allow_null=True,
        help_text='Claim token returned by the jobs endpoint. Required for claimed jobs.',
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
            'The agent calls this endpoint after attempting to execute a claimed job. '
            'On success Trustpoint stamps last_certificate_update, clears the claim, and '
            'schedules the next renewal from the certificate expiry minus the threshold. '
            'On failure the claim is cleared, the error is stored, and the job is retried '
            'with exponential backoff.'
        ),
        request=AgentJobResultRequestSerializer,
        responses={
            200: AgentJobResultResponseSerializer,
            400: OpenApiResponse(description='Bad Request - validation error in request body'),
            401: OpenApiResponse(description='Unauthenticated - missing or unrecognised client certificate'),
            403: OpenApiResponse(description='Forbidden - profile does not belong to this agent'),
            404: OpenApiResponse(description='Not Found - profile_id does not exist'),
            409: OpenApiResponse(description='Conflict - the job claim token is stale'),
        },
        examples=[
            OpenApiExample(
                name='Successful job result',
                value={
                    'profile_id': 42,
                    'success': True,
                    'job_token': '6f3f1e0e-5b8a-4c1f-9f3a-3f1c2b7a9d10',
                },
                request_only=True,
            ),
            OpenApiExample(
                name='Failed job result',
                value={
                    'profile_id': 42,
                    'success': False,
                    'error_message': 'WBM login timed out after 30 s',
                    'job_token': '6f3f1e0e-5b8a-4c1f-9f3a-3f1c2b7a9d10',
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
    def post(self, request: Request) -> Response:  # noqa: PLR0911 - explicit HTTP error responses.
        """Process a job result posted by the authenticated agent."""
        if not AgentSecurity.is_agent_protocol_permitted():
            return Response(
                {'detail': 'Agent functionality is disabled by the current security configuration.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        agent: TrustpointAgent = request.user  # type: ignore[assignment]

        TrustpointAgent.objects.filter(pk=agent.pk).update(last_seen_at=timezone.now())

        serializer = AgentJobResultRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        profile_id: int = serializer.validated_data['profile_id']
        success: bool = serializer.validated_data['success']
        error_message: str = serializer.validated_data.get('error_message', '')
        job_token = serializer.validated_data.get('job_token')

        profile: AgentAssignedProfile | None = (
            AgentAssignedProfile.objects.filter(pk=profile_id)
            .select_related('workflow_definition', 'agent__device__domain')
            .defer('workflow_definition__secrets')
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

        if job_token is not None and profile.claim_token is not None and profile.claim_token != job_token:
            self.logger.warning(
                'Agent %s reported a stale or invalid claim token for profile %d',
                agent.agent_id,
                profile_id,
            )
            return Response(
                {'detail': 'The job claim is no longer valid. Poll again for the current job.'},
                status=status.HTTP_409_CONFLICT,
            )

        now = timezone.now()
        if success:
            profile.last_certificate_update = now
            profile.last_attempt_at = now
            profile.last_error = ''
            profile.failure_count = 0
            next_update = next_update_after_success(profile, now)
            profile.next_certificate_update_scheduled = next_update
        else:
            profile.last_attempt_at = now
            profile.last_error = error_message[:MAX_ERROR_LENGTH]
            profile.failure_count += 1
            next_update = now + timedelta(seconds=_failure_backoff_seconds(profile))
            profile.next_certificate_update_scheduled = next_update

        updated = AgentAssignedProfile.objects.filter(pk=profile.pk, claim_token=profile.claim_token).update(
            last_certificate_update=profile.last_certificate_update,
            last_attempt_at=profile.last_attempt_at,
            last_error=profile.last_error,
            failure_count=profile.failure_count,
            next_certificate_update_scheduled=profile.next_certificate_update_scheduled,
            claimed_at=None,
            claim_token=None,
        )
        if not updated:
            return Response(
                {'detail': 'The job claim is no longer valid. Poll again for the current job.'},
                status=status.HTTP_409_CONFLICT,
            )

        if success:
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
                'Agent %s: profile %d (%s) reported failure: %s (retry after %s)',
                agent.agent_id,
                profile_id,
                profile.workflow_definition.name,
                error_message or '(no message)',
                next_update.isoformat(),
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
