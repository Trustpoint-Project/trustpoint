# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Capabilities endpoint for advertising supported operations and management methods."""

from typing import Any, ClassVar

from drf_spectacular.utils import extend_schema
from rest_framework import status, viewsets
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response

from crypto.models import CryptoProviderProfileModel
from management.models import SecurityConfig
from onboarding.enums import NoOnboardingPkiProtocol, OnboardingProtocol
from trustpoint.logger import LoggerMixin


@extend_schema(tags=['Capabilities'])
class CapabilitiesViewSet(LoggerMixin, viewsets.GenericViewSet[Any]):
    """ViewSet for advertising system capabilities."""

    permission_classes: ClassVar = [AllowAny]  # type: ignore[misc]
    filter_backends: ClassVar = ()  # type: ignore[misc]

    def _get_protocol_availability(self) -> dict[str, dict[str, bool]]:
        """Check protocol availability from SecurityConfig."""
        onboarding = {
            'manual': True,
            'cmp_idevid': True,
            'cmp_shared_secret': True,
            'est_idevid': True,
            'est_username_password': True,
            'aoki': True,
            'brski': True,
            'opc_gds_push': True,
            'rest_username_password': True,
            'agent': True,
        }
        no_onboarding = {
            'cmp_shared_secret': True,
            'est_username_password': True,
            'manual': True,
            'rest_username_password': True,
        }

        security_config: SecurityConfig | None = None
        try:
            security_config = SecurityConfig.objects.get()
        except SecurityConfig.DoesNotExist:
            return {'onboarding': onboarding, 'no_onboarding': no_onboarding}
        except SecurityConfig.MultipleObjectsReturned:
            security_config = SecurityConfig.objects.first()
            if not security_config:
                return {'onboarding': onboarding, 'no_onboarding': no_onboarding}

        no_onb_protocols = security_config.permitted_no_onboarding_pki_protocols
        onb_protocols = security_config.permitted_onboarding_protocols

        no_onboarding = {
            'cmp_shared_secret': NoOnboardingPkiProtocol.CMP_SHARED_SECRET in no_onb_protocols,
            'est_username_password': NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD in no_onb_protocols,
            'manual': NoOnboardingPkiProtocol.MANUAL in no_onb_protocols,
            'rest_username_password': NoOnboardingPkiProtocol.REST_USERNAME_PASSWORD in no_onb_protocols,
        }

        onboarding = {
            'manual': OnboardingProtocol.MANUAL in onb_protocols,
            'cmp_idevid': OnboardingProtocol.CMP_IDEVID in onb_protocols,
            'cmp_shared_secret': OnboardingProtocol.CMP_SHARED_SECRET in onb_protocols,
            'est_idevid': OnboardingProtocol.EST_IDEVID in onb_protocols,
            'est_username_password': OnboardingProtocol.EST_USERNAME_PASSWORD in onb_protocols,
            'aoki': OnboardingProtocol.AOKI in onb_protocols,
            'brski': OnboardingProtocol.BRSKI in onb_protocols,
            'opc_gds_push': OnboardingProtocol.OPC_GDS_PUSH in onb_protocols,
            'rest_username_password': OnboardingProtocol.REST_USERNAME_PASSWORD in onb_protocols,
            'agent': OnboardingProtocol.AGENT in onb_protocols,
        }

        return {'onboarding': onboarding, 'no_onboarding': no_onboarding}

    @extend_schema(
        summary='Get system capabilities',
        description=(
            'Returns information about supported protocols, operations, and management methods. '
            'This endpoint allows clients to discover what features are available in this Trustpoint instance.'
        ),
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'protocols': {
                        'type': 'object',
                        'properties': {
                            'onboarding': {
                                'type': 'object',
                                'properties': {
                                    'manual': {'type': 'boolean', 'example': True},
                                    'cmp_idevid': {'type': 'boolean', 'example': True},
                                    'cmp_shared_secret': {'type': 'boolean', 'example': True},
                                    'est_idevid': {'type': 'boolean', 'example': True},
                                    'est_username_password': {'type': 'boolean', 'example': True},
                                    'aoki': {'type': 'boolean', 'example': True},
                                    'brski': {'type': 'boolean', 'example': True},
                                    'opc_gds_push': {'type': 'boolean', 'example': True},
                                    'rest_username_password': {'type': 'boolean', 'example': True},
                                    'agent': {'type': 'boolean', 'example': True},
                                },
                            },
                            'no_onboarding': {
                                'type': 'object',
                                'properties': {
                                    'cmp_shared_secret': {'type': 'boolean', 'example': True},
                                    'est_username_password': {'type': 'boolean', 'example': True},
                                    'manual': {'type': 'boolean', 'example': True},
                                    'rest_username_password': {'type': 'boolean', 'example': True},
                                },
                            },
                        },
                    },
                    'crypto_backend': {
                        'type': 'object',
                        'properties': {
                            'kind': {'type': 'string', 'example': 'software'},
                            'active': {'type': 'boolean', 'example': True},
                        },
                    },
                },
            },
        },
    )
    def list(self, _request: Request) -> Response:
        """Return system capabilities."""
        protocol_availability = self._get_protocol_availability()

        crypto_backend_kind = None
        crypto_backend_active = False

        try:
            active_profile = CryptoProviderProfileModel.objects.filter(active=True).first()
            if active_profile:
                crypto_backend_kind = active_profile.backend_kind
                crypto_backend_active = True
        except Exception:
            self.logger.exception('Failed to retrieve crypto backend information')

        capabilities = {
            'protocols': protocol_availability,
            'crypto_backend': {
                'kind': crypto_backend_kind,
                'active': crypto_backend_active,
            },
        }

        return Response(capabilities, status=status.HTTP_200_OK)
