# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the capabilities API endpoint."""

from django.test import TestCase
from rest_framework.test import APIClient

from management.models import SecurityConfig
from onboarding.enums import NoOnboardingPkiProtocol, OnboardingProtocol


class CapabilitiesViewSetTestCase(TestCase):
    """Test cases for the CapabilitiesViewSet."""

    def setUp(self) -> None:
        """Set up test client."""
        self.client = APIClient()

    def test_capabilities_endpoint_no_auth_required(self) -> None:
        """Test that the capabilities endpoint does not require authentication."""
        response = self.client.get('/api/capabilities/')
        assert response.status_code == 200

    def test_capabilities_response_structure(self) -> None:
        """Test that the capabilities response has the expected structure."""
        response = self.client.get('/api/capabilities/')
        assert response.status_code == 200

        data = response.json()
        assert 'protocols' in data
        assert 'crypto_backend' in data

        # Check protocols structure
        assert 'onboarding' in data['protocols']
        assert 'no_onboarding' in data['protocols']

        # Check onboarding protocols
        assert 'manual' in data['protocols']['onboarding']
        assert 'cmp_idevid' in data['protocols']['onboarding']
        assert 'cmp_shared_secret' in data['protocols']['onboarding']
        assert 'est_idevid' in data['protocols']['onboarding']
        assert 'est_username_password' in data['protocols']['onboarding']
        assert 'aoki' in data['protocols']['onboarding']
        assert 'brski' in data['protocols']['onboarding']
        assert 'opc_gds_push' in data['protocols']['onboarding']
        assert 'rest_username_password' in data['protocols']['onboarding']
        assert 'agent' in data['protocols']['onboarding']

        # Check no_onboarding protocols
        assert 'cmp_shared_secret' in data['protocols']['no_onboarding']
        assert 'est_username_password' in data['protocols']['no_onboarding']
        assert 'manual' in data['protocols']['no_onboarding']
        assert 'rest_username_password' in data['protocols']['no_onboarding']

        # Check crypto backend
        assert 'kind' in data['crypto_backend']
        assert 'active' in data['crypto_backend']

    def test_capabilities_with_security_config(self) -> None:
        """Test that capabilities reflect the SecurityConfig settings."""
        # Create a security config with limited protocols
        SecurityConfig.objects.create(
            security_mode=SecurityConfig.SecurityModeChoices.HARDENED,
            permitted_no_onboarding_pki_protocols=[
                NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD,
            ],
            permitted_onboarding_protocols=[
                OnboardingProtocol.EST_IDEVID,
            ],
        )

        response = self.client.get('/api/capabilities/')
        assert response.status_code == 200

        data = response.json()

        # Check onboarding protocols - only EST_IDEVID should be enabled
        assert data['protocols']['onboarding']['manual'] is False
        assert data['protocols']['onboarding']['cmp_idevid'] is False
        assert data['protocols']['onboarding']['cmp_shared_secret'] is False
        assert data['protocols']['onboarding']['est_idevid'] is True
        assert data['protocols']['onboarding']['est_username_password'] is False
        assert data['protocols']['onboarding']['aoki'] is False
        assert data['protocols']['onboarding']['brski'] is False
        assert data['protocols']['onboarding']['opc_gds_push'] is False
        assert data['protocols']['onboarding']['rest_username_password'] is False
        assert data['protocols']['onboarding']['agent'] is False

        # Check no_onboarding protocols - only EST_USERNAME_PASSWORD should be enabled
        assert data['protocols']['no_onboarding']['cmp_shared_secret'] is False
        assert data['protocols']['no_onboarding']['est_username_password'] is True
        assert data['protocols']['no_onboarding']['manual'] is False
        assert data['protocols']['no_onboarding']['rest_username_password'] is False

    def test_capabilities_default_when_no_config(self) -> None:
        """Test that all protocols are enabled when no SecurityConfig exists."""
        # Ensure no SecurityConfig exists
        SecurityConfig.objects.all().delete()

        response = self.client.get('/api/capabilities/')
        assert response.status_code == 200

        data = response.json()

        # All onboarding protocols should be enabled by default
        assert data['protocols']['onboarding']['manual'] is True
        assert data['protocols']['onboarding']['cmp_idevid'] is True
        assert data['protocols']['onboarding']['cmp_shared_secret'] is True
        assert data['protocols']['onboarding']['est_idevid'] is True
        assert data['protocols']['onboarding']['est_username_password'] is True
        assert data['protocols']['onboarding']['aoki'] is True
        assert data['protocols']['onboarding']['brski'] is True
        assert data['protocols']['onboarding']['opc_gds_push'] is True
        assert data['protocols']['onboarding']['rest_username_password'] is True
        assert data['protocols']['onboarding']['agent'] is True

        # All no_onboarding protocols should be enabled by default
        assert data['protocols']['no_onboarding']['cmp_shared_secret'] is True
        assert data['protocols']['no_onboarding']['est_username_password'] is True
        assert data['protocols']['no_onboarding']['manual'] is True
        assert data['protocols']['no_onboarding']['rest_username_password'] is True
