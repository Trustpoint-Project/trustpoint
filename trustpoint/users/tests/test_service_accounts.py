# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for service account functionality."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from users.authentication import ServiceAccountBackend
from users.models import ServiceAccountCredential, TrustpointUser

if TYPE_CHECKING:
    from management.models.organization import OrganizationModel


@pytest.fixture
def organization(db: object) -> OrganizationModel:
    """Create a test organization."""
    from management.models import OrganizationModel
    return OrganizationModel.objects.create(name='TestOrg', organization='testorg')


@pytest.fixture
def service_role(db: object) -> Group:
    """Create a role for service accounts."""
    return Group.objects.create(name='ServiceRole')


@pytest.fixture
def service_account(db: object, service_role: Group, organization: OrganizationModel) -> TrustpointUser:
    """Create a service account."""
    account = TrustpointUser.objects.create(
        username='test_service',
        account_type=TrustpointUser.AccountType.SERVICE,
        role=service_role,
        organization=organization,
    )
    account.set_unusable_password()
    account.save()
    return account


@pytest.fixture
def service_credential(db: object, service_account: TrustpointUser) -> tuple[ServiceAccountCredential, str]:
    """Create an API key credential for the service account."""
    client_id = ServiceAccountCredential.generate_client_id()
    secret = ServiceAccountCredential.generate_secret()
    hashed_secret = make_password(secret)

    credential = ServiceAccountCredential.objects.create(
        service_account=service_account,
        client_id=client_id,
        hashed_secret=hashed_secret,
        description='Test credential',
    )
    return credential, secret


@pytest.mark.django_db
class TestTrustpointUser:
    """Tests for TrustpointUser model with service accounts."""

    def test_service_account_creation(self, service_role: Group, organization: OrganizationModel) -> None:
        """Test creating a service account."""
        account = TrustpointUser.objects.create(
            username='service1',
            account_type=TrustpointUser.AccountType.SERVICE,
            role=service_role,
            organization=organization,
        )

        assert account.account_type == TrustpointUser.AccountType.SERVICE
        assert not account.is_staff
        assert not account.is_superuser

    def test_service_account_cannot_be_staff(self, service_account: TrustpointUser) -> None:
        """Test that service accounts cannot be staff."""
        service_account.is_staff = True
        service_account.is_superuser = True

        with pytest.raises(ValidationError, match='Service accounts cannot be staff or superusers'):
            service_account.full_clean()

    def test_service_account_flags_forced_to_false_on_save(
        self,
        service_account: TrustpointUser
    ) -> None:
        """Test that is_staff and is_superuser are forced to False on save."""
        service_account.is_staff = True
        service_account.is_superuser = True
        service_account.save()

        service_account.refresh_from_db()
        assert not service_account.is_staff
        assert not service_account.is_superuser

    def test_human_account_str_representation(self, service_role: Group, organization: OrganizationModel) -> None:
        """Test string representation of human account."""
        account = TrustpointUser.objects.create(
            username='human1',
            account_type=TrustpointUser.AccountType.HUMAN,
            role=service_role,
            organization=organization,
        )

        assert str(account) == 'Username: human1, Role: ServiceRole'

    def test_service_account_str_representation(self, service_account: TrustpointUser) -> None:
        """Test string representation of service account."""
        result = str(service_account)
        assert 'test_service' in result
        assert 'Service' in result


@pytest.mark.django_db
class TestServiceAccountCredential:
    """Tests for ServiceAccountCredential model."""

    def test_credential_creation(self, service_credential: tuple[ServiceAccountCredential, str]) -> None:
        """Test creating a service account credential."""
        credential, secret = service_credential

        assert credential.client_id.startswith('sa_')
        assert credential.is_active
        assert credential.is_valid()

    def test_client_id_generation(self) -> None:
        """Test client ID generation."""
        client_id = ServiceAccountCredential.generate_client_id()

        assert client_id.startswith('sa_')
        assert len(client_id) > 40  # URL-safe base64 encoded token

    def test_secret_generation(self) -> None:
        """Test secret generation."""
        secret = ServiceAccountCredential.generate_secret()

        assert len(secret) > 60  # URL-safe base64 encoded token

    def test_credential_expiration(
        self,
        service_account: TrustpointUser
    ) -> None:
        """Test credential expiration."""
        past_time = timezone.now() - timedelta(days=1)

        credential = ServiceAccountCredential.objects.create(
            service_account=service_account,
            client_id=ServiceAccountCredential.generate_client_id(),
            hashed_secret=make_password('test_secret'),
            expires_at=past_time,
        )

        assert not credential.is_valid()

    def test_credential_inactive(
        self,
        service_credential: tuple[ServiceAccountCredential, str]
    ) -> None:
        """Test inactive credential."""
        credential, _ = service_credential
        credential.is_active = False
        credential.save()

        assert not credential.is_valid()

    def test_record_usage(
        self,
        service_credential: tuple[ServiceAccountCredential, str]
    ) -> None:
        """Test recording credential usage."""
        credential, _ = service_credential
        assert credential.last_used is None

        credential.record_usage()
        credential.refresh_from_db()

        assert credential.last_used is not None

    def test_credential_requires_service_account(
        self,
        service_role: Group,
        organization: OrganizationModel
    ) -> None:
        """Test that credentials can only be associated with service accounts."""
        human_account = TrustpointUser.objects.create(
            username='human1',
            account_type=TrustpointUser.AccountType.HUMAN,
            role=service_role,
            organization=organization,
        )

        credential = ServiceAccountCredential(
            service_account=human_account,
            client_id=ServiceAccountCredential.generate_client_id(),
            hashed_secret=make_password('test'),
        )

        with pytest.raises(ValidationError, match='Credentials can only be associated with service accounts'):
            credential.full_clean()


@pytest.mark.django_db
class TestServiceAccountBackend:
    """Tests for ServiceAccountBackend authentication."""

    def test_successful_authentication(
        self,
        service_credential: tuple[ServiceAccountCredential, str]
    ) -> None:
        """Test successful service account authentication."""
        credential, secret = service_credential
        backend = ServiceAccountBackend()

        user = backend.authenticate(
            request=None,
            client_id=credential.client_id,
            secret=secret,
        )

        assert user is not None
        assert user == credential.service_account

    def test_authentication_with_invalid_client_id(self) -> None:
        """Test authentication with invalid client ID."""
        backend = ServiceAccountBackend()

        user = backend.authenticate(
            request=None,
            client_id='invalid_id',
            secret='invalid_secret',
        )

        assert user is None

    def test_authentication_with_invalid_secret(
        self,
        service_credential: tuple[ServiceAccountCredential, str]
    ) -> None:
        """Test authentication with invalid secret."""
        credential, _ = service_credential
        backend = ServiceAccountBackend()

        user = backend.authenticate(
            request=None,
            client_id=credential.client_id,
            secret='wrong_secret',
        )

        assert user is None

    def test_authentication_with_inactive_credential(
        self,
        service_credential: tuple[ServiceAccountCredential, str]
    ) -> None:
        """Test authentication with inactive credential."""
        credential, secret = service_credential
        credential.is_active = False
        credential.save()

        backend = ServiceAccountBackend()
        user = backend.authenticate(
            request=None,
            client_id=credential.client_id,
            secret=secret,
        )

        assert user is None

    def test_authentication_with_expired_credential(
        self,
        service_account: TrustpointUser
    ) -> None:
        """Test authentication with expired credential."""
        client_id = ServiceAccountCredential.generate_client_id()
        secret = ServiceAccountCredential.generate_secret()

        credential = ServiceAccountCredential.objects.create(
            service_account=service_account,
            client_id=client_id,
            hashed_secret=make_password(secret),
            expires_at=timezone.now() - timedelta(days=1),
        )

        backend = ServiceAccountBackend()
        user = backend.authenticate(
            request=None,
            client_id=credential.client_id,
            secret=secret,
        )

        assert user is None

    def test_get_user(self, service_account: TrustpointUser) -> None:
        """Test retrieving a user by ID."""
        backend = ServiceAccountBackend()
        user = backend.get_user(service_account.pk)

        assert user == service_account

    def test_get_user_not_found(self) -> None:
        """Test retrieving a non-existent user."""
        backend = ServiceAccountBackend()
        user = backend.get_user(999999)

        assert user is None


@pytest.mark.django_db
class TestServiceAccountAPI:
    """Tests for service account API authentication."""

    def test_api_authentication_with_service_account(
        self,
        service_credential: tuple[ServiceAccountCredential, str]
    ) -> None:
        """Test API authentication using service account credentials via OAuth 2.0."""
        credential, secret = service_credential
        client = APIClient()

        # Use OAuth 2.0 client credentials grant
        response = client.post('/api/token/', {
            'grant_type': 'client_credentials',
            'client_id': credential.client_id,
            'client_secret': secret,
        })

        # Should get access token
        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data
        assert 'token_type' in response.data
        assert response.data['token_type'] == 'Bearer'

    def test_api_authentication_with_invalid_format(self) -> None:
        """Test API authentication with invalid credentials."""
        client = APIClient()

        response = client.post('/api/token/', {
            'grant_type': 'client_credentials',
            'client_id': 'invalid_client',
            'client_secret': 'invalid_secret',
        })
        # Should get authentication error
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_api_authentication_missing_credentials(self) -> None:
        """Test API request without credentials."""
        client = APIClient()

        response = client.post('/api/token/', {
            'grant_type': 'client_credentials',
        })
        # Should get bad request error for missing required fields
        assert response.status_code == status.HTTP_400_BAD_REQUEST
