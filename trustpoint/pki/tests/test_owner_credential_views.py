"""Tests for newly added owner credential views."""

from __future__ import annotations

from typing import Any

import pytest
from django.contrib.auth.models import User
from django.test import Client
from django.urls import reverse

from onboarding.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol
from pki.models import OwnerCredentialModel
from pki.models.credential import CredentialModel, IDevIDReferenceModel
from pki.models import RemoteIssuedCredentialModel
from pki.models.truststore import TruststoreModel


@pytest.fixture(autouse=True)
def _enable_db(db: None) -> None:
    """Enable database access for all tests in this module."""


@pytest.fixture()
def admin_user() -> User:
    """Create a superuser for view access."""
    return User.objects.create_superuser(username='admin', email='admin@test.com', password='testpass123')


@pytest.fixture()
def auth_client(admin_user: User) -> Client:
    """Return a Django test Client with an authenticated superuser session."""
    client = Client()
    client.force_login(admin_user)
    return client


@pytest.fixture()
def owner_credential_local() -> OwnerCredentialModel:
    """Create a LOCAL OwnerCredentialModel (no remote config)."""
    return OwnerCredentialModel.objects.create(unique_name='local-oc')


@pytest.fixture()
def owner_credential_remote_est() -> OwnerCredentialModel:
    """Create a REMOTE_EST OwnerCredentialModel with a NoOnboardingConfig."""
    no_onboarding = NoOnboardingConfigModel(
        pki_protocols=NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD,
        est_password='secret',
    )
    no_onboarding.save()
    return OwnerCredentialModel.objects.create(
        unique_name='remote-oc',
        no_onboarding_config=no_onboarding,
        owner_credential_type=OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST,
        remote_host='est.example.com',
        remote_port=443,
        remote_path='/.well-known/est/simpleenroll',
        est_username='user',
    )


# ---------------------------------------------------------------------------
# OwnerCredentialTableView
# ---------------------------------------------------------------------------


class TestOwnerCredentialTableView:
    """Tests for the owner credentials list view."""

    def test_get_returns_200(self, auth_client: Client) -> None:
        """GET request renders successfully."""
        url = reverse('pki:owner_credentials')
        response = auth_client.get(url)
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# OwnerCredentialDetailView
# ---------------------------------------------------------------------------


class TestOwnerCredentialDetailView:
    """Tests for the owner credential detail view."""

    def test_get_returns_200(
        self, auth_client: Client, owner_credential_local: OwnerCredentialModel
    ) -> None:
        """GET request renders the detail page."""
        url = reverse('pki:owner_credentials-details', kwargs={'pk': owner_credential_local.pk})
        response = auth_client.get(url)
        assert response.status_code == 200

    def test_context_contains_idevid_refs(
        self, auth_client: Client, owner_credential_local: OwnerCredentialModel
    ) -> None:
        """Context includes the idevid_refs list."""
        IDevIDReferenceModel.objects.create(
            dev_owner_id=owner_credential_local,
            idevid_ref='dev-owner:SN.X509.FP',
        )
        url = reverse('pki:owner_credentials-details', kwargs={'pk': owner_credential_local.pk})
        response = auth_client.get(url)
        assert response.status_code == 200
        assert len(response.context['idevid_refs']) == 1


# ---------------------------------------------------------------------------
# OwnerCredentialAddMethodSelectView
# ---------------------------------------------------------------------------


class TestOwnerCredentialAddMethodSelectView:
    """Tests for the add-method selection view."""

    def test_get_returns_200(self, auth_client: Client) -> None:
        """GET renders the method selection page."""
        url = reverse('pki:owner_credentials-add')
        response = auth_client.get(url)
        assert response.status_code == 200

    def test_post_local_file_import_redirects(self, auth_client: Client) -> None:
        """POST with method_select=local_file_import redirects to the file import view."""
        url = reverse('pki:owner_credentials-add')
        response = auth_client.post(url, {'method_select': 'local_file_import'})
        assert response.status_code == 302
        assert 'file-import' in response.url  # type: ignore[union-attr]

    def test_post_unknown_method_redirects_back(self, auth_client: Client) -> None:
        """POST with an unknown method redirects back to the add page."""
        url = reverse('pki:owner_credentials-add')
        response = auth_client.post(url, {'method_select': 'unknown'})
        assert response.status_code == 302


# ---------------------------------------------------------------------------
# OwnerCredentialAddRequestEstMethodSelectView
# ---------------------------------------------------------------------------


class TestOwnerCredentialAddRequestEstMethodSelectView:
    """Tests for the EST method selection view."""

    def test_get_returns_200(self, auth_client: Client) -> None:
        """GET renders the EST method selection page."""
        url = reverse('pki:owner_credentials-add-est')
        response = auth_client.get(url)
        assert response.status_code == 200

    def test_post_no_onboarding_redirects(self, auth_client: Client) -> None:
        """POST with method_select=no_onboarding redirects to the no-onboarding form."""
        url = reverse('pki:owner_credentials-add-est')
        response = auth_client.post(url, {'method_select': 'no_onboarding'})
        assert response.status_code == 302
        assert 'no-onboarding' in response.url  # type: ignore[union-attr]

    def test_post_onboarding_redirects(self, auth_client: Client) -> None:
        """POST with method_select=onboarding redirects to the onboarding form."""
        url = reverse('pki:owner_credentials-add-est')
        response = auth_client.post(url, {'method_select': 'onboarding'})
        assert response.status_code == 302
        assert 'onboarding' in response.url  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# OwnerCredentialAddRequestEstNoOnboardingView
# ---------------------------------------------------------------------------


class TestOwnerCredentialAddRequestEstNoOnboardingView:
    """Tests for the EST no-onboarding enrollment view."""

    def test_get_returns_200(self, auth_client: Client) -> None:
        """GET renders the form page."""
        url = reverse('pki:owner_credentials-add-est-no-onboarding')
        response = auth_client.get(url)
        assert response.status_code == 200

    def test_valid_post_creates_owner_credential(self, auth_client: Client) -> None:
        """A valid POST creates an OwnerCredentialModel and redirects."""
        url = reverse('pki:owner_credentials-add-est-no-onboarding')
        data = {
            'unique_name': 'new-est-oc',
            'remote_host': 'est.example.com',
            'remote_port': 443,
            'remote_path': '/.well-known/est/simpleenroll',
            'key_type': 'ECC-SECP256R1',
            'est_username': 'admin',
            'est_password': 'secret',
        }
        response = auth_client.post(url, data)
        assert response.status_code == 302
        assert OwnerCredentialModel.objects.filter(unique_name='new-est-oc').exists()
        oc = OwnerCredentialModel.objects.get(unique_name='new-est-oc')
        assert oc.owner_credential_type == OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST
        assert oc.remote_host == 'est.example.com'
        # Should redirect to truststore association page
        assert 'truststore-association' in response.url  # type: ignore[union-attr]

    def test_invalid_post_returns_form(self, auth_client: Client) -> None:
        """A POST with missing required fields re-renders the form (200)."""
        url = reverse('pki:owner_credentials-add-est-no-onboarding')
        response = auth_client.post(url, {'unique_name': 'incomplete'})
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# OwnerCredentialTruststoreAssociationView
# ---------------------------------------------------------------------------


class TestOwnerCredentialTruststoreAssociationView:
    """Tests for the truststore association view."""

    def test_get_returns_200(
        self, auth_client: Client, owner_credential_remote_est: OwnerCredentialModel
    ) -> None:
        """GET renders the truststore association page."""
        url = reverse(
            'pki:owner_credentials-truststore-association',
            kwargs={'pk': owner_credential_remote_est.pk},
        )
        response = auth_client.get(url)
        assert response.status_code == 200

    def test_context_contains_import_form(
        self, auth_client: Client, owner_credential_remote_est: OwnerCredentialModel
    ) -> None:
        """The context includes the import form for inline truststore creation."""
        url = reverse(
            'pki:owner_credentials-truststore-association',
            kwargs={'pk': owner_credential_remote_est.pk},
        )
        response = auth_client.get(url)
        assert 'import_form' in response.context

    def test_404_for_nonexistent_pk(self, auth_client: Client) -> None:
        """Requesting a non-existent pk returns 404."""
        url = reverse('pki:owner_credentials-truststore-association', kwargs={'pk': 99999})
        response = auth_client.get(url)
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# OwnerCredentialCLMView
# ---------------------------------------------------------------------------


class TestOwnerCredentialCLMView:
    """Tests for the Certificate Lifecycle Management view."""

    def test_get_returns_200(
        self, auth_client: Client, owner_credential_remote_est: OwnerCredentialModel
    ) -> None:
        """GET renders the CLM page."""
        url = reverse('pki:owner_credentials-clm', kwargs={'pk': owner_credential_remote_est.pk})
        response = auth_client.get(url)
        assert response.status_code == 200

    def test_context_contains_issued_credentials(
        self, auth_client: Client, owner_credential_remote_est: OwnerCredentialModel
    ) -> None:
        """The context includes issued_credentials (possibly empty)."""
        url = reverse('pki:owner_credentials-clm', kwargs={'pk': owner_credential_remote_est.pk})
        response = auth_client.get(url)
        assert 'issued_credentials' in response.context

    def test_pending_credential_shows_pending_text(
        self, auth_client: Client, owner_credential_remote_est: OwnerCredentialModel
    ) -> None:
        """A credential without a certificate shows 'Pending enrollment'."""
        cred = CredentialModel.objects.create(
            credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID,
        )
        RemoteIssuedCredentialModel.objects.create(
            common_name='pending-cred',
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
            credential=cred,
            owner_credential=owner_credential_remote_est,
        )
        url = reverse('pki:owner_credentials-clm', kwargs={'pk': owner_credential_remote_est.pk})
        response = auth_client.get(url)
        issued = list(response.context['issued_credentials'])
        assert len(issued) == 1
        assert 'Pending' in str(issued[0].expires_in)


# ---------------------------------------------------------------------------
# IssuedCredentialDeleteView
# ---------------------------------------------------------------------------


class TestIssuedCredentialDeleteView:
    """Tests for deleting a single issued credential from the CLM."""

    def test_get_confirm_page(
        self, auth_client: Client, owner_credential_remote_est: OwnerCredentialModel
    ) -> None:
        """GET renders the deletion confirmation page."""
        cred = CredentialModel.objects.create(
            credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID,
        )
        issued = RemoteIssuedCredentialModel.objects.create(
            common_name='del-me',
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
            credential=cred,
            owner_credential=owner_credential_remote_est,
        )
        url = reverse(
            'pki:owner_credentials-issued-credential-delete',
            kwargs={'owner_pk': owner_credential_remote_est.pk, 'pk': issued.pk},
        )
        response = auth_client.get(url)
        assert response.status_code == 200

    def test_post_deletes_credential(
        self, auth_client: Client, owner_credential_remote_est: OwnerCredentialModel
    ) -> None:
        """POST deletes the issued credential and redirects to CLM."""
        cred = CredentialModel.objects.create(
            credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID,
        )
        issued = RemoteIssuedCredentialModel.objects.create(
            common_name='del-me',
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
            credential=cred,
            owner_credential=owner_credential_remote_est,
        )
        url = reverse(
            'pki:owner_credentials-issued-credential-delete',
            kwargs={'owner_pk': owner_credential_remote_est.pk, 'pk': issued.pk},
        )
        response = auth_client.post(url)
        assert response.status_code == 302
        assert 'clm' in response.url  # type: ignore[union-attr]

    def test_404_for_wrong_owner(
        self, auth_client: Client, owner_credential_remote_est: OwnerCredentialModel
    ) -> None:
        """Requesting a credential that does not belong to the owner returns 404."""
        other_oc = OwnerCredentialModel.objects.create(unique_name='other-oc')
        cred = CredentialModel.objects.create(
            credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID,
        )
        issued = RemoteIssuedCredentialModel.objects.create(
            common_name='other',
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
            credential=cred,
            owner_credential=other_oc,
        )
        url = reverse(
            'pki:owner_credentials-issued-credential-delete',
            kwargs={'owner_pk': owner_credential_remote_est.pk, 'pk': issued.pk},
        )
        response = auth_client.get(url)
        assert response.status_code == 404
