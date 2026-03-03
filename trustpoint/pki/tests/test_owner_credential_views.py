"""Tests for newly added owner credential views."""

from __future__ import annotations


import pytest
from django.contrib.auth.models import User
from django.test import Client
from django.urls import reverse

from onboarding.models import (
    NoOnboardingConfigModel,
    NoOnboardingPkiProtocol,
    OnboardingConfigModel,
    OnboardingProtocol,
)
from pki.models import OwnerCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.credential import CredentialModel, IDevIDReferenceModel
from pki.models import RemoteIssuedCredentialModel


@pytest.fixture(autouse=True)
def _enable_db(db: None) -> None:
    """Enable database access for all tests in this module."""


@pytest.fixture(autouse=True)
def _key_storage_config(_enable_db: None) -> None:
    """Ensure a KeyStorageConfig row exists (required by EncryptedCharField on every save)."""
    from management.models import KeyStorageConfig

    KeyStorageConfig.get_or_create_default()


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


@pytest.fixture()
def owner_credential_onboarding() -> OwnerCredentialModel:
    """Create a REMOTE_EST_ONBOARDING OwnerCredentialModel with an OnboardingConfig."""
    onboarding_config = OnboardingConfigModel(
        pki_protocols=0,
        onboarding_protocol=OnboardingProtocol.EST_USERNAME_PASSWORD,
        est_password='secret',
    )
    onboarding_config.save()
    return OwnerCredentialModel.objects.create(
        unique_name='onboarding-oc',
        onboarding_config=onboarding_config,
        owner_credential_type=OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST_ONBOARDING,
        remote_host='est.example.com',
        remote_port=443,
        remote_path='/.well-known/est/simpleenroll',
        remote_path_domain_credential='/.well-known/est/simpleenroll',
        est_username='user',
    )


@pytest.fixture()
def cert_profile() -> CertificateProfileModel:
    """Create a minimal CertificateProfileModel for use in define-cert-content views."""
    return CertificateProfileModel.objects.create(
        unique_name='dev_owner_id',
        display_name='DevOwnerID',
        profile_json={'type': 'cert_profile'},
    )


@pytest.fixture()
def domain_credential_cert_profile() -> CertificateProfileModel:
    """Create a domain-credential CertificateProfileModel."""
    return CertificateProfileModel.objects.create(
        unique_name='devownerid_domain_credential',
        display_name='DevOwnerID Domain Credential',
        profile_json={'type': 'cert_profile'},
    )
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


# ---------------------------------------------------------------------------
# OwnerCredentialDefineCertContentEstView
# ---------------------------------------------------------------------------


class TestOwnerCredentialDefineCertContentEstView:
    """Tests for Step 1 of the DevOwnerID EST enrollment flow."""

    def test_get_redirects_when_no_profile(
        self, auth_client: Client, owner_credential_remote_est: OwnerCredentialModel
    ) -> None:
        """GET redirects to the CLM when no CertificateProfileModel exists."""
        url = reverse(
            'pki:owner_credentials-define-cert-content-est',
            kwargs={'pk': owner_credential_remote_est.pk},
        )
        response = auth_client.get(url)
        assert response.status_code == 302
        assert 'clm' in response.url  # type: ignore[union-attr]

    def test_get_returns_200_with_profile(
        self,
        auth_client: Client,
        owner_credential_remote_est: OwnerCredentialModel,
        cert_profile: CertificateProfileModel,
    ) -> None:
        """GET renders successfully when a CertificateProfileModel exists."""
        url = reverse(
            'pki:owner_credentials-define-cert-content-est',
            kwargs={'pk': owner_credential_remote_est.pk},
        )
        response = auth_client.get(url)
        assert response.status_code == 200

    def test_context_contains_cert_profile(
        self,
        auth_client: Client,
        owner_credential_remote_est: OwnerCredentialModel,
        cert_profile: CertificateProfileModel,
    ) -> None:
        """Context includes the resolved cert_profile."""
        url = reverse(
            'pki:owner_credentials-define-cert-content-est',
            kwargs={'pk': owner_credential_remote_est.pk},
        )
        response = auth_client.get(url)
        assert response.context['cert_profile'].unique_name == 'dev_owner_id'

    def test_context_contains_available_profiles(
        self,
        auth_client: Client,
        owner_credential_remote_est: OwnerCredentialModel,
        cert_profile: CertificateProfileModel,
    ) -> None:
        """Context includes the full list of available profiles for the dropdown."""
        url = reverse(
            'pki:owner_credentials-define-cert-content-est',
            kwargs={'pk': owner_credential_remote_est.pk},
        )
        response = auth_client.get(url)
        assert cert_profile in response.context['available_profiles']

    def test_profile_switchable_via_query_param(
        self,
        auth_client: Client,
        owner_credential_remote_est: OwnerCredentialModel,
        cert_profile: CertificateProfileModel,
    ) -> None:
        """Passing cert_profile_pk in the query string selects that profile."""
        other = CertificateProfileModel.objects.create(
            unique_name='other_profile', display_name='Other', profile_json={'type': 'cert_profile'}
        )
        url = reverse(
            'pki:owner_credentials-define-cert-content-est',
            kwargs={'pk': owner_credential_remote_est.pk},
        )
        response = auth_client.get(url, {'cert_profile_pk': other.pk})
        assert response.context['cert_profile'].unique_name == 'other_profile'

    def test_get_creates_pending_credential(
        self,
        auth_client: Client,
        owner_credential_remote_est: OwnerCredentialModel,
        cert_profile: CertificateProfileModel,
    ) -> None:
        """A GET request creates a key-only RemoteIssuedCredentialModel."""
        url = reverse(
            'pki:owner_credentials-define-cert-content-est',
            kwargs={'pk': owner_credential_remote_est.pk},
        )
        auth_client.get(url)
        assert RemoteIssuedCredentialModel.objects.filter(
            owner_credential=owner_credential_remote_est,
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
            credential__certificate__isnull=True,
        ).exists()

    def test_valid_post_stores_session_data_and_redirects(
        self,
        auth_client: Client,
        owner_credential_remote_est: OwnerCredentialModel,
        cert_profile: CertificateProfileModel,
    ) -> None:
        """A valid POST stores cert content in the session and redirects to Step 2."""
        url = reverse(
            'pki:owner_credentials-define-cert-content-est',
            kwargs={'pk': owner_credential_remote_est.pk},
        )
        # First GET to create the pending credential and warm the session
        auth_client.get(url)
        response = auth_client.post(url, {
            'cert_profile_pk': cert_profile.pk,
            'common_name': 'test-device',
            'days': 365,
        })
        assert response.status_code == 302
        assert 'request-cert-est' in response.url  # type: ignore[union-attr]
        session_key = f'dev_owner_id_cert_content_{owner_credential_remote_est.pk}'
        session = auth_client.session
        assert session_key in session
        assert session[session_key].get('cert_profile_unique_name') == 'dev_owner_id'

    def test_404_for_nonexistent_owner(self, auth_client: Client, cert_profile: CertificateProfileModel) -> None:
        """GET returns 404 for an unknown owner credential pk."""
        url = reverse('pki:owner_credentials-define-cert-content-est', kwargs={'pk': 99999})
        response = auth_client.get(url)
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# OwnerCredentialDefineCertContentDomainCredentialEstView
# ---------------------------------------------------------------------------


class TestOwnerCredentialDefineCertContentDomainCredentialEstView:
    """Tests for Step 1 of the Domain Credential EST enrollment flow."""

    def test_get_redirects_non_onboarding_owner(
        self,
        auth_client: Client,
        owner_credential_remote_est: OwnerCredentialModel,
        domain_credential_cert_profile: CertificateProfileModel,
    ) -> None:
        """GET redirects to CLM when owner credential is not REMOTE_EST_ONBOARDING."""
        url = reverse(
            'pki:owner_credentials-define-cert-content-domain-credential-est',
            kwargs={'pk': owner_credential_remote_est.pk},
        )
        response = auth_client.get(url)
        assert response.status_code == 302
        assert 'clm' in response.url  # type: ignore[union-attr]

    def test_get_redirects_when_no_profile(
        self,
        auth_client: Client,
        owner_credential_onboarding: OwnerCredentialModel,
    ) -> None:
        """GET redirects to CLM when no CertificateProfileModel exists."""
        url = reverse(
            'pki:owner_credentials-define-cert-content-domain-credential-est',
            kwargs={'pk': owner_credential_onboarding.pk},
        )
        response = auth_client.get(url)
        assert response.status_code == 302
        assert 'clm' in response.url  # type: ignore[union-attr]

    def test_get_returns_200_with_profile(
        self,
        auth_client: Client,
        owner_credential_onboarding: OwnerCredentialModel,
        domain_credential_cert_profile: CertificateProfileModel,
    ) -> None:
        """GET renders successfully for a REMOTE_EST_ONBOARDING owner with a profile."""
        url = reverse(
            'pki:owner_credentials-define-cert-content-domain-credential-est',
            kwargs={'pk': owner_credential_onboarding.pk},
        )
        response = auth_client.get(url)
        assert response.status_code == 200

    def test_context_defaults_to_domain_credential_profile(
        self,
        auth_client: Client,
        owner_credential_onboarding: OwnerCredentialModel,
        domain_credential_cert_profile: CertificateProfileModel,
    ) -> None:
        """Context cert_profile defaults to devownerid_domain_credential when present."""
        url = reverse(
            'pki:owner_credentials-define-cert-content-domain-credential-est',
            kwargs={'pk': owner_credential_onboarding.pk},
        )
        response = auth_client.get(url)
        assert response.context['cert_profile'].unique_name == 'devownerid_domain_credential'

    def test_context_contains_available_profiles(
        self,
        auth_client: Client,
        owner_credential_onboarding: OwnerCredentialModel,
        domain_credential_cert_profile: CertificateProfileModel,
    ) -> None:
        """Context includes the full list of available profiles for the dropdown."""
        url = reverse(
            'pki:owner_credentials-define-cert-content-domain-credential-est',
            kwargs={'pk': owner_credential_onboarding.pk},
        )
        response = auth_client.get(url)
        assert domain_credential_cert_profile in response.context['available_profiles']

    def test_profile_switchable_via_query_param(
        self,
        auth_client: Client,
        owner_credential_onboarding: OwnerCredentialModel,
        domain_credential_cert_profile: CertificateProfileModel,
    ) -> None:
        """Passing cert_profile_pk in the query string selects that profile."""
        other = CertificateProfileModel.objects.create(
            unique_name='alt_profile', display_name='Alt', profile_json={'type': 'cert_profile'}
        )
        url = reverse(
            'pki:owner_credentials-define-cert-content-domain-credential-est',
            kwargs={'pk': owner_credential_onboarding.pk},
        )
        response = auth_client.get(url, {'cert_profile_pk': other.pk})
        assert response.context['cert_profile'].unique_name == 'alt_profile'

    def test_get_creates_pending_domain_credential(
        self,
        auth_client: Client,
        owner_credential_onboarding: OwnerCredentialModel,
        domain_credential_cert_profile: CertificateProfileModel,
    ) -> None:
        """A GET request creates a key-only DOMAIN_CREDENTIAL RemoteIssuedCredentialModel."""
        url = reverse(
            'pki:owner_credentials-define-cert-content-domain-credential-est',
            kwargs={'pk': owner_credential_onboarding.pk},
        )
        auth_client.get(url)
        assert RemoteIssuedCredentialModel.objects.filter(
            owner_credential=owner_credential_onboarding,
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DOMAIN_CREDENTIAL,
            credential__certificate__isnull=True,
        ).exists()

    def test_valid_post_stores_session_data_and_redirects(
        self,
        auth_client: Client,
        owner_credential_onboarding: OwnerCredentialModel,
        domain_credential_cert_profile: CertificateProfileModel,
    ) -> None:
        """A valid POST stores cert content in the session and redirects to Step 2."""
        url = reverse(
            'pki:owner_credentials-define-cert-content-domain-credential-est',
            kwargs={'pk': owner_credential_onboarding.pk},
        )
        auth_client.get(url)
        response = auth_client.post(url, {
            'cert_profile_pk': domain_credential_cert_profile.pk,
            'common_name': 'domain-device',
            'days': 180,
        })
        assert response.status_code == 302
        assert 'request-domain-credential-est' in response.url  # type: ignore[union-attr]
        session_key = f'domain_credential_cert_content_{owner_credential_onboarding.pk}'
        session = auth_client.session
        assert session_key in session
        assert session[session_key].get('cert_profile_unique_name') == 'devownerid_domain_credential'

    def test_404_for_nonexistent_owner(
        self, auth_client: Client, domain_credential_cert_profile: CertificateProfileModel
    ) -> None:
        """GET returns 404 for an unknown owner credential pk."""
        url = reverse(
            'pki:owner_credentials-define-cert-content-domain-credential-est',
            kwargs={'pk': 99999},
        )
        response = auth_client.get(url)
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# OwnerCredentialRequestCertEstView
# ---------------------------------------------------------------------------


class TestOwnerCredentialRequestCertEstView:
    """Tests for Step 2 of the DevOwnerID EST enrollment flow."""

    def test_get_returns_200_without_session_data(
        self,
        auth_client: Client,
        owner_credential_remote_est: OwnerCredentialModel,
    ) -> None:
        """GET renders the review page even when no session data is present."""
        url = reverse(
            'pki:owner_credentials-request-cert-est',
            kwargs={'pk': owner_credential_remote_est.pk},
        )
        response = auth_client.get(url)
        assert response.status_code == 200
        assert response.context['has_cert_content'] is False

    def test_get_shows_cert_content_when_session_present(
        self,
        auth_client: Client,
        owner_credential_remote_est: OwnerCredentialModel,
        cert_profile: CertificateProfileModel,
    ) -> None:
        """GET renders cert content summary when session data is populated."""
        session = auth_client.session
        session_key = f'dev_owner_id_cert_content_{owner_credential_remote_est.pk}'
        session[session_key] = {
            'common_name': 'my-device',
            'days': 365,
            'cert_profile_unique_name': 'dev_owner_id',
        }
        session.save()
        url = reverse(
            'pki:owner_credentials-request-cert-est',
            kwargs={'pk': owner_credential_remote_est.pk},
        )
        response = auth_client.get(url)
        assert response.status_code == 200
        assert response.context['has_cert_content'] is True
        assert response.context['cert_profile'].unique_name == 'dev_owner_id'

    def test_post_without_session_redirects_to_define(
        self,
        auth_client: Client,
        owner_credential_remote_est: OwnerCredentialModel,
    ) -> None:
        """POST without session data redirects back to the define-cert-content step."""
        url = reverse(
            'pki:owner_credentials-request-cert-est',
            kwargs={'pk': owner_credential_remote_est.pk},
        )
        response = auth_client.post(url)
        assert response.status_code == 302
        assert 'define-cert-content-est' in response.url  # type: ignore[union-attr]

    def test_404_for_nonexistent_owner(self, auth_client: Client) -> None:
        """GET returns 404 for an unknown owner credential pk."""
        url = reverse('pki:owner_credentials-request-cert-est', kwargs={'pk': 99999})
        response = auth_client.get(url)
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# OwnerCredentialRequestDomainCredentialEstView
# ---------------------------------------------------------------------------


class TestOwnerCredentialRequestDomainCredentialEstView:
    """Tests for Step 2 of the Domain Credential EST enrollment flow."""

    def test_get_returns_200_without_session_data(
        self,
        auth_client: Client,
        owner_credential_onboarding: OwnerCredentialModel,
    ) -> None:
        """GET renders the review page even when no session data is present."""
        url = reverse(
            'pki:owner_credentials-request-domain-credential-est',
            kwargs={'pk': owner_credential_onboarding.pk},
        )
        response = auth_client.get(url)
        assert response.status_code == 200
        assert response.context['has_cert_content'] is False

    def test_get_shows_cert_content_when_session_present(
        self,
        auth_client: Client,
        owner_credential_onboarding: OwnerCredentialModel,
        domain_credential_cert_profile: CertificateProfileModel,
    ) -> None:
        """GET renders cert content summary when session data is populated."""
        session = auth_client.session
        session_key = f'domain_credential_cert_content_{owner_credential_onboarding.pk}'
        session[session_key] = {
            'common_name': 'domain-device',
            'days': 180,
            'cert_profile_unique_name': 'devownerid_domain_credential',
        }
        session.save()
        url = reverse(
            'pki:owner_credentials-request-domain-credential-est',
            kwargs={'pk': owner_credential_onboarding.pk},
        )
        response = auth_client.get(url)
        assert response.status_code == 200
        assert response.context['has_cert_content'] is True
        assert response.context['cert_profile'].unique_name == 'devownerid_domain_credential'

    def test_get_context_includes_trust_store(
        self,
        auth_client: Client,
        owner_credential_onboarding: OwnerCredentialModel,
    ) -> None:
        """Context includes trust_store (None when not configured)."""
        url = reverse(
            'pki:owner_credentials-request-domain-credential-est',
            kwargs={'pk': owner_credential_onboarding.pk},
        )
        response = auth_client.get(url)
        assert 'trust_store' in response.context

    def test_get_context_includes_est_password_set(
        self,
        auth_client: Client,
        owner_credential_onboarding: OwnerCredentialModel,
    ) -> None:
        """Context includes est_password_set True when onboarding config has a password."""
        url = reverse(
            'pki:owner_credentials-request-domain-credential-est',
            kwargs={'pk': owner_credential_onboarding.pk},
        )
        response = auth_client.get(url)
        assert response.context['est_password_set'] is True

    def test_post_without_session_redirects_to_define(
        self,
        auth_client: Client,
        owner_credential_onboarding: OwnerCredentialModel,
    ) -> None:
        """POST without session data redirects back to the define-cert-content step."""
        url = reverse(
            'pki:owner_credentials-request-domain-credential-est',
            kwargs={'pk': owner_credential_onboarding.pk},
        )
        response = auth_client.post(url)
        assert response.status_code == 302
        assert 'define-cert-content-domain-credential-est' in response.url  # type: ignore[union-attr]

    def test_404_for_nonexistent_owner(self, auth_client: Client) -> None:
        """GET returns 404 for an unknown owner credential pk."""
        url = reverse('pki:owner_credentials-request-domain-credential-est', kwargs={'pk': 99999})
        response = auth_client.get(url)
        assert response.status_code == 404
