"""Tests for newly added owner credential forms."""

from __future__ import annotations

from typing import Any

import pytest
from django.core.exceptions import ValidationError

from onboarding.models import (
    NoOnboardingConfigModel,
    NoOnboardingPkiProtocol,
    OnboardingConfigModel,
    OnboardingProtocol,
)
from pki.forms.owner_credential import (
    OwnerCredentialAddRequestEstNoOnboardingForm,
    OwnerCredentialAddRequestEstOnboardingForm,
    OwnerCredentialTruststoreAssociationForm,
    _OwnerCredentialEstBaseMixin,
)
from pki.models import OwnerCredentialModel
from pki.models.truststore import TruststoreModel


@pytest.fixture(autouse=True)
def _enable_db(db: None) -> None:
    """Enable database access for all tests in this module."""


@pytest.fixture(autouse=True)
def _key_storage_config(_enable_db: None) -> None:
    """Ensure a KeyStorageConfig row exists (required by EncryptedCharField on every save)."""
    from management.models import KeyStorageConfig

    KeyStorageConfig.get_or_create_default()


# ---------------------------------------------------------------------------
# _OwnerCredentialEstBaseMixin helpers
# ---------------------------------------------------------------------------


class TestEstBaseMixinGeneratePrivateKey:
    """Tests for _OwnerCredentialEstBaseMixin._generate_private_key."""

    @pytest.fixture()
    def mixin(self) -> _OwnerCredentialEstBaseMixin:
        """Return a bare mixin instance (no form data needed)."""
        return _OwnerCredentialEstBaseMixin()

    @pytest.mark.parametrize('key_type', ['RSA-2048', 'RSA-3072', 'RSA-4096'])
    def test_generate_rsa_key(self, mixin: _OwnerCredentialEstBaseMixin, key_type: str) -> None:
        """RSA key types produce a key with the correct bit size."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = mixin._generate_private_key(key_type)
        assert isinstance(key, rsa.RSAPrivateKey)
        expected_size = int(key_type.split('-')[1])
        assert key.key_size == expected_size

    @pytest.mark.parametrize('key_type', ['ECC-SECP256R1', 'ECC-SECP384R1', 'ECC-SECP521R1'])
    def test_generate_ecc_key(self, mixin: _OwnerCredentialEstBaseMixin, key_type: str) -> None:
        """ECC key types produce an EC private key."""
        from cryptography.hazmat.primitives.asymmetric import ec

        key = mixin._generate_private_key(key_type)
        assert isinstance(key, ec.EllipticCurvePrivateKey)


class TestEstBaseMixinResolveUniqueName:
    """Tests for _OwnerCredentialEstBaseMixin._resolve_unique_name."""

    @pytest.fixture()
    def mixin(self) -> _OwnerCredentialEstBaseMixin:
        """Return a bare mixin instance."""
        return _OwnerCredentialEstBaseMixin()

    def test_returns_given_name(self, mixin: _OwnerCredentialEstBaseMixin) -> None:
        """When a non-empty unique_name is given it is returned as-is."""
        assert mixin._resolve_unique_name('my-name', 'example.com') == 'my-name'

    def test_derives_name_from_host(self, mixin: _OwnerCredentialEstBaseMixin) -> None:
        """When unique_name is empty or None the host is used."""
        assert mixin._resolve_unique_name(None, 'est.example.com') == 'est.example.com'
        assert mixin._resolve_unique_name('', 'est.example.com') == 'est.example.com'

    def test_auto_increments_on_collision(self, mixin: _OwnerCredentialEstBaseMixin) -> None:
        """When the derived name already exists a numeric suffix is appended."""
        OwnerCredentialModel.objects.create(unique_name='est.example.com')
        result = mixin._resolve_unique_name(None, 'est.example.com')
        assert result == 'est.example.com-1'


# ---------------------------------------------------------------------------
# OwnerCredentialTruststoreAssociationForm
# ---------------------------------------------------------------------------


class TestOwnerCredentialTruststoreAssociationForm:
    """Tests for OwnerCredentialTruststoreAssociationForm."""

    @pytest.fixture()
    def owner_credential(self) -> OwnerCredentialModel:
        """Create a minimal OwnerCredentialModel with a NoOnboardingConfigModel."""
        no_onboarding = NoOnboardingConfigModel(
            pki_protocols=NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD,
            est_password='secret',
        )
        no_onboarding.save()
        return OwnerCredentialModel.objects.create(
            unique_name='test-owner',
            no_onboarding_config=no_onboarding,
            owner_credential_type=OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST,
        )

    def test_instantiation_succeeds(self, owner_credential: OwnerCredentialModel) -> None:
        """The form can be instantiated without raising AttributeError."""
        form = OwnerCredentialTruststoreAssociationForm(instance=owner_credential)
        assert 'trust_store' in form.fields

    def test_queryset_only_contains_tls_truststores(self, owner_credential: OwnerCredentialModel) -> None:
        """The trust_store field queryset should only include TLS truststores."""
        # Create one TLS and one non-TLS truststore
        tls_ts = TruststoreModel.objects.create(
            unique_name='tls-ts',
            intended_usage=TruststoreModel.IntendedUsage.TLS,
        )
        TruststoreModel.objects.create(
            unique_name='idevid-ts',
            intended_usage=TruststoreModel.IntendedUsage.IDEVID,
        )

        form = OwnerCredentialTruststoreAssociationForm(instance=owner_credential)
        qs = form.fields['trust_store'].queryset  # type: ignore[union-attr]
        assert list(qs) == [tls_ts]

    def test_save_raises_when_no_onboarding_config_is_none(self) -> None:
        """save() raises ValidationError when no_onboarding_config is None."""
        oc = OwnerCredentialModel.objects.create(
            unique_name='test-owner-no-config',
            owner_credential_type=OwnerCredentialModel.OwnerCredentialTypeChoice.LOCAL,
        )
        form = OwnerCredentialTruststoreAssociationForm(instance=oc)
        with pytest.raises(ValidationError):
            form.save()


# ---------------------------------------------------------------------------
# OwnerCredentialAddRequestEstNoOnboardingForm
# ---------------------------------------------------------------------------


class TestOwnerCredentialAddRequestEstNoOnboardingForm:
    """Tests for the EST no-onboarding form."""

    def _form_data(self, **overrides: Any) -> dict[str, Any]:
        """Return valid form data with optional overrides."""
        data: dict[str, Any] = {
            'unique_name': 'test-est',
            'remote_host': 'est.example.com',
            'remote_port': 443,
            'remote_path': '/.well-known/est/simpleenroll',
            'key_type': 'ECC-SECP256R1',
            'est_username': 'admin',
            'est_password': 'secret',
        }
        data.update(overrides)
        return data

    def test_instantiation_succeeds(self) -> None:
        """The form can be instantiated without errors."""
        form = OwnerCredentialAddRequestEstNoOnboardingForm()
        assert 'remote_host' in form.fields
        assert 'est_username' in form.fields
        assert 'est_password' in form.fields

    def test_valid_data_creates_no_onboarding_config(self) -> None:
        """Submitting valid data creates a NoOnboardingConfigModel in cleaned_data."""
        form = OwnerCredentialAddRequestEstNoOnboardingForm(data=self._form_data())
        assert form.is_valid(), form.errors
        assert '_no_onboarding_config' in form.cleaned_data
        config = form.cleaned_data['_no_onboarding_config']
        assert isinstance(config, NoOnboardingConfigModel)
        assert config.pk is not None  # saved to DB

    def test_missing_host_skips_enrollment(self) -> None:
        """When remote_host is blank the form does not create a config."""
        form = OwnerCredentialAddRequestEstNoOnboardingForm(data=self._form_data(remote_host=''))
        # remote_host is required, so the form should be invalid
        assert not form.is_valid()

    def test_duplicate_unique_name_raises(self) -> None:
        """Submitting a unique_name that already exists raises a ValidationError."""
        OwnerCredentialModel.objects.create(unique_name='duplicate')
        form = OwnerCredentialAddRequestEstNoOnboardingForm(data=self._form_data(unique_name='duplicate'))
        assert not form.is_valid()

    def test_private_key_is_generated(self) -> None:
        """The cleaned_data contains a generated private key."""
        form = OwnerCredentialAddRequestEstNoOnboardingForm(data=self._form_data(key_type='RSA-2048'))
        assert form.is_valid(), form.errors
        assert '_private_key' in form.cleaned_data
        from cryptography.hazmat.primitives.asymmetric import rsa
        assert isinstance(form.cleaned_data['_private_key'], rsa.RSAPrivateKey)


# ---------------------------------------------------------------------------
# OwnerCredentialAddRequestEstOnboardingForm
# ---------------------------------------------------------------------------


class TestOwnerCredentialAddRequestEstOnboardingForm:
    """Tests for the EST IDevID-based onboarding form."""

    def _form_data(self, **overrides: Any) -> dict[str, Any]:
        """Return valid form data with optional overrides."""
        data: dict[str, Any] = {
            'unique_name': 'test-est-onboarding',
            'remote_host': 'est.example.com',
            'remote_port': 443,
            'remote_path': '/.well-known/est/simpleenroll',
            'remote_path_domain_credential': '/.well-known/est/simpleenroll',
            'key_type': 'ECC-SECP256R1',
            'est_username': 'admin',
            'est_password': 'secret',
        }
        data.update(overrides)
        return data

    def test_instantiation_succeeds(self) -> None:
        """The form can be instantiated and exposes the expected fields."""
        form = OwnerCredentialAddRequestEstOnboardingForm()
        assert 'remote_host' in form.fields
        assert 'remote_path_domain_credential' in form.fields
        assert 'est_username' in form.fields
        assert 'est_password' in form.fields

    def test_valid_data_creates_onboarding_config(self, db: None) -> None:
        """Submitting valid data creates an OnboardingConfigModel in cleaned_data."""
        form = OwnerCredentialAddRequestEstOnboardingForm(data=self._form_data())
        assert form.is_valid(), form.errors
        assert '_onboarding_config' in form.cleaned_data
        config = form.cleaned_data['_onboarding_config']
        assert isinstance(config, OnboardingConfigModel)
        assert config.pk is not None  # saved to DB

    def test_onboarding_config_protocol_is_est(self, db: None) -> None:
        """The created OnboardingConfigModel uses EST_USERNAME_PASSWORD as onboarding protocol."""
        form = OwnerCredentialAddRequestEstOnboardingForm(data=self._form_data())
        assert form.is_valid(), form.errors
        config: OnboardingConfigModel = form.cleaned_data['_onboarding_config']
        assert config.onboarding_protocol == OnboardingProtocol.EST_USERNAME_PASSWORD

    def test_cleaned_data_contains_expected_keys(self, db: None) -> None:
        """All auxiliary cleaned_data keys are populated after a valid submission."""
        form = OwnerCredentialAddRequestEstOnboardingForm(data=self._form_data())
        assert form.is_valid(), form.errors
        for key in ('_private_key', '_onboarding_config', '_remote_host', '_remote_port',
                    '_remote_path', '_remote_path_domain_credential', '_est_username'):
            assert key in form.cleaned_data, f'Missing key: {key}'

    def test_remote_path_domain_credential_stored(self, db: None) -> None:
        """The custom domain-credential path is forwarded into cleaned_data."""
        custom_path = '/.well-known/est/domain-cred'
        form = OwnerCredentialAddRequestEstOnboardingForm(
            data=self._form_data(remote_path_domain_credential=custom_path)
        )
        assert form.is_valid(), form.errors
        assert form.cleaned_data['_remote_path_domain_credential'] == custom_path

    def test_missing_host_skips_enrollment(self, db: None) -> None:
        """When remote_host is blank the form is invalid (required field)."""
        form = OwnerCredentialAddRequestEstOnboardingForm(data=self._form_data(remote_host=''))
        assert not form.is_valid()
        assert 'remote_host' in form.errors

    def test_missing_username_skips_config_creation(self, db: None) -> None:
        """When est_username is blank the form is invalid (required field)."""
        form = OwnerCredentialAddRequestEstOnboardingForm(data=self._form_data(est_username=''))
        assert not form.is_valid()
        assert 'est_username' in form.errors

    def test_duplicate_unique_name_raises(self, db: None) -> None:
        """Submitting a unique_name that already exists makes the form invalid."""
        OwnerCredentialModel.objects.create(unique_name='duplicate-onboarding')
        form = OwnerCredentialAddRequestEstOnboardingForm(
            data=self._form_data(unique_name='duplicate-onboarding')
        )
        assert not form.is_valid()

    def test_unique_name_derived_from_host_when_omitted(self, db: None) -> None:
        """When unique_name is left blank, it is derived from remote_host."""
        form = OwnerCredentialAddRequestEstOnboardingForm(
            data=self._form_data(unique_name='', remote_host='est.example.com')
        )
        assert form.is_valid(), form.errors
        assert form.cleaned_data['unique_name'] == 'est.example.com'

    def test_unique_name_auto_incremented_on_collision(self, db: None) -> None:
        """When the host-derived name already exists a numeric suffix is appended."""
        OwnerCredentialModel.objects.create(unique_name='est.example.com')
        form = OwnerCredentialAddRequestEstOnboardingForm(
            data=self._form_data(unique_name='', remote_host='est.example.com')
        )
        assert form.is_valid(), form.errors
        assert form.cleaned_data['unique_name'] == 'est.example.com-1'

    def test_private_key_is_generated_ecc(self, db: None) -> None:
        """The cleaned_data contains an EC private key when an ECC key type is selected."""
        from cryptography.hazmat.primitives.asymmetric import ec

        form = OwnerCredentialAddRequestEstOnboardingForm(data=self._form_data(key_type='ECC-SECP384R1'))
        assert form.is_valid(), form.errors
        assert isinstance(form.cleaned_data['_private_key'], ec.EllipticCurvePrivateKey)

    def test_private_key_is_generated_rsa(self, db: None) -> None:
        """The cleaned_data contains an RSA private key when an RSA key type is selected."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        form = OwnerCredentialAddRequestEstOnboardingForm(data=self._form_data(key_type='RSA-2048'))
        assert form.is_valid(), form.errors
        key = form.cleaned_data['_private_key']
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048

    def test_est_username_stored_in_cleaned_data(self, db: None) -> None:
        """The submitted est_username is forwarded as _est_username in cleaned_data."""
        form = OwnerCredentialAddRequestEstOnboardingForm(
            data=self._form_data(est_username='myuser')
        )
        assert form.is_valid(), form.errors
        assert form.cleaned_data['_est_username'] == 'myuser'
