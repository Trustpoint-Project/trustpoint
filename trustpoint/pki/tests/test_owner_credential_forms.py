"""Tests for newly added owner credential forms."""

from __future__ import annotations

from typing import Any

import pytest
from django.core.exceptions import ValidationError

from onboarding.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol
from pki.forms.owner_credential import (
    OwnerCredentialAddRequestEstNoOnboardingForm,
    OwnerCredentialTruststoreAssociationForm,
    _OwnerCredentialEstBaseMixin,
)
from pki.models import OwnerCredentialModel
from pki.models.truststore import TruststoreModel


@pytest.fixture(autouse=True)
def _enable_db(db: None) -> None:
    """Enable database access for all tests in this module."""


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
