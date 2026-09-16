# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for DevOwnerID (owner credential) form validation and setup flows."""

from __future__ import annotations

from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile

from onboarding.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol
from pki.forms.owner_credential import (
    OwnerCredentialAddRequestEstNoOnboardingForm,
    OwnerCredentialAddRequestEstOnboardingForm,
    OwnerCredentialFileImportForm,
    OwnerCredentialOnboardingSetupForm,
    OwnerCredentialTruststoreAssociationForm,
)
from pki.models import OwnerCredentialModel
from pki.models.devid_registration import DevIdRegistration
from pki.models.domain import DomainModel
from pki.models.truststore import TruststoreModel
from pki.util.x509 import CertificateGenerator

pytestmark = pytest.mark.django_db

TEST_KEY_PASSWORD = 'unit-test-secret-password'  # noqa: S105
MAX_UPLOAD_BYTES = 1024 * 64


def _dev_owner_id_material() -> tuple[x509.Certificate, Any, x509.Certificate]:
    """Return a DevOwnerID certificate carrying an IDevID SAN reference."""
    root, root_key = CertificateGenerator.create_root_ca('Form Owner Root')
    san = x509.SubjectAlternativeName([x509.UniformResourceIdentifier('dev-owner:SN1.SN2.FP')])
    certificate, private_key = CertificateGenerator.create_ee(
        root_key, root.subject, 'FormDevOwnerID', extensions=[(san, False)]
    )
    return certificate, private_key, root


def _key_pem(private_key: Any, password: str | None = None) -> bytes:
    """Serialize a private key to PEM, optionally encrypted."""
    encryption: serialization.KeySerializationEncryption = serialization.NoEncryption()
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    return private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )


def _import_files(**overrides: Any) -> dict[str, Any]:
    """Build the file payload for the DevOwnerID import form."""
    certificate, private_key, root = _dev_owner_id_material()
    files = {
        'certificate': SimpleUploadedFile('cert.pem', certificate.public_bytes(serialization.Encoding.PEM)),
        'certificate_chain': SimpleUploadedFile('chain.pem', root.public_bytes(serialization.Encoding.PEM)),
        'private_key_file': SimpleUploadedFile('key.pem', _key_pem(private_key)),
    }
    files.update(overrides)
    return files


class TestOwnerCredentialFileImportForm:
    """Validation of the DevOwnerID file import form."""

    def test_valid_import_creates_owner_credential(self) -> None:
        """A consistent certificate, chain and key create the DevOwnerID."""
        form = OwnerCredentialFileImportForm(data={}, files=_import_files())

        assert form.is_valid(), form.errors
        owner = form.cleaned_data['_owner_credential']
        assert isinstance(owner, OwnerCredentialModel)
        assert owner.dev_owner_id_credential is not None

    def test_name_is_derived_from_certificate(self) -> None:
        """Without an explicit name the certificate subject is used."""
        form = OwnerCredentialFileImportForm(data={}, files=_import_files())

        assert form.is_valid(), form.errors
        assert form.cleaned_data['unique_name']

    def test_oversized_private_key_is_rejected(self) -> None:
        """Private key uploads above the size limit are rejected."""
        files = _import_files(
            private_key_file=SimpleUploadedFile('key.pem', b'x' * (MAX_UPLOAD_BYTES + 1))
        )
        form = OwnerCredentialFileImportForm(data={}, files=files)

        assert not form.is_valid()
        assert 'too large' in str(form.errors['private_key_file'])

    def test_oversized_certificate_is_rejected(self) -> None:
        """Certificate uploads above the size limit are rejected."""
        files = _import_files(certificate=SimpleUploadedFile('cert.pem', b'x' * (MAX_UPLOAD_BYTES + 1)))
        form = OwnerCredentialFileImportForm(data={}, files=files)

        assert not form.is_valid()
        assert 'too large' in str(form.errors['certificate'])

    def test_wrong_private_key_password_is_rejected_without_leaking_it(self) -> None:
        """An encrypted key with the wrong password fails without echoing secrets."""
        certificate, private_key, _root = _dev_owner_id_material()
        form = OwnerCredentialFileImportForm(
            data={'private_key_file_password': 'wrong-password'},
            files={
                'certificate': SimpleUploadedFile(
                    'cert.pem', certificate.public_bytes(serialization.Encoding.PEM)
                ),
                'private_key_file': SimpleUploadedFile('key.pem', _key_pem(private_key, TEST_KEY_PASSWORD)),
            },
        )

        assert not form.is_valid()
        assert 'private_key_file' in form.errors
        assert TEST_KEY_PASSWORD not in str(form.errors)

    def test_correct_private_key_password_is_accepted(self) -> None:
        """An encrypted key is parsed when the correct password is supplied."""
        certificate, private_key, _root = _dev_owner_id_material()
        form = OwnerCredentialFileImportForm(
            data={'private_key_file_password': TEST_KEY_PASSWORD},
            files={
                'certificate': SimpleUploadedFile(
                    'cert.pem', certificate.public_bytes(serialization.Encoding.PEM)
                ),
                'private_key_file': SimpleUploadedFile('key.pem', _key_pem(private_key, TEST_KEY_PASSWORD)),
            },
        )

        assert form.is_valid(), form.errors

    def test_corrupt_certificate_is_rejected(self) -> None:
        """Unparsable certificate content is reported on the certificate field."""
        form = OwnerCredentialFileImportForm(
            data={}, files=_import_files(certificate=SimpleUploadedFile('cert.pem', b'broken'))
        )

        assert not form.is_valid()
        assert 'certificate' in form.errors

    def test_corrupt_chain_is_rejected(self) -> None:
        """Unparsable chain content is reported on the chain field."""
        form = OwnerCredentialFileImportForm(
            data={}, files=_import_files(certificate_chain=SimpleUploadedFile('chain.pem', b'broken'))
        )

        assert not form.is_valid()
        assert 'certificate_chain' in form.errors

    def test_duplicate_certificate_is_rejected(self) -> None:
        """The same DevOwnerID certificate cannot be imported twice."""
        certificate, private_key, _root = _dev_owner_id_material()
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
        first = OwnerCredentialFileImportForm(
            data={},
            files={
                'certificate': SimpleUploadedFile('cert.pem', certificate_pem),
                'private_key_file': SimpleUploadedFile('key.pem', _key_pem(private_key)),
            },
        )
        assert first.is_valid(), first.errors

        second = OwnerCredentialFileImportForm(
            data={'unique_name': 'second-owner'},
            files={
                'certificate': SimpleUploadedFile('cert.pem', certificate_pem),
                'private_key_file': SimpleUploadedFile('key.pem', _key_pem(private_key)),
            },
        )

        assert not second.is_valid()
        assert 'already configured' in str(second.errors['certificate'])

    def test_duplicate_unique_name_is_rejected(self) -> None:
        """A DevOwnerID name that is already taken is rejected."""
        OwnerCredentialModel.objects.create(unique_name='existing-owner')
        form = OwnerCredentialFileImportForm(data={'unique_name': 'existing-owner'}, files=_import_files())

        assert not form.is_valid()
        assert 'already exists' in str(form.errors)

    def test_certificate_without_idevid_reference_is_rejected(self) -> None:
        """A certificate lacking an IDevID SAN reference cannot become a DevOwnerID."""
        root, root_key = CertificateGenerator.create_root_ca('No Ref Root')
        certificate, private_key = CertificateGenerator.create_ee(root_key, root.subject, 'No Ref Leaf')
        form = OwnerCredentialFileImportForm(
            data={},
            files={
                'certificate': SimpleUploadedFile(
                    'cert.pem', certificate.public_bytes(serialization.Encoding.PEM)
                ),
                'private_key_file': SimpleUploadedFile('key.pem', _key_pem(private_key)),
            },
        )

        assert not form.is_valid()
        assert not OwnerCredentialModel.objects.exists()


class TestOwnerCredentialOnboardingSetupForm:
    """AOKI onboarding setup performed after a DevOwnerID import."""

    @pytest.fixture
    def owner(self) -> OwnerCredentialModel:
        """Return a stored DevOwnerID to attach the onboarding setup to."""
        return OwnerCredentialModel.objects.create(unique_name='aoki-owner')

    @pytest.fixture
    def domain(self, issuing_ca_instance: dict[str, Any]) -> DomainModel:
        """Return an active domain for the registration."""
        return DomainModel.objects.create(
            unique_name='aoki_domain', issuing_ca=issuing_ca_instance['issuing_ca'], is_active=True
        )

    def _files(self) -> dict[str, Any]:
        root, _ = CertificateGenerator.create_root_ca('IDevID Anchor')
        return {'trust_store_file': SimpleUploadedFile('ts.pem', root.public_bytes(serialization.Encoding.PEM))}

    def test_setup_creates_truststore_and_registration(
        self, owner: OwnerCredentialModel, domain: DomainModel
    ) -> None:
        """A valid setup creates an IDevID truststore and a DevID registration."""
        form = OwnerCredentialOnboardingSetupForm(
            data={'domain': domain.pk, 'serial_number_pattern': '^SN-[0-9]+$'},
            files=self._files(),
            owner_credential=owner,
        )

        assert form.is_valid(), form.errors
        truststore = form.cleaned_data['_truststore']
        registration = form.cleaned_data['_dev_id_registration']
        assert truststore.intended_usage == TruststoreModel.IntendedUsage.IDEVID
        assert registration.domain == domain
        assert registration.serial_number_pattern == '^SN-[0-9]+$'

    def test_truststore_name_collision_is_resolved(
        self, owner: OwnerCredentialModel, domain: DomainModel
    ) -> None:
        """Repeated setups produce uniquely suffixed truststore names."""
        first = OwnerCredentialOnboardingSetupForm(
            data={'unique_name': 'anchor', 'domain': domain.pk, 'serial_number_pattern': '^A$'},
            files=self._files(),
            owner_credential=owner,
        )
        assert first.is_valid(), first.errors

        second = OwnerCredentialOnboardingSetupForm(
            data={'unique_name': 'anchor', 'domain': domain.pk, 'serial_number_pattern': '^B$'},
            files=self._files(),
            owner_credential=owner,
        )

        assert second.is_valid(), second.errors
        assert second.cleaned_data['_truststore'].unique_name == 'idevid-ts-anchor-1'
        assert second.cleaned_data['_dev_id_registration'].unique_name == 'reg-anchor-1'

    def test_malformed_truststore_file_is_rejected(
        self, owner: OwnerCredentialModel, domain: DomainModel
    ) -> None:
        """A corrupt trust anchor file is rejected before anything is stored."""
        form = OwnerCredentialOnboardingSetupForm(
            data={'domain': domain.pk, 'serial_number_pattern': '^A$'},
            files={'trust_store_file': SimpleUploadedFile('ts.pem', b'not-a-certificate')},
            owner_credential=owner,
        )

        assert not form.is_valid()
        assert 'malformed' in str(form.errors).lower()
        assert not TruststoreModel.objects.filter(
            intended_usage=TruststoreModel.IntendedUsage.IDEVID
        ).exists()
        assert not DevIdRegistration.objects.exists()

    def test_missing_required_fields_short_circuit(self, owner: OwnerCredentialModel) -> None:
        """Missing domain or pattern stops processing without side effects."""
        form = OwnerCredentialOnboardingSetupForm(
            data={'serial_number_pattern': '^A$'}, files=self._files(), owner_credential=owner
        )

        assert not form.is_valid()
        assert 'domain' in form.errors
        assert not TruststoreModel.objects.filter(
            intended_usage=TruststoreModel.IntendedUsage.IDEVID
        ).exists()


class TestOwnerCredentialTruststoreAssociationForm:
    """TLS truststore association for remote DevOwnerIDs."""

    @pytest.fixture
    def truststore(self) -> TruststoreModel:
        """Return a TLS truststore selectable by the form."""
        return TruststoreModel.objects.create(
            unique_name='tls-anchor', intended_usage=TruststoreModel.IntendedUsage.TLS
        )

    def test_queryset_is_limited_to_tls_truststores(self, truststore: TruststoreModel) -> None:
        """Only TLS truststores can be associated."""
        TruststoreModel.objects.create(
            unique_name='idevid-anchor', intended_usage=TruststoreModel.IntendedUsage.IDEVID
        )
        owner = OwnerCredentialModel.objects.create(unique_name='assoc-owner')

        form = OwnerCredentialTruststoreAssociationForm(instance=owner)

        assert list(form.fields['trust_store'].queryset) == [truststore]

    def test_initial_reflects_configured_truststore(self, truststore: TruststoreModel) -> None:
        """An already configured truststore is pre-selected."""
        config = NoOnboardingConfigModel(
            pki_protocols=NoOnboardingPkiProtocol.MANUAL, trust_store=truststore
        )
        config.save()
        owner = OwnerCredentialModel.objects.create(unique_name='assoc-initial', no_onboarding_config=config)

        form = OwnerCredentialTruststoreAssociationForm(instance=owner)

        assert form.fields['trust_store'].initial == truststore

    def test_save_persists_truststore_on_no_onboarding_config(self, truststore: TruststoreModel) -> None:
        """Saving attaches the truststore to the no-onboarding configuration."""
        config = NoOnboardingConfigModel(pki_protocols=NoOnboardingPkiProtocol.MANUAL)
        config.save()
        owner = OwnerCredentialModel.objects.create(unique_name='assoc-save', no_onboarding_config=config)
        form = OwnerCredentialTruststoreAssociationForm(
            data={'trust_store': truststore.pk}, instance=owner
        )
        assert form.is_valid(), form.errors

        form.save()

        config.refresh_from_db()
        assert config.trust_store == truststore

    def test_save_without_any_config_raises(self, truststore: TruststoreModel) -> None:
        """A DevOwnerID without any config cannot store a truststore."""
        owner = OwnerCredentialModel.objects.create(unique_name='assoc-noconfig')
        owner.no_onboarding_config = None
        form = OwnerCredentialTruststoreAssociationForm(
            data={'trust_store': truststore.pk}, instance=owner
        )
        assert form.is_valid(), form.errors

        with pytest.raises(ValidationError):
            form.save()


class TestOwnerCredentialEstForms:
    """EST-based DevOwnerID request forms."""

    def _payload(self, **overrides: Any) -> dict[str, Any]:
        payload = {
            'remote_host': 'est.example.com',
            'remote_port': 443,
            'remote_path': '/.well-known/est/simpleenroll',
            'key_type': 'ECC-SECP256R1',
            'est_username': 'operator',
            'est_password': TEST_KEY_PASSWORD,
        }
        payload.update(overrides)
        return payload

    def test_basic_auth_form_prepares_config_and_key(self) -> None:
        """A valid basic-auth request generates a key and no-onboarding config."""
        form = OwnerCredentialAddRequestEstNoOnboardingForm(data=self._payload())

        assert form.is_valid(), form.errors
        assert form.cleaned_data['unique_name'] == 'est.example.com'
        assert form.cleaned_data['_private_key'] is not None
        assert form.cleaned_data['_no_onboarding_config'].pk is not None
        assert form.cleaned_data['_est_username'] == 'operator'

    @pytest.mark.parametrize('key_type', ['RSA-2048', 'ECC-SECP384R1'])
    def test_key_type_choice_controls_generated_key(self, key_type: str) -> None:
        """The selected key type determines the generated key algorithm."""
        form = OwnerCredentialAddRequestEstNoOnboardingForm(data=self._payload(key_type=key_type))

        assert form.is_valid(), form.errors
        private_key = form.cleaned_data['_private_key']
        if key_type.startswith('RSA-'):
            assert private_key.key_size == int(key_type.split('-')[1])
        else:
            assert private_key.curve.name == 'secp384r1'

    def test_name_collision_is_resolved_from_host(self) -> None:
        """A host-derived name that already exists gains a numeric suffix."""
        OwnerCredentialModel.objects.create(unique_name='est.example.com')
        form = OwnerCredentialAddRequestEstNoOnboardingForm(data=self._payload())

        assert form.is_valid(), form.errors
        assert form.cleaned_data['unique_name'] == 'est.example.com-1'

    def test_explicit_duplicate_name_is_rejected(self) -> None:
        """An explicitly supplied duplicate name is rejected."""
        OwnerCredentialModel.objects.create(unique_name='explicit-oc')
        form = OwnerCredentialAddRequestEstNoOnboardingForm(data=self._payload(unique_name='explicit-oc'))

        assert not form.is_valid()
        assert 'already exists' in str(form.errors)

    def test_missing_credentials_short_circuit(self) -> None:
        """Without EST credentials the form does not create any config."""
        form = OwnerCredentialAddRequestEstNoOnboardingForm(data=self._payload(est_username='', est_password=''))

        assert not form.is_valid()
        assert not NoOnboardingConfigModel.objects.exists()

    def test_onboarding_form_prepares_onboarding_config(self) -> None:
        """The mTLS variant prepares an onboarding config and both EST paths."""
        form = OwnerCredentialAddRequestEstOnboardingForm(
            data=self._payload(remote_path_domain_credential='/.well-known/est/dc')
        )

        assert form.is_valid(), form.errors
        assert form.cleaned_data['_onboarding_config'].pk is not None
        assert form.cleaned_data['_remote_path_domain_credential'] == '/.well-known/est/dc'
        assert form.cleaned_data['_private_key'] is not None

    def test_onboarding_form_rejects_duplicate_name(self) -> None:
        """The mTLS variant also rejects an existing DevOwnerID name."""
        OwnerCredentialModel.objects.create(unique_name='mtls-existing')
        form = OwnerCredentialAddRequestEstOnboardingForm(
            data=self._payload(unique_name='mtls-existing', remote_path_domain_credential='/dc')
        )

        assert not form.is_valid()
        assert 'already exists' in str(form.errors)
