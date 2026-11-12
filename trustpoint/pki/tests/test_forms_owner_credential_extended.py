# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for DevOwnerID (owner credential) form validation and setup flows."""

from __future__ import annotations

from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from django.core.files.uploadedfile import SimpleUploadedFile

from pki.forms.owner_credential import (
    OwnerCredentialFileImportForm,
    OwnerCredentialOnboardingSetupForm,
    OwnerCredentialPkcs12ImportForm,
)
from pki.models import RemoteIssuedCredentialModel
from pki.models.credential import CredentialModel
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
    return private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)


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


class TestOwnerCredentialPkcs12ImportForm:
    """Validation of the PKCS#12 DevOwnerID import."""

    def test_pkcs12_import_creates_owner_credential(self) -> None:
        """A certificate and key in one container create the DevOwnerID."""
        certificate, private_key, root = _dev_owner_id_material()
        container = pkcs12.serialize_key_and_certificates(
            b'devowner', private_key, certificate, [root], serialization.NoEncryption()
        )
        form = OwnerCredentialPkcs12ImportForm(
            files={'pkcs12_file': SimpleUploadedFile('owner.p12', container)},
        )

        assert form.is_valid(), form.errors
        assert form.cleaned_data['_dev_owner_id_credential'].common_name == 'FormDevOwnerID'


class TestOwnerCredentialFileImportForm:
    """Validation of the DevOwnerID file import form."""

    def test_valid_import_creates_owner_credential(self) -> None:
        """A consistent certificate, chain and key create the DevOwnerID."""
        form = OwnerCredentialFileImportForm(data={}, files=_import_files())

        assert form.is_valid(), form.errors
        owner = form.cleaned_data['_dev_owner_id_credential']
        assert isinstance(owner, RemoteIssuedCredentialModel)
        assert owner.common_name == 'FormDevOwnerID'

    def test_name_is_derived_from_certificate(self) -> None:
        """Without an explicit name the certificate subject is used."""
        form = OwnerCredentialFileImportForm(data={}, files=_import_files())

        assert form.is_valid(), form.errors
        assert form.cleaned_data['common_name']

    def test_oversized_private_key_is_rejected(self) -> None:
        """Private key uploads above the size limit are rejected."""
        files = _import_files(private_key_file=SimpleUploadedFile('key.pem', b'x' * (MAX_UPLOAD_BYTES + 1)))
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
                'certificate': SimpleUploadedFile('cert.pem', certificate.public_bytes(serialization.Encoding.PEM)),
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
                'certificate': SimpleUploadedFile('cert.pem', certificate.public_bytes(serialization.Encoding.PEM)),
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
            data={},
            files={
                'certificate': SimpleUploadedFile('cert.pem', certificate_pem),
                'private_key_file': SimpleUploadedFile('key.pem', _key_pem(private_key)),
            },
        )

        assert not second.is_valid()
        assert 'already configured' in str(second.errors['certificate'])

    def test_certificate_without_idevid_reference_is_rejected(self) -> None:
        """A certificate lacking an IDevID SAN reference cannot become a DevOwnerID."""
        root, root_key = CertificateGenerator.create_root_ca('No Ref Root')
        certificate, private_key = CertificateGenerator.create_ee(root_key, root.subject, 'No Ref Leaf')
        form = OwnerCredentialFileImportForm(
            data={},
            files={
                'certificate': SimpleUploadedFile('cert.pem', certificate.public_bytes(serialization.Encoding.PEM)),
                'private_key_file': SimpleUploadedFile('key.pem', _key_pem(private_key)),
            },
        )

        assert not form.is_valid()
        assert not RemoteIssuedCredentialModel.objects.exists()


class TestOwnerCredentialOnboardingSetupForm:
    """AOKI onboarding setup performed after a DevOwnerID import."""

    @pytest.fixture
    def owner(self) -> RemoteIssuedCredentialModel:
        """Return a stored DevOwnerID to attach the onboarding setup to."""
        credential = CredentialModel.objects.create(credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID)
        return RemoteIssuedCredentialModel.objects.create(
            common_name='aoki-owner',
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
            credential=credential,
        )

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
        self, owner: RemoteIssuedCredentialModel, domain: DomainModel
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
        self, owner: RemoteIssuedCredentialModel, domain: DomainModel
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
        self, owner: RemoteIssuedCredentialModel, domain: DomainModel
    ) -> None:
        """A corrupt trust anchor file is rejected before anything is stored."""
        form = OwnerCredentialOnboardingSetupForm(
            data={'domain': domain.pk, 'serial_number_pattern': '^A$'},
            files={'trust_store_file': SimpleUploadedFile('ts.pem', b'not-a-certificate')},
            owner_credential=owner,
        )

        assert not form.is_valid()
        assert 'malformed' in str(form.errors).lower()
        assert not TruststoreModel.objects.filter(intended_usage=TruststoreModel.IntendedUsage.IDEVID).exists()
        assert not DevIdRegistration.objects.exists()

    def test_missing_required_fields_short_circuit(self, owner: RemoteIssuedCredentialModel) -> None:
        """Missing domain or pattern stops processing without side effects."""
        form = OwnerCredentialOnboardingSetupForm(
            data={'serial_number_pattern': '^A$'}, files=self._files(), owner_credential=owner
        )

        assert not form.is_valid()
        assert 'domain' in form.errors
        assert not TruststoreModel.objects.filter(intended_usage=TruststoreModel.IntendedUsage.IDEVID).exists()
