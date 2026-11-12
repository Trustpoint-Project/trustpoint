# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the DevOwnerID (owner credential) API serializers."""

from __future__ import annotations

from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework import serializers

from pki.models import RemoteIssuedCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.serializer.owner_credential import (
    CertificateIssuanceContentSerializer,
    OwnerCredentialFileImportSerializer,
    OwnerCredentialSerializer,
)
from pki.util.x509 import CertificateGenerator

pytestmark = pytest.mark.django_db

TEST_KEY_PASSWORD = 'unit-test-secret-password'  # noqa: S105


def _dev_owner_id_material() -> tuple[x509.Certificate, Any, x509.Certificate]:
    """Return a DevOwnerID certificate with an IDevID SAN reference plus its key and issuer."""
    root, root_key = CertificateGenerator.create_root_ca('DevOwner Root')
    san = x509.SubjectAlternativeName([x509.UniformResourceIdentifier('dev-owner:SN1.SN2.FINGERPRINT')])
    certificate, private_key = CertificateGenerator.create_ee(
        root_key, root.subject, 'DevOwnerID', extensions=[(san, False)]
    )
    return certificate, private_key, root


def _key_bytes(private_key: Any, password: str | None = None) -> bytes:
    """Serialize a private key to PEM, optionally encrypted."""
    encryption: serialization.KeySerializationEncryption = serialization.NoEncryption()
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def _upload(name: str, data: bytes) -> SimpleUploadedFile:
    """Wrap raw bytes in an uploaded file."""
    return SimpleUploadedFile(name, data)


class TestOwnerCredentialSerializer:
    """Read-only representation of a DevOwnerID credential row."""

    def test_certificate_pem_is_none_before_issuance(self) -> None:
        """No DevOwnerID certificate is exposed before one is issued."""
        from pki.models.credential import CredentialModel

        credential = CredentialModel.objects.create(credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID)
        owner = RemoteIssuedCredentialModel.objects.create(
            common_name='oc-3',
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
            credential=credential,
        )

        assert OwnerCredentialSerializer(owner).data['devownerid_certificate_pem'] is None

    def test_issued_certificate_is_exposed_as_pem(self) -> None:
        """An issued DevOwnerID certificate is exposed in PEM form."""
        certificate, private_key, _root = _dev_owner_id_material()
        from trustpoint_core.serializer import CredentialSerializer

        owner = RemoteIssuedCredentialModel.create_imported_dev_owner_id(
            common_name='oc-issued',
            credential_serializer=CredentialSerializer(
                private_key=private_key, certificate=certificate, additional_certificates=[]
            ),
        )

        assert owner.certificate_profile_id is None
        assert owner.issued_using_cert_profile == ''
        data = OwnerCredentialSerializer(owner).data
        assert data['devownerid_certificate_pem'].startswith('-----BEGIN CERTIFICATE-----')

    def test_private_key_material_is_never_serialized(self) -> None:
        """Serialized DevOwnerIDs never expose private keys or passwords."""
        certificate, private_key, _root = _dev_owner_id_material()
        from trustpoint_core.serializer import CredentialSerializer

        owner = RemoteIssuedCredentialModel.create_imported_dev_owner_id(
            common_name='oc-secret',
            credential_serializer=CredentialSerializer(
                private_key=private_key, certificate=certificate, additional_certificates=[]
            ),
        )

        payload = str(OwnerCredentialSerializer(owner).data)
        assert 'PRIVATE KEY' not in payload
        assert TEST_KEY_PASSWORD not in payload


class TestOwnerCredentialFileImportSerializer:
    """File-based DevOwnerID import validation."""

    def _files(self, **overrides: Any) -> dict[str, Any]:
        certificate, private_key, root = _dev_owner_id_material()
        files = {
            'certificate': _upload('cert.pem', certificate.public_bytes(serialization.Encoding.PEM)),
            'certificate_chain': _upload('chain.pem', root.public_bytes(serialization.Encoding.PEM)),
            'private_key_file': _upload('key.pem', _key_bytes(private_key)),
        }
        files.update(overrides)
        return files

    def test_valid_import_creates_owner_credential(self) -> None:
        """A matching certificate, chain and key import successfully."""
        serializer = OwnerCredentialFileImportSerializer(data=self._files())

        assert serializer.is_valid(), serializer.errors
        owner = serializer.save()
        assert isinstance(owner, RemoteIssuedCredentialModel)
        assert owner.common_name == 'DevOwnerID'

    def test_encrypted_key_requires_correct_password(self) -> None:
        """An encrypted private key is rejected when the password is wrong."""
        certificate, private_key, root = _dev_owner_id_material()
        files = {
            'certificate': _upload('cert.pem', certificate.public_bytes(serialization.Encoding.PEM)),
            'private_key_file': _upload('key.pem', _key_bytes(private_key, TEST_KEY_PASSWORD)),
            'private_key_file_password': 'wrong-password',
        }
        serializer = OwnerCredentialFileImportSerializer(data=files)

        assert not serializer.is_valid()
        assert 'private_key_file' in serializer.errors
        assert TEST_KEY_PASSWORD not in str(serializer.errors)

    def test_encrypted_key_is_accepted_with_correct_password(self) -> None:
        """An encrypted private key imports successfully with the right password."""
        certificate, private_key, _root = _dev_owner_id_material()
        serializer = OwnerCredentialFileImportSerializer(
            data={
                'certificate': _upload('cert.pem', certificate.public_bytes(serialization.Encoding.PEM)),
                'private_key_file': _upload('key.pem', _key_bytes(private_key, TEST_KEY_PASSWORD)),
                'private_key_file_password': TEST_KEY_PASSWORD,
            }
        )

        assert serializer.is_valid(), serializer.errors
        assert serializer.save().common_name == 'DevOwnerID'

    def test_corrupt_certificate_is_rejected(self) -> None:
        """Unparsable certificate bytes produce a certificate field error."""
        serializer = OwnerCredentialFileImportSerializer(
            data=self._files(certificate=_upload('cert.pem', b'not-a-certificate'))
        )

        assert not serializer.is_valid()
        assert 'certificate' in serializer.errors

    def test_corrupt_chain_is_rejected(self) -> None:
        """Unparsable chain bytes produce a chain field error."""
        serializer = OwnerCredentialFileImportSerializer(
            data=self._files(certificate_chain=_upload('chain.pem', b'not-a-chain'))
        )

        assert not serializer.is_valid()
        assert 'certificate_chain' in serializer.errors

    def test_duplicate_certificate_is_rejected(self) -> None:
        """The same DevOwnerID certificate cannot be imported twice."""
        files = self._files()
        first = OwnerCredentialFileImportSerializer(data=files)
        assert first.is_valid(), first.errors
        first.save()

        certificate_bytes = files['certificate']
        certificate_bytes.seek(0)
        second = OwnerCredentialFileImportSerializer(
            data={
                'certificate': _upload('cert.pem', certificate_bytes.read()),
                'private_key_file': _upload('key.pem', _key_bytes(_dev_owner_id_material()[1])),
            }
        )

        assert not second.is_valid()
        assert 'already uses this certificate' in str(second.errors['certificate'])

    def test_create_surfaces_model_validation_errors(self) -> None:
        """Certificates without an IDevID SAN reference are rejected on save."""
        root, root_key = CertificateGenerator.create_root_ca('No SAN Root')
        certificate, private_key = CertificateGenerator.create_ee(root_key, root.subject, 'No SAN Leaf')
        serializer = OwnerCredentialFileImportSerializer(
            data={
                'certificate': _upload('cert.pem', certificate.public_bytes(serialization.Encoding.PEM)),
                'private_key_file': _upload('key.pem', _key_bytes(private_key)),
            }
        )
        assert serializer.is_valid(), serializer.errors

        with pytest.raises(serializers.ValidationError):
            serializer.save()

        assert not RemoteIssuedCredentialModel.objects.exists()


class TestCertificateIssuanceContentSerializer:
    """Certificate content payload used by DevOwnerID issuance actions."""

    def test_unknown_profile_is_rejected(self) -> None:
        """A certificate profile id that does not exist is rejected."""
        serializer = CertificateIssuanceContentSerializer(data={'cert_profile_pk': 999999})

        assert not serializer.is_valid()
        assert 'cert_profile_pk' in serializer.errors

    def test_known_profile_and_content_are_accepted(self) -> None:
        """An existing profile with subject and SAN content validates."""
        profile = CertificateProfileModel.objects.create(
            unique_name='issuance-profile',
            display_name='Issuance',
            profile_json={'type': 'cert_profile'},
        )
        serializer = CertificateIssuanceContentSerializer(
            data={
                'cert_profile_pk': profile.pk,
                'common_name': 'device.example',
                'dns_names': 'device.example,alt.example',
                'days': 30,
            }
        )

        assert serializer.is_valid(), serializer.errors
        assert serializer.validated_data['common_name'] == 'device.example'

    def test_negative_validity_is_rejected(self) -> None:
        """Negative validity components are rejected."""
        serializer = CertificateIssuanceContentSerializer(data={'days': -1})

        assert not serializer.is_valid()
        assert 'days' in serializer.errors
