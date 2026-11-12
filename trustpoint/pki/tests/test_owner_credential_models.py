# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for DevOwnerID credential rows and IDevIDReferenceModel."""

from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError
from django.db.models.deletion import ProtectedError

from pki.models import RemoteIssuedCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.credential import CredentialModel, IDevIDReferenceModel


@pytest.fixture(autouse=True)
def _enable_db(db: None) -> None:
    """Enable database access for all tests in this module."""


def _make_dev_owner_id(common_name: str = 'test-oc') -> RemoteIssuedCredentialModel:
    credential = CredentialModel.objects.create(credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID)
    return RemoteIssuedCredentialModel.objects.create(
        common_name=common_name,
        issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
        credential=credential,
    )


# ---------------------------------------------------------------------------
# IDevIDReferenceModel property parsing
# ---------------------------------------------------------------------------


class TestIDevIDReferenceModelProperties:
    """Tests for the IDevIDReferenceModel parsed properties."""

    @pytest.fixture
    def dev_owner_id(self) -> RemoteIssuedCredentialModel:
        """Create a minimal DevOwnerID credential row."""
        return _make_dev_owner_id()

    def _make_ref(self, owner: RemoteIssuedCredentialModel, ref: str) -> IDevIDReferenceModel:
        return IDevIDReferenceModel.objects.create(dev_owner_id=owner, idevid_ref=ref)

    def test_subject_serial_number(self, dev_owner_id: RemoteIssuedCredentialModel) -> None:
        """idevid_subject_serial_number returns the first dot-segment after stripping the prefix."""
        ref = self._make_ref(dev_owner_id, 'dev-owner:cert:SUBJ-SN_SHA256FP')
        assert ref.idevid_subject_serial_number == 'SUBJ-SN'

    def test_sha256_fingerprint(self, dev_owner_id: RemoteIssuedCredentialModel) -> None:
        """idevid_sha256_fingerprint returns the third dot-segment after stripping the prefix."""
        ref = self._make_ref(dev_owner_id, 'dev-owner:cert:SUBJ-SN_SHA256FP')
        assert ref.idevid_sha256_fingerprint == 'SHA256FP'

    def test_missing_segments_return_empty(self, dev_owner_id: RemoteIssuedCredentialModel) -> None:
        """Properties that reference a missing segment return an empty string."""
        ref = self._make_ref(dev_owner_id, 'dev-owner:cert:ONLY')
        assert ref.idevid_subject_serial_number == 'ONLY'
        assert ref.idevid_sha256_fingerprint == ''

    def test_without_prefix(self, dev_owner_id: RemoteIssuedCredentialModel) -> None:
        """If the ref does not start with 'dev-owner:cert:' the values are empty."""
        ref = self._make_ref(dev_owner_id, 'A_B')
        assert ref.idevid_subject_serial_number == ''
        assert ref.idevid_sha256_fingerprint == ''

    def test_str(self, dev_owner_id: RemoteIssuedCredentialModel) -> None:
        """__str__ includes the common name and the raw idevid_ref value."""
        ref = self._make_ref(dev_owner_id, 'dev-owner:A_B')
        assert str(ref) == 'test-oc - dev-owner:A_B'


def test_remote_profile_reference_drives_label_and_protects_profile() -> None:
    """The profile label follows display_name and protects the profile from deletion."""
    profile = CertificateProfileModel.objects.create(
        unique_name='remote_profile', display_name='Original', profile_json={}
    )
    credential = CredentialModel.objects.create(credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID)
    record = RemoteIssuedCredentialModel.objects.create(
        common_name='remote-owner',
        credential=credential,
        issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
        certificate_profile=profile,
    )
    profile.display_name = 'Renamed'
    profile.save(update_fields=['display_name'])
    record.refresh_from_db()
    assert record.issued_using_cert_profile == 'Renamed'
    with pytest.raises(ProtectedError):
        profile.delete()
    profile.display_name = ''
    profile.save(update_fields=['display_name'])
    record.refresh_from_db()
    assert record.issued_using_cert_profile == 'remote_profile'
    assert 'issued_using_cert_profile' not in {field.name for field in record._meta.fields}  # noqa: SLF001


def test_imported_owner_credentials_may_omit_profile() -> None:
    """Imported DevOwnerIDs need no certificate profile."""
    record = _make_dev_owner_id()
    record.clean()
    assert record.issued_using_cert_profile == ''


def test_managed_owner_credentials_require_profile() -> None:
    """Managed DevOwnerIDs require a certificate profile."""
    record = _make_dev_owner_id()
    record.ca_id = 1
    with pytest.raises(ValidationError, match='profile is required'):
        record.clean()
