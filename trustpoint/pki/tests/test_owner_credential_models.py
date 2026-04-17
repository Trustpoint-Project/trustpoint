"""Tests for newly added OwnerCredentialModel and IDevIDReferenceModel code."""

from __future__ import annotations


import pytest

from onboarding.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol
from pki.models import OwnerCredentialModel
from pki.models.credential import CredentialModel, IDevIDReferenceModel
from pki.models import RemoteIssuedCredentialModel


@pytest.fixture(autouse=True)
def _enable_db(db: None) -> None:
    """Enable database access for all tests in this module."""


# ---------------------------------------------------------------------------
# IDevIDReferenceModel property parsing
# ---------------------------------------------------------------------------


class TestIDevIDReferenceModelProperties:
    """Tests for the IDevIDReferenceModel parsed properties."""

    @pytest.fixture()
    def owner_credential(self) -> OwnerCredentialModel:
        """Create a minimal OwnerCredentialModel."""
        return OwnerCredentialModel.objects.create(unique_name='test-oc')

    def _make_ref(self, owner: OwnerCredentialModel, ref: str) -> IDevIDReferenceModel:
        return IDevIDReferenceModel.objects.create(dev_owner_id=owner, idevid_ref=ref)

    def test_subject_serial_number(self, owner_credential: OwnerCredentialModel) -> None:
        """idevid_subject_serial_number returns the first dot-segment after stripping the prefix."""
        ref = self._make_ref(owner_credential, 'dev-owner:cert:SUBJ-SN_SHA256FP')
        assert ref.idevid_subject_serial_number == 'SUBJ-SN'

    def test_sha256_fingerprint(self, owner_credential: OwnerCredentialModel) -> None:
        """idevid_sha256_fingerprint returns the third dot-segment after stripping the prefix."""
        ref = self._make_ref(owner_credential, 'dev-owner:cert:SUBJ-SN_SHA256FP')
        assert ref.idevid_sha256_fingerprint == 'SHA256FP'

    def test_missing_segments_return_empty(self, owner_credential: OwnerCredentialModel) -> None:
        """Properties that reference a missing segment return an empty string."""
        ref = self._make_ref(owner_credential, 'dev-owner:ONLY')
        assert ref.idevid_subject_serial_number == 'ONLY'
        assert ref.idevid_sha256_fingerprint == ''

    def test_without_prefix(self, owner_credential: OwnerCredentialModel) -> None:
        """If the ref does not start with 'dev-owner:' parsing still works (no prefix to strip)."""
        ref = self._make_ref(owner_credential, 'A_B')
        assert ref.idevid_subject_serial_number == 'A'
        assert ref.idevid_sha256_fingerprint == 'B'

    def test_str(self, owner_credential: OwnerCredentialModel) -> None:
        """__str__ includes the owner name and the raw idevid_ref value."""
        ref = self._make_ref(owner_credential, 'dev-owner:A_B')
        assert str(ref) == 'test-oc - dev-owner:A_B'


# ---------------------------------------------------------------------------
# OwnerCredentialModel basic model behaviour
# ---------------------------------------------------------------------------


class TestOwnerCredentialModel:
    """Tests for OwnerCredentialModel fields and properties."""

    def test_str_returns_unique_name(self) -> None:
        """__str__ returns the unique_name."""
        oc = OwnerCredentialModel.objects.create(unique_name='my-owner')
        assert str(oc) == 'my-owner'

    def test_repr(self) -> None:
        """__repr__ includes the unique_name."""
        oc = OwnerCredentialModel.objects.create(unique_name='my-owner')
        assert 'my-owner' in repr(oc)

    def test_default_type_is_local(self) -> None:
        """The default owner_credential_type is LOCAL."""
        oc = OwnerCredentialModel.objects.create(unique_name='local-oc')
        assert oc.owner_credential_type == OwnerCredentialModel.OwnerCredentialTypeChoice.LOCAL

    def test_remote_est_type(self) -> None:
        """REMOTE_EST type can be set and persisted."""
        no_onboarding = NoOnboardingConfigModel(
            pki_protocols=NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD,
            est_password='pw',
        )
        no_onboarding.save()
        oc = OwnerCredentialModel.objects.create(
            unique_name='remote-oc',
            owner_credential_type=OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST,
            no_onboarding_config=no_onboarding,
            remote_host='est.example.com',
            remote_port=443,
            remote_path='/.well-known/est/simpleenroll',
            est_username='user',
            key_type='RSA-2048',
        )
        oc.refresh_from_db()
        assert oc.owner_credential_type == OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST
        assert oc.remote_host == 'est.example.com'
        assert oc.remote_port == 443
        assert oc.est_username == 'user'
        assert oc.key_type == 'RSA-2048'

    def test_dev_owner_id_credential_returns_none_when_empty(self) -> None:
        """dev_owner_id_credential returns None when no issued credentials exist."""
        oc = OwnerCredentialModel.objects.create(unique_name='empty-oc')
        assert oc.dev_owner_id_credential is None

    def test_dev_owner_id_credentials_returns_queryset(self) -> None:
        """dev_owner_id_credentials returns a queryset of DEV_OWNER_ID remote issued credentials."""
        oc = OwnerCredentialModel.objects.create(unique_name='oc-with-cred')
        cred = CredentialModel.objects.create(
            credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID,
        )
        issued = RemoteIssuedCredentialModel.objects.create(
            common_name='test-cn',
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
            credential=cred,
            owner_credential=oc,
        )
        result = list(oc.dev_owner_id_credentials)
        assert len(result) == 1
        assert result[0].pk == issued.pk

    def test_dev_owner_id_credential_returns_latest(self) -> None:
        """dev_owner_id_credential returns the most recently created credential."""
        oc = OwnerCredentialModel.objects.create(unique_name='oc-multi')
        cred1 = CredentialModel.objects.create(
            credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID,
        )
        RemoteIssuedCredentialModel.objects.create(
            common_name='first',
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
            credential=cred1,
            owner_credential=oc,
        )
        cred2 = CredentialModel.objects.create(
            credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID,
        )
        issued2 = RemoteIssuedCredentialModel.objects.create(
            common_name='second',
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
            credential=cred2,
            owner_credential=oc,
        )
        assert oc.dev_owner_id_credential is not None
        assert oc.dev_owner_id_credential.pk == issued2.pk

    def test_post_delete_removes_issued_credentials(self) -> None:
        """post_delete removes all associated remote issued credentials."""
        oc = OwnerCredentialModel.objects.create(unique_name='oc-delete')
        cred = CredentialModel.objects.create(
            credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID,
        )
        RemoteIssuedCredentialModel.objects.create(
            common_name='to-delete',
            issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
            credential=cred,
            owner_credential=oc,
        )
        oc.post_delete()
        assert not CredentialModel.objects.filter(pk=cred.pk).exists()
