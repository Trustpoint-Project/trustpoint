# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for CaModel hierarchy, CRL helpers and lifecycle behaviour."""

from __future__ import annotations

from typing import Any

import pytest
from cryptography import x509
from django.core.exceptions import ValidationError
from django_q.models import Schedule
from trustpoint_core import oid

from pki.models import CaModel
from pki.models.certificate import CertificateModel, RevokedCertificateModel
from pki.models.crl import CrlModel
from pki.tests.managed_ca_helpers import create_managed_issuing_ca, create_managed_root_ca
from pki.util.x509 import CertificateGenerator

pytestmark = pytest.mark.django_db


@pytest.fixture
def ca_hierarchy() -> dict[str, Any]:
    """Return a persisted root CA with an intermediate child CA."""
    root_cert, root_key = create_managed_root_ca(cn='Hierarchy Root')
    root_ca = CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=root_cert,
        private_key=root_key,
        chain=[],
        unique_name='hierarchy_root',
        ca_type=CaModel.CaTypeChoice.LOCAL_PKCS11,
    )
    child_cert, child_key = create_managed_issuing_ca(
        issuer_private_key=root_key, issuer_cn='Hierarchy Root', subject_cn='Hierarchy Child'
    )
    child_ca = CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=child_cert,
        private_key=child_key,
        chain=[root_cert],
        unique_name='hierarchy_child',
        ca_type=CaModel.CaTypeChoice.LOCAL_PKCS11,
        parent_ca=root_ca,
    )
    return {
        'root_ca': root_ca,
        'child_ca': child_ca,
        'root_cert': root_cert,
        'root_key': root_key,
        'child_cert': child_cert,
        'child_key': child_key,
    }


class TestCaCertificateValidation:
    """Validation applied before a CA is created."""

    def test_end_entity_certificate_is_rejected(self) -> None:
        """A non-CA certificate cannot be registered as a CA."""
        root, root_key = CertificateGenerator.create_root_ca('Validation Root')
        leaf, _ = CertificateGenerator.create_ee(root_key, root.subject, 'leaf')

        with pytest.raises(ValidationError, match='End Entity'):
            CaModel._validate_ca_certificate(leaf)

    def test_certificate_without_basic_constraints_is_rejected(self) -> None:
        """A certificate lacking BasicConstraints cannot be a CA."""
        root, root_key = CertificateGenerator.create_root_ca('No BC Root')
        certificate = (
            x509.CertificateBuilder()
            .subject_name(root.subject)
            .issuer_name(root.subject)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(root.not_valid_before_utc)
            .not_valid_after(root.not_valid_after_utc)
            .sign(root_key, root.signature_hash_algorithm)
        )

        with pytest.raises(ValidationError, match='Basic Constraints'):
            CaModel._validate_ca_certificate(certificate)

    @pytest.mark.parametrize(
        'ca_type',
        [
            CaModel.CaTypeChoice.KEYLESS,
            CaModel.CaTypeChoice.REMOTE_EST_RA,
            CaModel.CaTypeChoice.REMOTE_CMP_RA,
        ],
    )
    def test_non_issuing_ca_types_are_rejected(self, ca_type: CaModel.CaTypeChoice) -> None:
        """Only issuing CA types may be used for issuing CAs."""
        with pytest.raises(ValueError, match='not supported for issuing CAs'):
            CaModel._validate_ca_type(ca_type)

    def test_unique_name_is_derived_from_common_name(self) -> None:
        """The CA name is derived from the certificate common name."""
        root, _ = CertificateGenerator.create_root_ca('Derived CA Name')

        assert CaModel._generate_unique_name(root) == 'Derived CA Name'

    def test_unique_name_falls_back_when_common_name_missing(self) -> None:
        """A certificate without a common name falls back to a generic name."""
        root, root_key = CertificateGenerator.create_root_ca('Fallback Root')
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(root.subject)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(root.not_valid_before_utc)
            .not_valid_after(root.not_valid_after_utc)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(root_key, root.signature_hash_algorithm)
        )

        assert CaModel._generate_unique_name(certificate) == 'CA'


class TestCaHierarchy:
    """Parent and child relationships between CAs."""

    def test_depth_and_root_resolution(self, ca_hierarchy: dict[str, Any]) -> None:
        """Depth and root lookups follow the parent chain."""
        root_ca, child_ca = ca_hierarchy['root_ca'], ca_hierarchy['child_ca']

        assert root_ca.get_hierarchy_depth() == 0
        assert child_ca.get_hierarchy_depth() == 1
        assert child_ca.get_root_ca() == root_ca
        assert root_ca.get_root_ca() == root_ca

    def test_hierarchy_path_runs_from_root_to_leaf(self, ca_hierarchy: dict[str, Any]) -> None:
        """The hierarchy path is ordered from the root down to the CA."""
        assert ca_hierarchy['child_ca'].get_hierarchy_path() == [
            ca_hierarchy['root_ca'],
            ca_hierarchy['child_ca'],
        ]

    def test_child_cas_are_collected_recursively(self, ca_hierarchy: dict[str, Any]) -> None:
        """Descendant lookups include children and optionally the CA itself."""
        root_ca, child_ca = ca_hierarchy['root_ca'], ca_hierarchy['child_ca']

        assert list(root_ca.get_all_child_cas()) == [child_ca]
        assert set(root_ca.get_all_child_cas(include_self=True)) == {root_ca, child_ca}
        assert list(child_ca.get_all_child_cas()) == []

    def test_self_signed_ca_is_detected_as_root(self, ca_hierarchy: dict[str, Any]) -> None:
        """A self-signed CA without a parent is reported as a root CA."""
        assert ca_hierarchy['root_ca'].is_root_ca() is True

    def test_ca_with_parent_is_not_a_root(self, ca_hierarchy: dict[str, Any]) -> None:
        """A CA with a parent is never a root CA."""
        assert ca_hierarchy['child_ca'].is_root_ca() is False

    def test_non_self_signed_ca_without_parent_is_not_a_root(self, ca_hierarchy: dict[str, Any]) -> None:
        """A CA signed by another CA is not a root even without a parent link."""
        child_ca = ca_hierarchy['child_ca']
        child_ca.parent_ca = None
        child_ca.save()

        assert child_ca.is_root_ca() is False

    def test_root_detection_requires_a_certificate(self) -> None:
        """Root detection fails when no certificate is available."""
        ca = CaModel(unique_name='no-cert-ca', ca_type=CaModel.CaTypeChoice.LOCAL_PKCS11)

        with pytest.raises(ValueError, match='no certificate model'):
            ca.is_root_ca()

    def test_chain_truststore_contains_the_full_path(self, ca_hierarchy: dict[str, Any]) -> None:
        """The generated chain truststore holds every CA in the path."""
        child_ca = ca_hierarchy['child_ca']

        truststore = child_ca.chain_truststore

        assert truststore is not None
        assert truststore.number_of_certificates == 2


class TestCaSignatureSuite:
    """Signature suite and public key info exposure."""

    def test_issuing_ca_reports_signature_suite(self, ca_hierarchy: dict[str, Any]) -> None:
        """An issuing CA derives its suite from the credential certificate."""
        root_ca = ca_hierarchy['root_ca']
        expected = oid.SignatureSuite.from_certificate(ca_hierarchy['root_cert'])

        assert root_ca.signature_suite == expected
        assert root_ca.public_key_info == expected.public_key_info
        assert root_ca.signature_suite_display != '-'

    def test_keyless_ca_reports_signature_suite(self) -> None:
        """A keyless CA derives its suite from the stored certificate."""
        certificate, _ = CertificateGenerator.create_root_ca('Keyless Suite CA')
        ca = CaModel.create_keyless_ca(unique_name='keyless-suite', certificate_obj=certificate)

        assert ca.signature_suite == oid.SignatureSuite.from_certificate(certificate)

    def test_missing_certificate_yields_no_suite(self) -> None:
        """A CA without a certificate has no signature suite."""
        ca = CaModel(unique_name='pending-ca', ca_type=CaModel.CaTypeChoice.LOCAL_PKCS11)

        assert ca.signature_suite is None
        assert ca.public_key_info is None
        assert ca.signature_suite_display == '-'


class TestCaIssuedCertificates:
    """Certificates attributed to a CA."""

    def test_issued_certificates_exclude_the_ca_itself(self, ca_hierarchy: dict[str, Any]) -> None:
        """A self-signed CA certificate is not reported as issued by itself."""
        root_ca = ca_hierarchy['root_ca']
        leaf, _ = CertificateGenerator.create_ee(
            ca_hierarchy['root_key'], ca_hierarchy['root_cert'].subject, 'issued-leaf'
        )
        CertificateModel.save_certificate(leaf)

        names = {cert.common_name for cert in root_ca.get_issued_certificates()}

        assert 'issued-leaf' in names
        assert 'Hierarchy Child' in names
        assert 'Hierarchy Root' not in names

    def test_keyless_ca_reports_no_issued_certificates(self) -> None:
        """Keyless CAs never report issued certificates."""
        certificate, _ = CertificateGenerator.create_root_ca('Keyless Issued CA')
        ca = CaModel.create_keyless_ca(unique_name='keyless-issued', certificate_obj=certificate)

        assert not ca.get_issued_certificates().exists()

    def test_revoking_all_certificates_records_reason(self, ca_hierarchy: dict[str, Any]) -> None:
        """Revoking all issued certificates records the given reason."""
        child_ca = ca_hierarchy['child_ca']
        leaf, _ = CertificateGenerator.create_ee(
            ca_hierarchy['child_key'], ca_hierarchy['child_cert'].subject, 'revoked-leaf'
        )
        CertificateModel.save_certificate(leaf)

        child_ca.revoke_all_issued_certificates(reason=RevokedCertificateModel.ReasonCode.CESSATION)

        revoked = RevokedCertificateModel.objects.get(ca=child_ca)
        assert revoked.certificate.common_name == 'revoked-leaf'
        assert revoked.revocation_reason == RevokedCertificateModel.ReasonCode.CESSATION

    def test_already_revoked_certificates_are_not_revoked_twice(
        self, ca_hierarchy: dict[str, Any]
    ) -> None:
        """Revocation is idempotent for certificates that are no longer valid."""
        child_ca = ca_hierarchy['child_ca']
        leaf, _ = CertificateGenerator.create_ee(
            ca_hierarchy['child_key'], ca_hierarchy['child_cert'].subject, 'twice-leaf'
        )
        CertificateModel.save_certificate(leaf)
        child_ca.revoke_all_issued_certificates()

        child_ca.revoke_all_issued_certificates()

        assert RevokedCertificateModel.objects.filter(ca=child_ca).count() == 1


class TestCaCrlHelpers:
    """CRL storage and retrieval helpers."""

    def test_active_and_latest_crl_are_reported(self, ca_hierarchy: dict[str, Any]) -> None:
        """Issuing a CRL exposes it as both active and latest."""
        root_ca = ca_hierarchy['root_ca']

        assert root_ca.get_active_crl() is None
        assert root_ca.get_latest_crl() is None
        assert root_ca.get_crl_as_crypto() is None

        assert root_ca.issue_crl() is True

        active = root_ca.get_active_crl()
        assert active is not None
        assert root_ca.get_latest_crl() == active
        assert isinstance(root_ca.get_crl_as_crypto(), x509.CertificateRevocationList)

    def test_crl_number_increases_with_each_issuance(self, ca_hierarchy: dict[str, Any]) -> None:
        """Each generated CRL carries an increasing CRL number."""
        root_ca = ca_hierarchy['root_ca']
        root_ca.issue_crl()
        first = root_ca.crl_number

        root_ca.issue_crl()

        assert root_ca.crl_number == first + 1

    def test_keyless_ca_cannot_issue_a_crl(self) -> None:
        """A keyless CA has no signing key and cannot issue CRLs."""
        certificate, _ = CertificateGenerator.create_root_ca('Keyless CRL CA')
        ca = CaModel.create_keyless_ca(unique_name='keyless-crl', certificate_obj=certificate)

        assert ca.issue_crl() is False

    def test_imported_crl_becomes_active(self, ca_hierarchy: dict[str, Any]) -> None:
        """An imported CRL is stored and becomes the active CRL."""
        root_ca = ca_hierarchy['root_ca']
        from pki.util.crl import generate_empty_crl

        crl_pem = generate_empty_crl(ca_hierarchy['root_cert'], ca_hierarchy['root_key'])

        crl = root_ca.import_crl(crl_pem)

        assert isinstance(crl, CrlModel)
        assert root_ca.get_active_crl() == crl
        assert root_ca.crl_pem.startswith('-----BEGIN X509 CRL-----')


class TestCaCrlScheduling:
    """Scheduling of periodic CRL generation."""

    def test_scheduling_is_skipped_when_cycle_disabled(self, ca_hierarchy: dict[str, Any]) -> None:
        """No schedule is created while the CRL cycle is disabled."""
        root_ca = ca_hierarchy['root_ca']
        root_ca.crl_cycle_enabled = False

        root_ca.schedule_next_crl_generation()

        assert not Schedule.objects.filter(name__startswith=f'crl_gen_{root_ca.unique_name}').exists()

    def test_enabled_cycle_creates_a_single_schedule(self, ca_hierarchy: dict[str, Any]) -> None:
        """Enabling the cycle schedules exactly one future generation."""
        root_ca = ca_hierarchy['root_ca']
        root_ca.crl_cycle_enabled = True
        root_ca.crl_cycle_interval_hours = 6

        root_ca.schedule_next_crl_generation()
        root_ca.schedule_next_crl_generation()

        schedules = Schedule.objects.filter(name__startswith=f'crl_gen_{root_ca.unique_name}')
        assert schedules.count() == 1
        assert root_ca.last_crl_generation_started_at is not None

    def test_post_revocation_schedule_bypasses_the_cycle_flag(self, ca_hierarchy: dict[str, Any]) -> None:
        """A post-revocation CRL is scheduled even when the cycle is off."""
        root_ca = ca_hierarchy['root_ca']
        root_ca.crl_cycle_enabled = False

        root_ca.schedule_next_crl_generation(post_revocation_crl=True)

        assert Schedule.objects.filter(name__startswith=f'crl_gen_{root_ca.unique_name}').exists()


class TestCaDeletion:
    """Deletion guards protecting the CA hierarchy."""

    def test_ca_with_children_cannot_be_deleted(self, ca_hierarchy: dict[str, Any]) -> None:
        """A CA that still has child CAs cannot be removed."""
        with pytest.raises(ValidationError, match='child CAs'):
            ca_hierarchy['root_ca'].pre_delete()

    def test_ca_with_unexpired_certificates_cannot_be_deleted(
        self, ca_hierarchy: dict[str, Any]
    ) -> None:
        """A CA that issued still-valid certificates cannot be removed."""
        child_ca = ca_hierarchy['child_ca']
        leaf, _ = CertificateGenerator.create_ee(
            ca_hierarchy['child_key'], ca_hierarchy['child_cert'].subject, 'blocking-leaf'
        )
        CertificateModel.save_certificate(leaf)

        with pytest.raises(ValidationError, match='unexpired certificate'):
            child_ca.pre_delete()

    def test_leaf_ca_without_issued_certificates_can_be_deleted(
        self, ca_hierarchy: dict[str, Any]
    ) -> None:
        """A CA with no children and no live certificates deletes cleanly."""
        child_ca = ca_hierarchy['child_ca']

        child_ca.delete()

        assert not CaModel.objects.filter(unique_name='hierarchy_child').exists()

    def test_display_not_valid_after_prefers_credential_certificate(
        self, ca_hierarchy: dict[str, Any]
    ) -> None:
        """The displayed expiry is taken from the CA certificate."""
        root_ca = ca_hierarchy['root_ca']

        assert root_ca.display_not_valid_after == root_ca.credential.certificate.not_valid_after

    def test_display_not_valid_after_is_none_without_certificate(self) -> None:
        """A CA without any certificate has no displayable expiry."""
        ca = CaModel(unique_name='pending-expiry', ca_type=CaModel.CaTypeChoice.LOCAL_PKCS11)

        assert ca.display_not_valid_after is None
