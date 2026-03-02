"""Tests for auto-issuing CRLs after certificate revocation."""

from __future__ import annotations

from typing import Any

import pytest
from django.utils import timezone
from django_q.models import Schedule  # type: ignore[import-untyped]

from pki.models import CertificateModel, RevokedCertificateModel
from pki.util.x509 import CertificateGenerator


@pytest.mark.django_db
@pytest.mark.parametrize('crl_cycle_enabled', [False, True])
def test_revocation_signal_schedules_crl_generation(
    issuing_ca_instance: dict[str, Any],
    crl_cycle_enabled: bool,
) -> None:
    """Revoking a certificate schedules CRL generation after ~30 seconds."""
    issuing_ca = issuing_ca_instance['issuing_ca']
    issuing_ca.crl_cycle_enabled = crl_cycle_enabled
    issuing_ca.auto_crl_on_revocation_enabled = True
    issuing_ca.save(update_fields=['crl_cycle_enabled', 'auto_crl_on_revocation_enabled'])

    Schedule.objects.all().delete()

    cert_model = CertificateModel.save_certificate(
        CertificateGenerator.create_ee(
            issuer_private_key=issuing_ca_instance['priv_key'],
            issuer_name=issuing_ca_instance['cert'].subject,
            subject_name='Revocation Test Cert 1',
        )[0]
    )

    RevokedCertificateModel.objects.create(
        certificate=cert_model,
        ca=issuing_ca,
        revocation_reason=RevokedCertificateModel.ReasonCode.UNSPECIFIED,
    )

    issuing_ca.refresh_from_db()
    assert issuing_ca.last_crl_generation_started_at is not None

    time_diff = (issuing_ca.last_crl_generation_started_at - timezone.now()).total_seconds()
    assert 20 < time_diff < 40

    schedule = Schedule.objects.get(name__startswith=f'crl_gen_{issuing_ca.unique_name}')
    schedule_diff = (schedule.next_run - issuing_ca.last_crl_generation_started_at).total_seconds()
    assert abs(schedule_diff) < 2

    base_name = f'crl_gen_{issuing_ca.unique_name}'
    assert Schedule.objects.filter(name__startswith=base_name).count() == 1


@pytest.mark.django_db
def test_revocation_signal_respects_auto_crl_flag(issuing_ca_instance: dict[str, Any]) -> None:
    """Revoking a certificate does not schedule CRL when auto CRL is disabled."""
    issuing_ca = issuing_ca_instance['issuing_ca']
    issuing_ca.auto_crl_on_revocation_enabled = False
    issuing_ca.crl_cycle_enabled = True
    issuing_ca.save(update_fields=['auto_crl_on_revocation_enabled', 'crl_cycle_enabled'])

    Schedule.objects.all().delete()

    cert_model = CertificateModel.save_certificate(
        CertificateGenerator.create_ee(
            issuer_private_key=issuing_ca_instance['priv_key'],
            issuer_name=issuing_ca_instance['cert'].subject,
            subject_name='Revocation Test Cert 2',
        )[0]
    )

    RevokedCertificateModel.objects.create(
        certificate=cert_model,
        ca=issuing_ca,
        revocation_reason=RevokedCertificateModel.ReasonCode.KEY_COMPROMISE,
    )

    issuing_ca.refresh_from_db()
    assert issuing_ca.last_crl_generation_started_at is not None
    # check schedule is more than 1 min in the future (not due to revocation, but regular cycle if enabled) or does not exist
    schedule = Schedule.objects.filter(name__startswith=f'crl_gen_{issuing_ca.unique_name}').first()
    if schedule:
        schedule_diff = (schedule.next_run - timezone.now()).total_seconds()
        assert schedule_diff > 60


@pytest.mark.django_db
def test_revocation_signal_deduplicates_schedule_per_ca(issuing_ca_instance: dict[str, Any]) -> None:
    """Multiple revocations for the same CA should create only one schedule."""
    issuing_ca = issuing_ca_instance['issuing_ca']
    issuing_ca.auto_crl_on_revocation_enabled = True
    issuing_ca.save(update_fields=['auto_crl_on_revocation_enabled'])

    Schedule.objects.all().delete()

    cert_model_1 = CertificateModel.save_certificate(
        CertificateGenerator.create_ee(
            issuer_private_key=issuing_ca_instance['priv_key'],
            issuer_name=issuing_ca_instance['cert'].subject,
            subject_name='Revocation Test Cert 3',
        )[0]
    )
    cert_model_2 = CertificateModel.save_certificate(
        CertificateGenerator.create_ee(
            issuer_private_key=issuing_ca_instance['priv_key'],
            issuer_name=issuing_ca_instance['cert'].subject,
            subject_name='Revocation Test Cert 4',
        )[0]
    )

    RevokedCertificateModel.objects.create(
        certificate=cert_model_1,
        ca=issuing_ca,
        revocation_reason=RevokedCertificateModel.ReasonCode.KEY_COMPROMISE,
    )
    RevokedCertificateModel.objects.create(
        certificate=cert_model_2,
        ca=issuing_ca,
        revocation_reason=RevokedCertificateModel.ReasonCode.CESSATION,
    )

    schedules = Schedule.objects.filter(name__startswith=f'crl_gen_{issuing_ca.unique_name}')
    assert schedules.count() == 1


@pytest.mark.django_db
def test_revocation_signal_creates_one_schedule_per_ca(issuing_ca_instance: dict[str, Any]) -> None:
    """Revoking certificates for different CAs should schedule each independently."""
    issuing_ca = issuing_ca_instance['issuing_ca']
    issuing_ca.auto_crl_on_revocation_enabled = True
    issuing_ca.save(update_fields=['auto_crl_on_revocation_enabled'])

    Schedule.objects.all().delete()

    other_cert, other_key = CertificateGenerator.create_root_ca('Other Root CA')
    other_ca = CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=other_cert,
        private_key=other_key,
        chain=[],
        unique_name='other_root_ca',
        ca_type=issuing_ca.ca_type,
    )
    other_ca.auto_crl_on_revocation_enabled = True
    other_ca.save(update_fields=['auto_crl_on_revocation_enabled'])

    cert_model_1 = CertificateModel.save_certificate(
        CertificateGenerator.create_ee(
            issuer_private_key=issuing_ca_instance['priv_key'],
            issuer_name=issuing_ca_instance['cert'].subject,
            subject_name='Revocation Test Cert 5',
        )[0]
    )
    cert_model_2 = CertificateModel.save_certificate(
        CertificateGenerator.create_ee(
            issuer_private_key=other_key,
            issuer_name=other_cert.subject,
            subject_name='Revocation Test Cert 6',
        )[0]
    )

    RevokedCertificateModel.objects.create(
        certificate=cert_model_1,
        ca=issuing_ca,
        revocation_reason=RevokedCertificateModel.ReasonCode.UNSPECIFIED,
    )
    RevokedCertificateModel.objects.create(
        certificate=cert_model_2,
        ca=other_ca,
        revocation_reason=RevokedCertificateModel.ReasonCode.UNSPECIFIED,
    )

    base_name = f'crl_gen_{issuing_ca.unique_name}'
    other_base_name = f'crl_gen_{other_ca.unique_name}'

    assert Schedule.objects.filter(name__startswith=base_name).count() == 1
    assert Schedule.objects.filter(name__startswith=other_base_name).count() == 1
    assert Schedule.objects.filter(name__startswith='crl_gen_').count() == 2
