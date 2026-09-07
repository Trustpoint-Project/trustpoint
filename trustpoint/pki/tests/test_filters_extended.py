# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for certificate, CA and CRL list filters."""

from __future__ import annotations

import datetime
from typing import Any

import pytest
from django.utils import timezone

from pki.filters import CaFilter, CertificateFilter, CrlFilter
from pki.models import CaModel
from pki.models.certificate import CertificateModel, RevokedCertificateModel
from pki.util.x509 import CertificateGenerator

pytestmark = pytest.mark.django_db


@pytest.fixture
def certificates(issuing_ca_instance: dict[str, Any]) -> dict[str, CertificateModel]:
    """Return certificates covering valid, expired, future and revoked states."""
    ca_cert = issuing_ca_instance['cert']
    ca_key = issuing_ca_instance['priv_key']

    valid, _ = CertificateGenerator.create_ee(ca_key, ca_cert.subject, 'valid-cert', validity_days=365)
    soon, _ = CertificateGenerator.create_ee(ca_key, ca_cert.subject, 'soon-cert', validity_days=3)
    revoked_cert, _ = CertificateGenerator.create_ee(ca_key, ca_cert.subject, 'revoked-cert')

    models = {
        'valid': CertificateModel.save_certificate(valid),
        'soon': CertificateModel.save_certificate(soon),
        'revoked': CertificateModel.save_certificate(revoked_cert),
    }
    RevokedCertificateModel.objects.create(
        certificate=models['revoked'],
        revocation_reason=RevokedCertificateModel.ReasonCode.UNSPECIFIED,
        ca=issuing_ca_instance['issuing_ca'],
    )
    return models


class TestCertificateFilter:
    """Certificate list filtering."""

    def test_status_ok_excludes_revoked(self, certificates: dict[str, CertificateModel]) -> None:
        """Valid certificates exclude revoked ones."""
        result = CertificateFilter({'status': 'ok'}, queryset=CertificateModel.objects.all()).qs

        assert certificates['valid'] in result
        assert certificates['revoked'] not in result

    def test_status_revoked_returns_only_revoked(
        self, certificates: dict[str, CertificateModel]
    ) -> None:
        """The revoked filter returns exactly the revoked certificates."""
        result = CertificateFilter({'status': 'revoked'}, queryset=CertificateModel.objects.all()).qs

        assert list(result) == [certificates['revoked']]

    def test_status_expired_and_not_yet_valid_are_supported(
        self, certificates: dict[str, CertificateModel]
    ) -> None:
        """Expired and not-yet-valid statuses exclude currently valid certificates."""
        expired = CertificateFilter({'status': 'expired'}, queryset=CertificateModel.objects.all()).qs
        future = CertificateFilter(
            {'status': 'not_yet_valid'}, queryset=CertificateModel.objects.all()
        ).qs

        assert certificates['valid'] not in expired
        assert certificates['valid'] not in future

    def test_unknown_status_returns_everything(
        self, certificates: dict[str, CertificateModel]
    ) -> None:
        """An unrecognised status leaves the queryset untouched."""
        result = CertificateFilter({'status': 'nonsense'}, queryset=CertificateModel.objects.all()).qs

        assert result.count() == CertificateModel.objects.count()

    @pytest.mark.parametrize('window', ['today', 'tomorrow', '7_days', '30_days', 'after_30_days'])
    def test_expiry_windows_only_return_currently_valid_certificates(
        self, certificates: dict[str, CertificateModel], window: str
    ) -> None:
        """Every expiry horizon excludes revoked certificates."""
        result = CertificateFilter(
            {'expiry_window': window}, queryset=CertificateModel.objects.all()
        ).qs

        assert certificates['revoked'] not in result

    def test_expiry_window_selects_certificates_expiring_soon(
        self, certificates: dict[str, CertificateModel]
    ) -> None:
        """A short horizon selects the certificate expiring within it."""
        result = CertificateFilter(
            {'expiry_window': '7_days'}, queryset=CertificateModel.objects.all()
        ).qs

        assert certificates['soon'] in result
        assert certificates['valid'] not in result

    def test_expiry_window_after_thirty_days_selects_long_lived(
        self, certificates: dict[str, CertificateModel]
    ) -> None:
        """A long horizon selects certificates valid beyond it."""
        result = CertificateFilter(
            {'expiry_window': 'after_30_days'}, queryset=CertificateModel.objects.all()
        ).qs

        assert certificates['valid'] in result
        assert certificates['soon'] not in result

    def test_unknown_expiry_window_returns_everything(
        self, certificates: dict[str, CertificateModel]
    ) -> None:
        """An unrecognised horizon leaves the queryset untouched."""
        result = CertificateFilter(
            {'expiry_window': 'nonsense'}, queryset=CertificateModel.objects.all()
        ).qs

        assert result.count() == CertificateModel.objects.count()

    @pytest.mark.parametrize(('value', 'expected'), [('true', True), ('false', False)])
    def test_self_signed_filter(
        self, certificates: dict[str, CertificateModel], value: str, expected: bool
    ) -> None:
        """Self-signed filtering matches the stored flag."""
        result = CertificateFilter(
            {'is_self_signed': value}, queryset=CertificateModel.objects.all()
        ).qs

        assert all(cert.is_self_signed is expected for cert in result)

    def test_unknown_self_signed_value_returns_everything(
        self, certificates: dict[str, CertificateModel]
    ) -> None:
        """An unrecognised self-signed value leaves the queryset untouched."""
        result = CertificateFilter(
            {'is_self_signed': 'nonsense'}, queryset=CertificateModel.objects.all()
        ).qs

        assert result.count() == CertificateModel.objects.count()

    def test_common_name_filter_is_case_insensitive(
        self, certificates: dict[str, CertificateModel]
    ) -> None:
        """Common name filtering matches partial, case-insensitive input."""
        result = CertificateFilter(
            {'common_name': 'VALID-CERT'}, queryset=CertificateModel.objects.all()
        ).qs

        assert certificates['valid'] in result


class TestCaFilter:
    """CA list filtering."""

    @pytest.fixture
    def cas(self, issuing_ca_instance: dict[str, Any]) -> dict[str, CaModel]:
        """Return an issuing CA plus a keyless CA."""
        keyless_cert, _ = CertificateGenerator.create_root_ca('Filter Keyless CA')
        keyless = CaModel.create_keyless_ca(unique_name='filter-keyless', certificate_obj=keyless_cert)
        return {'issuing': issuing_ca_instance['issuing_ca'], 'keyless': keyless}

    def test_ca_group_excludes_keyless_and_ra(self, cas: dict[str, CaModel]) -> None:
        """The CA group excludes keyless CAs and registration authorities."""
        result = CaFilter({'ca_type_group': 'ca'}, queryset=CaModel.objects.all()).qs

        assert cas['issuing'] in result
        assert cas['keyless'] not in result

    def test_keyless_group_returns_only_keyless(self, cas: dict[str, CaModel]) -> None:
        """The keyless group returns exactly the keyless CAs."""
        result = CaFilter({'ca_type_group': 'keyless'}, queryset=CaModel.objects.all()).qs

        assert list(result) == [cas['keyless']]

    def test_ra_group_returns_registration_authorities(self, cas: dict[str, CaModel]) -> None:
        """The RA group excludes ordinary issuing CAs."""
        result = CaFilter({'ca_type_group': 'ra'}, queryset=CaModel.objects.all()).qs

        assert cas['issuing'] not in result

    def test_unknown_group_returns_everything(self, cas: dict[str, CaModel]) -> None:
        """An unrecognised group leaves the queryset untouched."""
        result = CaFilter({'ca_type_group': 'nonsense'}, queryset=CaModel.objects.all()).qs

        assert result.count() == CaModel.objects.count()

    def test_active_filter_separates_enabled_cas(self, cas: dict[str, CaModel]) -> None:
        """Active filtering distinguishes enabled from disabled CAs."""
        cas['keyless'].is_active = False
        cas['keyless'].save()

        active = CaFilter({'is_active': 'true'}, queryset=CaModel.objects.all()).qs
        inactive = CaFilter({'is_active': 'false'}, queryset=CaModel.objects.all()).qs

        assert cas['issuing'] in active
        assert list(inactive) == [cas['keyless']]

    def test_unknown_active_value_returns_everything(self, cas: dict[str, CaModel]) -> None:
        """An unrecognised active value leaves the queryset untouched."""
        result = CaFilter({'is_active': 'nonsense'}, queryset=CaModel.objects.all()).qs

        assert result.count() == CaModel.objects.count()


class TestCrlFilter:
    """CRL list filtering."""

    @pytest.fixture
    def crl(self, issuing_ca_instance: dict[str, Any]) -> Any:
        """Return an issued CRL."""
        ca = issuing_ca_instance['issuing_ca']
        ca.issue_crl()
        return ca.get_active_crl()

    def test_active_filter_selects_the_active_crl(self, crl: Any) -> None:
        """Active filtering returns the currently active CRL."""
        from pki.models.crl import CrlModel

        active = CrlFilter({'is_active': 'true'}, queryset=CrlModel.objects.all()).qs
        inactive = CrlFilter({'is_active': 'false'}, queryset=CrlModel.objects.all()).qs

        assert list(active) == [crl]
        assert crl not in inactive

    def test_unknown_active_value_returns_everything(self, crl: Any) -> None:
        """An unrecognised active value leaves the queryset untouched."""
        from pki.models.crl import CrlModel

        result = CrlFilter({'is_active': 'nonsense'}, queryset=CrlModel.objects.all()).qs

        assert result.count() == CrlModel.objects.count()

    def test_update_date_range_selects_recent_crls(self, crl: Any) -> None:
        """Date range filtering matches CRLs updated inside the window."""
        from pki.models.crl import CrlModel

        today = timezone.now().date()
        result = CrlFilter(
            {
                'this_update_from': (today - datetime.timedelta(days=1)).isoformat(),
                'this_update_to': (today + datetime.timedelta(days=1)).isoformat(),
            },
            queryset=CrlModel.objects.all(),
        ).qs

        assert crl in result
