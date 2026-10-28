# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Parity between health rules, database filtering, sorting, badges and counts."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.urls import reverse

from devices.dashboard_filters import (
    filter_devices_with_expiring_domain_credential_in_1_day,
    filter_devices_with_expiring_domain_credential_in_7_days,
    filter_devices_with_expiring_domain_credential_in_30_days,
    filter_expired_or_revoked_devices,
)
from devices.filters import DeviceFilter
from devices.health import credential_health_expression, device_credential_health, filter_credential_health
from devices.models import DeviceModel
from devices.presentation import DeviceHealthPresentationMixin, credential_health_display
from devices.views.tables import DeviceTableView
from home.analytics import application_certificate_device_counts
from home.simplified_view import SimplifiedDomainOverviewView
from home.views import DashboardChartsAndCountsView
from pki.filters import CertificateFilter
from pki.models import CertificateModel, CredentialModel, IssuedCredentialModel, RevokedCertificateModel
from pki.models.credential import PrimaryCredentialCertificate
from pki.models.domain import DomainModel
from pki.services.certificate_health import (
    HEALTH_PRIORITY,
    certificate_health_conditions,
    certificate_health_counts,
    classify_certificate,
    summarize_certificate_health,
)
from users.models import TrustpointUser

pytestmark = pytest.mark.django_db
NOW = datetime(2026, 10, 27, 12, tzinfo=UTC)
DOMAIN = IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL
APPLICATION = IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL


def _certificate(start: float, end: float, *, revoked: bool = False) -> CertificateModel:
    """Store an independent certificate with exact validity boundaries."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'health-test')])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW + timedelta(days=start))
        .not_valid_after(NOW + timedelta(days=end))
        .sign(key, hashes.SHA256())
    )
    model = CertificateModel.save_certificate(certificate)
    if revoked:
        RevokedCertificateModel.objects.create(certificate=model)
    return model


def _issue(device: DeviceModel, certificate: CertificateModel | None, kind: int) -> None:
    """Link a certificate or pending key-only record to a device."""
    credential = CredentialModel.objects.create(
        credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL,
        certificate=certificate,
    )
    if certificate is not None:
        PrimaryCredentialCertificate.objects.create(credential=credential, certificate=certificate, is_primary=True)
    IssuedCredentialModel.objects.create(
        common_name=device.common_name,
        device=device,
        credential=credential,
        issued_credential_type=kind,
    )


@pytest.mark.parametrize(
    ('start', 'end', 'revoked', 'expected'),
    [
        (-1, 30, False, 'valid'),
        (0, 30, False, 'valid'),
        (-1, 7, False, 'expiring'),
        (-1, 1, False, 'expiring'),
        (-1, 0, False, 'expired'),
        (-2, -1, False, 'expired'),
        (1, 30, False, 'not_yet_valid'),
        (-1, 30, True, 'revoked'),
        (1, 30, True, 'revoked'),
        (-2, -1, True, 'revoked'),
    ],
)
def test_certificate_python_sql_model_and_filter_parity(start, end, revoked, expected):
    """A certificate belongs to exactly the same state in every representation."""
    certificate = _certificate(start, end, revoked=revoked)
    assert (
        classify_certificate(
            not_valid_before=certificate.not_valid_before,
            not_valid_after=certificate.not_valid_after,
            revoked=revoked,
            as_of=NOW,
            expiry_days=7,
        )
        == expected
    )
    conditions = certificate_health_conditions(as_of=NOW, expiry_days=7)
    matching = [
        state
        for state, condition in conditions.items()
        if CertificateModel.objects.filter(
            condition,
            pk=certificate.pk,
        ).exists()
    ]
    assert matching == [expected]
    counts = certificate_health_counts(CertificateModel.objects.filter(pk=certificate.pk), as_of=NOW, expiry_days=7)
    assert counts[expected] == 1
    assert counts['unclassified'] == 0
    assert sum(counts[state] for state in HEALTH_PRIORITY) == counts['total']

    expected_status = {
        'valid': 'OK',
        'expiring': 'OK',
        'expired': 'EXP',
        'revoked': 'REV',
        'not_yet_valid': 'NYV',
    }[expected]
    # The model property owns the present-time adapter; the service takes an explicit instant.
    with patch('pki.models.certificate.dt.datetime') as clock:
        clock.now.return_value = NOW
        assert certificate.certificate_status == expected_status
    filter_value = 'ok' if expected in ('valid', 'expiring') else expected
    with patch('pki.filters.timezone.now', return_value=NOW):
        assert CertificateFilter({'status': filter_value}).qs.filter(pk=certificate.pk).exists()


@pytest.mark.parametrize('kind', [DOMAIN, APPLICATION])
@pytest.mark.parametrize(
    ('states', 'expected'),
    [
        ([], 'none'),
        (['valid'], 'valid'),
        (['expiring'], 'expiring'),
        (['not_yet_valid'], 'not_yet_valid'),
        (['expired'], 'expired'),
        (['revoked'], 'revoked'),
        (['valid', 'expired', 'revoked'], 'valid'),
        (['expiring', 'not_yet_valid', 'expired'], 'expiring'),
        (['not_yet_valid', 'revoked'], 'not_yet_valid'),
        (['expired', 'revoked'], 'expired'),
    ],
)
def test_device_badges_filters_and_sort_annotations_agree(kind, states, expected):
    """A device's best certificate determines badge, filter and sortable state."""
    device = DeviceModel.objects.create(common_name='device-health')
    dates = {'valid': (-1, 30), 'expiring': (-1, 3), 'not_yet_valid': (1, 30), 'expired': (-2, -1), 'revoked': (-1, 30)}
    for state in states:
        _issue(device, _certificate(*dates[state], revoked=state == 'revoked'), kind)
    # A healthy certificate of the other type must never affect the selected type's state.
    _issue(device, _certificate(-1, 60), APPLICATION if kind == DOMAIN else DOMAIN)
    _issue(device, None, kind)
    summary = device_credential_health(device, kind, as_of=NOW)
    assert summary.state == expected
    assert summary.count == len(states)
    annotated = DeviceModel.objects.annotate(health=credential_health_expression(kind, as_of=NOW)).get(pk=device.pk)
    assert annotated.health == expected
    assert (
        filter_credential_health(DeviceModel.objects.all(), kind, [expected], as_of=NOW).filter(pk=device.pk).exists()
    )
    for other in [*HEALTH_PRIORITY, 'none']:
        if other != expected:
            assert (
                not filter_credential_health(DeviceModel.objects.all(), kind, [other], as_of=NOW)
                .filter(pk=device.pk)
                .exists()
            )

    table = DeviceTableView()
    simplified = SimplifiedDomainOverviewView()
    table.health_as_of = simplified.health_as_of = NOW
    badge = table._get_domain_credential_status if kind == DOMAIN else table._get_application_certificate_status
    other_badge = (
        simplified._get_domain_credential_status if kind == DOMAIN else simplified._get_application_certificate_status
    )
    expected_badge = 'active' if kind == APPLICATION and expected in ('valid', 'expiring') else expected
    assert badge(device) == other_badge(device)
    assert badge(device)['status_key'] == expected_badge
    sorted_record = table.get_base_queryset().get(pk=device.pk)
    expected_domain_rank = {'none': 0, 'valid': 1, 'expiring': 2, 'not_yet_valid': 3, 'expired': 4, 'revoked': 5}[
        expected
    ]
    expected_application_rank = {'none': 0, 'valid': 1, 'expiring': 1, 'not_yet_valid': 2, 'expired': 3, 'revoked': 4}[
        expected
    ]
    if kind == DOMAIN:
        assert sorted_record.domain_credential_sort == expected_domain_rank
    else:
        assert sorted_record.application_certificate_sort == expected_application_rank
    field = 'domain_credential_state' if kind == DOMAIN else 'application_certificate_state'
    filter_value = 'expired' if expected == 'expired' else expected_badge
    assert DeviceFilter({field: filter_value}, reference_time=NOW).qs.filter(pk=device.pk).exists()


def test_revoked_future_and_pending_records_are_not_active():
    """Devices containing future-only certificates are counted separately from missing identities."""
    for state in ('none', 'valid', 'expiring', 'not_yet_valid', 'expired', 'revoked'):
        device = DeviceModel.objects.create(common_name=state)
        if state != 'none':
            start, end = {
                'valid': (-1, 30),
                'expiring': (-1, 2),
                'not_yet_valid': (1, 30),
                'expired': (-2, -1),
                'revoked': (-1, 30),
            }[state]
            _issue(device, _certificate(start, end, revoked=state == 'revoked'), APPLICATION)
    result = application_certificate_device_counts(NOW)
    assert result == {'active': 2, 'expired_or_revoked_only': 2, 'not_yet_valid': 1, 'none': 1}


def test_next_expiry_uses_only_current_nonrevoked_certificates():
    """The tooltip excludes earlier future, expired and revoked certificates."""
    certificates = [_certificate(-1, 30), _certificate(1, 2), _certificate(-1, 1, revoked=True), _certificate(-2, -1)]
    summary = summarize_certificate_health(certificates, as_of=NOW)
    assert summary.next_expiry == NOW + timedelta(days=30)
    assert summary.state == 'valid'


def test_reused_certificate_is_counted_once_in_a_device_summary():
    """Repeated credential links do not inflate counts relative to SQL certificate aggregates."""
    device = DeviceModel.objects.create(common_name='shared-certificate')
    certificate = _certificate(-1, 30)
    _issue(device, certificate, DOMAIN)
    _issue(device, certificate, DOMAIN)
    assert device_credential_health(device, DOMAIN, as_of=NOW).count == 1


@pytest.mark.parametrize(
    ('domain_state', 'application_state', 'expired'),
    [
        ('expired', 'valid', True),
        ('revoked', 'valid', True),
        ('valid', 'revoked', False),
        ('not_yet_valid', 'revoked', False),
        ('none', 'revoked', True),
        ('none', 'not_yet_valid', False),
        ('none', 'valid', False),
    ],
)
def test_composite_device_health_keeps_domain_identity_precedence(domain_state, application_state, expired):
    """Composing domain and application filters does not mix their credential subqueries."""
    device = DeviceModel.objects.create(common_name='composite-health')
    dates = {'valid': (-1, 30), 'not_yet_valid': (1, 30), 'expired': (-2, -1), 'revoked': (-1, 30)}
    for kind, state in [(DOMAIN, domain_state), (APPLICATION, application_state)]:
        _issue(device, None if state == 'none' else _certificate(*dates[state], revoked=state == 'revoked'), kind)
    matches = filter_expired_or_revoked_devices(DeviceModel.objects.all(), NOW).filter(pk=device.pk).exists()
    assert matches is expired


def test_prefetched_badges_need_no_additional_queries(django_assert_num_queries):
    """Rendering all badges reuses the list view's prefetch."""
    for index in range(3):
        device = DeviceModel.objects.create(common_name=f'prefetched-{index}')
        _issue(device, _certificate(-1, 30), DOMAIN)
    view = DeviceTableView()
    view.health_as_of = NOW
    devices = list(view.get_base_queryset())
    with django_assert_num_queries(0):
        for device in devices:
            assert credential_health_display(device, DOMAIN, as_of=NOW)['status_key'] == 'valid'


def test_simplified_page_uses_shared_badges_and_certificate_counts(admin_user, admin_client):
    """The simplified page renders future certificates separately from usable or revoked ones."""
    admin_user.view_mode = TrustpointUser.ViewModeChoices.SIMPLIFIED
    admin_user.save(update_fields=['view_mode'])
    domain = DomainModel.objects.create(unique_name='health-domain')
    device = DeviceModel.objects.create(common_name='future-domain-identity', domain=domain)
    _issue(device, _certificate(1, 30), DOMAIN)
    _issue(device, _certificate(-1, 30, revoked=True), DOMAIN)
    # The page's counters follow the issued credential's recorded domain.
    device.issued_credentials.update(domain=domain)
    with patch.object(DeviceHealthPresentationMixin, 'health_as_of', NOW):
        response = admin_client.get(reverse('home:simplified_overview'), {'domain': domain.pk})
    assert response.status_code == 200
    prepared_domain = response.context['domains'][0]
    assert prepared_domain.active_certificates == 0
    assert prepared_domain.expiring_certificates == 0
    assert prepared_domain.expired_certificates == 0
    assert prepared_domain.prepared_devices[0].domain_credential_status['status_key'] == 'not_yet_valid'


def test_historical_status_respects_recorded_revocation_time():
    """Past status queries retain their explicit revocation-time semantics."""
    certificate = _certificate(-1, 30, revoked=True)
    RevokedCertificateModel.objects.filter(certificate=certificate).update(revoked_at=NOW + timedelta(days=1))
    view = DashboardChartsAndCountsView()
    before = view.get_cert_counts_by_status(None, reference_date=NOW)
    after = view.get_cert_counts_by_status(None, reference_date=NOW + timedelta(days=2))
    assert before['OK'] == 1
    assert before['Revoked'] == 0
    assert after['Revoked'] == 1


def test_device_expiry_intervals_ignore_obsolete_and_future_certificates():
    """Expiry buckets use the earliest usable certificate unless a longer-lived one exists."""
    fixtures = {
        'day': [(-1, 0.5, False), (-1, 3, False)],
        'week': [(-1, 3, False), (-1, 0.5, True), (1, 2, False)],
        'month': [(-1, 15, False)],
        'healthy': [(-1, 0.5, False), (-1, 60, False)],
        'future': [(1, 2, False)],
    }
    for name, certificates in fixtures.items():
        device = DeviceModel.objects.create(common_name=name)
        for start, end, revoked in certificates:
            _issue(device, _certificate(start, end, revoked=revoked), DOMAIN)
    devices = DeviceModel.objects.all()
    for filter_function, expected in [
        (filter_devices_with_expiring_domain_credential_in_1_day, 'day'),
        (filter_devices_with_expiring_domain_credential_in_7_days, 'week'),
        (filter_devices_with_expiring_domain_credential_in_30_days, 'month'),
    ]:
        assert list(filter_function(devices, NOW).values_list('common_name', flat=True)) == [expected]
    counts = DashboardChartsAndCountsView().get_expiring_device_counts(NOW)
    # This legacy endpoint counts credentials, while the dashboard buckets count devices.
    assert counts == {'expiring_in_1_day': 2, 'expiring_in_7_days': 2, 'expiring_in_30_days': 1}
