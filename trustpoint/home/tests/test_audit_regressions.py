# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression checks for dashboard filtering and the simplified CRL action."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from bs4 import BeautifulSoup
from django.contrib.auth.models import Permission
from django.db import connection
from django.test import RequestFactory
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone
from django_q.models import Schedule

from devices.models import DeviceModel
from home.analytics import issuing_ca_crl_summary
from home.filters import NotificationFilter
from home.views import DashboardChartsAndCountsView
from management.models import NotificationModel, SecurityConfig
from management.models.audit_log import AuditLog
from pki.models import CrlModel, DomainModel
from trustpoint.settings import UIConfig

pytestmark = pytest.mark.django_db


@pytest.fixture
def simplified_user(client, django_user_model):
    user = django_user_model.objects.create_user(username='simplified-audit', view_mode='simplified')
    client.force_login(user)
    return user


def grant_ca_permission(user):
    user.user_permissions.add(Permission.objects.get(content_type__app_label='users', codename='manage_cas'))


def test_quick_action_requires_ca_permission(client, simplified_user, issuing_ca_instance):
    ca = issuing_ca_instance['issuing_ca']
    response = client.post(reverse('home:simplified_enable_crl_cycle', args=[ca.pk]))
    assert response.status_code == 403
    ca.refresh_from_db()
    assert not ca.crl_cycle_enabled
    assert not Schedule.objects.filter(func='pki.tasks.generate_crl_for_ca').exists()


def test_quick_action_schedules_and_audits_once(client, simplified_user, issuing_ca_instance):
    ca = issuing_ca_instance['issuing_ca']
    grant_ca_permission(simplified_user)
    SecurityConfig.objects.create(allow_self_signed_ca=True)
    original_auto_revoke = ca.auto_crl_on_revocation_enabled
    url = reverse('home:simplified_enable_crl_cycle', args=[ca.pk])
    assert client.post(url).status_code == 302
    ca.refresh_from_db()
    assert ca.crl_cycle_enabled
    assert ca.crl_cycle_interval_hours == 48
    assert ca.crl_validity_hours == 72
    assert ca.auto_crl_on_revocation_enabled == original_auto_revoke
    assert ca.last_crl_generation_started_at is not None
    schedules = Schedule.objects.filter(func='pki.tasks.generate_crl_for_ca', args=str((ca.pk,)))
    assert schedules.count() == 1
    audit = AuditLog.objects.get(operation_type='CA_UPDATED', target_object_id=ca.pk)
    assert audit.actor == simplified_user
    assert client.post(url).status_code == 302
    assert schedules.count() == 1
    assert AuditLog.objects.filter(operation_type='CA_UPDATED', target_object_id=ca.pk).count() == 1


@pytest.mark.parametrize('reason', ['inactive', 'validity_limit', 'missing_policy', 'self_signed'])
def test_quick_action_rejects_inactive_ca_or_policy_limit(client, simplified_user, issuing_ca_instance, reason):
    ca = issuing_ca_instance['issuing_ca']
    grant_ca_permission(simplified_user)
    if reason == 'inactive':
        ca.is_active = False
        ca.save(update_fields=['is_active'])
    elif reason == 'validity_limit':
        SecurityConfig.objects.create(max_crl_validity_days=1)
    elif reason == 'self_signed':
        SecurityConfig.objects.create(allow_self_signed_ca=False)
    assert client.post(reverse('home:simplified_enable_crl_cycle', args=[ca.pk])).status_code == 302
    ca.refresh_from_db()
    assert not ca.crl_cycle_enabled
    assert not Schedule.objects.filter(func='pki.tasks.generate_crl_for_ca').exists()
    assert not AuditLog.objects.filter(operation_type='CA_UPDATED', target_object_id=ca.pk).exists()


def test_default_reference_preserves_instant_in_user_timezone():
    now = datetime(2026, 11, 4, 12, tzinfo=UTC)
    with timezone.override('Europe/Berlin'), patch('home.views.timezone.now', return_value=now):
        _, _, reference = DashboardChartsAndCountsView()._get_dashboard_dates(RequestFactory().get('/'))
    assert reference == now


@pytest.mark.parametrize('parameter', ['start_date', 'end_date', 'reference_date'])
def test_invalid_calendar_date_returns_bad_request(parameter):
    response = DashboardChartsAndCountsView().get(RequestFactory().get('/', {parameter: '2026-02-30'}))
    assert response.status_code == 400


def test_today_filter_uses_local_date():
    now = datetime(2026, 11, 4, 23, 30, tzinfo=UTC)
    today = NotificationModel.objects.create(notification_type='WAR')
    yesterday = NotificationModel.objects.create(notification_type='WAR')
    NotificationModel.objects.filter(pk=today.pk).update(created_at=now)
    NotificationModel.objects.filter(pk=yesterday.pk).update(created_at=now - timedelta(hours=1))
    with timezone.override('Europe/Berlin'), patch('home.filters.timezone.now', return_value=now):
        actual = NotificationFilter.filter_by_date_range(NotificationModel.objects.all(), '', 'today')
        assert list(actual) == [today]


def test_simplified_invalid_domain_returns_not_found(client, simplified_user):
    assert client.get(reverse('home:simplified_overview'), {'domain': 'abc'}).status_code == 404


def test_ca_less_domain_excludes_other_domains_notifications(client, simplified_user):
    selected = DomainModel.objects.create(unique_name='audit-selected')
    other = DomainModel.objects.create(unique_name='audit-other')
    wrong = NotificationModel.objects.create(domain=other, notification_source='D', notification_type='WAR')
    own = NotificationModel.objects.create(domain=selected, notification_source='D', notification_type='WAR')
    system = NotificationModel.objects.create(notification_source='S', notification_type='WAR')
    response = client.get(reverse('home:simplified_overview'), {'domain': selected.pk})
    items = list(response.context['domains'][0].recent_notifications)
    assert wrong not in items
    assert own in items
    assert system in items


def test_profile_ca_bucket_excludes_end_entity_certificates(credential_instance):
    assert credential_instance['credential'].certificate is not None
    counts = DashboardChartsAndCountsView().get_cert_counts_by_profile(None)
    assert counts['CA Certificates'] == 1


def test_crl_summary_fetches_only_active_metadata(issuing_ca_instance):
    ca = issuing_ca_instance['issuing_ca']
    now = timezone.now()
    for active in (False, True):
        CrlModel.objects.create(
            ca=ca,
            crl_pem='unused',
            is_active=active,
            this_update=now - timedelta(days=1),
            next_update=now + timedelta(days=1),
        )
    with CaptureQueriesContext(connection) as queries:
        summary = issuing_ca_crl_summary(now)
    assert summary == {'current': 1, 'expired': 0, 'not_yet_valid': 0, 'missing': 0}
    crl_queries = [entry['sql'] for entry in queries if 'FROM "pki_crlmodel"' in entry['sql']]
    assert len(crl_queries) == 1
    assert 'crl_pem' not in crl_queries[0]
    assert 'WHERE' in crl_queries[0] and '"is_active"' in crl_queries[0].split('WHERE')[1]


def test_simplified_devices_are_paginated_after_filtering(client, simplified_user):
    domain = DomainModel.objects.create(unique_name='audit-pagination')
    devices = DeviceModel.objects.bulk_create(
        [DeviceModel(common_name=f'page-device-{index}', domain=domain) for index in range(UIConfig.paginate_by + 1)]
    )
    DeviceModel.objects.create(common_name='excluded', domain=domain)
    url = reverse('home:simplified_overview')
    params = {'domain': domain.pk, 'common_name': 'page-device'}
    response = client.get(url, params)
    first = response.context['domains'][0]
    assert first.device_page.paginator.count == UIConfig.paginate_by + 1
    assert len(first.prepared_devices) == UIConfig.paginate_by
    next_link = BeautifulSoup(response.content, 'html.parser').select_one('nav[aria-label="Device pages"] a')
    response = client.get(url + next_link['href'])
    last = response.context['domains'][0]
    assert [device.pk for device in last.prepared_devices] == [devices[-1].pk]
