# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT
"""Dashboard notification contract tests."""
import json
from unittest.mock import patch

import pytest
from django.test import RequestFactory
from home.views import DashboardNotificationsAPIView


@pytest.mark.django_db
def test_notification_api_rejects_invalid_period(django_user_model):
    user=django_user_model.objects.create_user(username='dashboard_notify1', password='password')
    request=RequestFactory().get('/dashboard/notifications/?activity_days=10')
    request.user=user
    assert DashboardNotificationsAPIView.as_view()(request).status_code == 400


@pytest.mark.django_db
def test_notification_api_readonly_contract(django_user_model):
    user=django_user_model.objects.create_user(username='dashboard_notify2', password='password')
    request=RequestFactory().get('/dashboard/notifications/?activity_days=7')
    request.user=user
    data={'as_of':'2026-10-19T12:00:00+00:00','activity_days':7,'alerts':{'counts':{'critical':0,'warning':0},'total':0,'items':[]},'activity':{'items':[]}}
    with patch('home.views.get_notification_payload', return_value=data) as mock:
        response=DashboardNotificationsAPIView.as_view()(request)
    assert response.status_code == 200
    assert json.loads(response.content)['activity_days'] == 7
    mock.assert_called_once_with(activity_days=7)


@pytest.mark.django_db
def test_solved_excluded_but_read_not_excluded():
    from management.models import NotificationModel, NotificationStatus
    from home.notifications import get_notification_payload
    solved, _=NotificationStatus.objects.get_or_create(status=NotificationStatus.StatusChoices.SOLVED)
    warning=NotificationModel.objects.create(notification_type='WAR')
    critical=NotificationModel.objects.create(notification_type='CRI')
    critical.statuses.add(solved)
    payload=get_notification_payload()
    ids=[item['id'] for item in payload['alerts']['items']]
    assert warning.pk in ids
    assert critical.pk not in ids
