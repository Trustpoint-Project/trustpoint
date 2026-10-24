# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for device selection shared by bulk delete and revoke views."""

import pytest
from django.contrib.messages import get_messages
from django.contrib.messages.storage.fallback import FallbackStorage
from django.test import RequestFactory

from devices.models import DeviceModel
from devices.views.delete import AbstractBulkDeleteView
from devices.views.revoke import AbstractBulkRevokeView


def selection_view(view_type, pks):
    """Prepare a view with URL selections and a request message store."""
    request = RequestFactory().get('/')
    request.session = {}
    request._messages = FallbackStorage(request)
    view = view_type()
    view.setup(request, pks=pks)
    return view


@pytest.mark.parametrize('view_type', [AbstractBulkDeleteView, AbstractBulkRevokeView])
def test_bulk_selection_rejects_missing_ids_without_changing_devices(view_type, device_instance):
    """A partial match redirects and leaves every selected device intact."""
    device = device_instance['device']
    missing_pk = device.pk + 1000
    view = selection_view(view_type, f'{device.pk}/{missing_pk}')
    assert view._set_queryset(view.request) == 'devices:devices'
    assert view.missing == str(missing_pk)
    assert list(view.queryset) == [device]
    assert DeviceModel.objects.filter(pk=device.pk).exists()

    valid_view = selection_view(view_type, f'{device.pk}/')
    assert valid_view._set_queryset(valid_view.request) is None
    assert list(valid_view.queryset) == [device]


@pytest.mark.parametrize(
    'view_type,action',
    [
        (AbstractBulkDeleteView, 'delete'),
        (AbstractBulkRevokeView, 'revoke'),
    ],
)
@pytest.mark.parametrize('pks', ['', 'invalid', '1/1'])
def test_bulk_selection_keeps_action_specific_validation_messages(view_type, action, pks):
    """Empty, invalid, and duplicate selections retain the delete/revoke wording."""
    view = selection_view(view_type, pks)
    assert view._set_queryset(view.request) == 'devices:devices'
    assert [str(message) for message in get_messages(view.request)] == [
        f'Please select the devices you would like to {action}.'
    ]
