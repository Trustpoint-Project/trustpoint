# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression coverage for protocol policy error responses."""

from unittest.mock import patch

import pytest
from rest_framework.exceptions import ValidationError
from rest_framework.views import exception_handler

from devices.models import DeviceModel
from devices.serializers import DeviceSerializer


def test_protocol_policy_failure_does_not_expose_exception_details():
    device = DeviceModel()
    internal_details = 'Internal policy error at /private/server/policy.py:42'
    with patch('devices.serializers.PermittedProtocolsAuthorization.check', side_effect=ValueError(internal_details)):
        with pytest.raises(ValidationError) as raised:
            DeviceSerializer._check_protocol_policy(device)

    response = exception_handler(raised.value, {})
    assert response is not None
    assert response.status_code == 400
    assert response.data == ['The selected protocols are not permitted by the active security policy.']
    assert internal_details not in str(response.data)
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__


def test_protocol_policy_success_checks_device():
    device = DeviceModel()
    with patch('devices.serializers.PermittedProtocolsAuthorization.check') as check:
        DeviceSerializer._check_protocol_policy(device)
    check.assert_called_once_with(device)
