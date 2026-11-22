# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the CRL validity notification sweep."""

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from django.utils import timezone

from management.management.commands.check_crl_validity import Command
from management.models import NotificationModel


def _crl() -> SimpleNamespace:
    return SimpleNamespace(
        pk=7,
        ca_id=3,
        ca=SimpleNamespace(unique_name='CA one'),
        next_update=timezone.now(),
    )


@pytest.mark.django_db
def test_existing_event_is_not_created_again() -> None:
    """The preloaded event set replaces a per-domain exists() query."""
    with patch(
        'management.management.commands.check_crl_validity.NotificationModel.objects.create'
    ) as create:
        Command()._create_notification(
            crl=_crl(),
            event='CRL_EXPIRED_7',
            notification_type=NotificationModel.NotificationTypes.CRITICAL,
            message_type=NotificationModel.NotificationMessageType.CRL_EXPIRED,
            new_status=Mock(),
            existing={('CRL_EXPIRED_7', 3, None)},
            domains_by_ca={},
        )

    create.assert_not_called()
