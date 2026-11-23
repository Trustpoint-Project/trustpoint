# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Guard notification scheduling against partial and bootstrap migrations."""

from types import SimpleNamespace
from unittest.mock import Mock

from management import signals


def test_signal_ignores_other_apps(monkeypatch):
    get = Mock()
    monkeypatch.setattr(signals.NotificationConfig, 'get', get)

    signals.initialize_notification_scheduling(SimpleNamespace(label='auth'))

    get.assert_not_called()


def test_signal_skipped_during_bootstrap(monkeypatch, settings):
    settings.TRUSTPOINT_IS_BOOTSTRAP = True
    get = Mock()
    monkeypatch.setattr(signals.NotificationConfig, 'get', get)

    signals.initialize_notification_scheduling(SimpleNamespace(label='management'))

    get.assert_not_called()
