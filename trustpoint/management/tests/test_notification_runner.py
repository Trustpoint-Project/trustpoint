# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Verify notification failures reach callers after independent checks finish."""

from io import StringIO
from unittest.mock import Mock

import pytest
from django.core.management import CommandError, call_command, get_commands

from management import tasks
from management.management.commands import execute_all_notifications, run_all_notifications


@pytest.fixture
def config(monkeypatch):
    value = Mock(enabled=True)
    monkeypatch.setattr(run_all_notifications.NotificationConfig, 'get', lambda: value)
    return value


def test_placeholder_commands_are_unavailable():
    commands = get_commands()
    assert 'check_system_health' not in commands
    assert 'check_for_security_vulnerabilities' not in commands


def test_runner_completes_supported_checks(config, monkeypatch):
    run = Mock()
    monkeypatch.setattr(run_all_notifications, 'call_command', run)
    output = StringIO()
    call_command('run_all_notifications', stdout=output)
    names = [item.args[0] for item in run.call_args_list]
    assert 'check_system_health' not in names
    assert 'check_for_security_vulnerabilities' not in names
    assert 'check_certificate_validity' in names
    assert 'check_tls_certificate_validity' in names
    assert 'All notification checks completed successfully.' in output.getvalue()


@pytest.mark.parametrize('error', [CommandError('failed'), RuntimeError('failed')])
def test_runner_continues_then_raises_aggregate_error(config, monkeypatch, error):
    attempted = []

    def check(name):
        attempted.append(name)
        if name in ('check_backup_age', 'check_certificate_validity'):
            raise error

    monkeypatch.setattr(run_all_notifications, 'call_command', check)
    output = StringIO()
    with pytest.raises(CommandError, match='check_backup_age, check_certificate_validity'):
        call_command('run_all_notifications', stdout=output)
    assert attempted[-1] == 'check_tls_certificate_validity'
    assert 'All notification checks completed successfully.' not in output.getvalue()


def test_disabled_notifications_skip_checks(config, monkeypatch):
    config.enabled = False
    run = Mock()
    monkeypatch.setattr(run_all_notifications, 'call_command', run)
    call_command('run_all_notifications', stdout=StringIO())
    run.assert_not_called()


@pytest.mark.parametrize('scheduled', [False, True])
def test_failure_reaches_outer_command_and_background_task(config, monkeypatch, scheduled, caplog):
    module = tasks if scheduled else execute_all_notifications
    monkeypatch.setattr(module, 'call_command', Mock(side_effect=CommandError('check_backup_age')))
    output = StringIO()
    with pytest.raises(CommandError, match='check_backup_age'):
        if scheduled:
            tasks.execute_all_notifications()
        else:
            call_command('execute_all_notifications', stdout=output)
    config.schedule_next_notification_check.assert_not_called()
    assert 'All notifications executed successfully' not in output.getvalue() + caplog.text
