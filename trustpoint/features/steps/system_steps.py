# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""System-management Behave steps."""

from __future__ import annotations

from unittest.mock import patch

from behave import given, runner, then, when
from django.conf import settings
from django.test import Client


LANGUAGE_TEXT = {
    'English': 'Username',
    'German': 'Benutzername',
}


@given('Trustpoint supports English and German')
def step_languages_supported(context: runner.Context) -> None:
    configured = {code for code, _name in settings.LANGUAGES}
    assert {'en', 'de'} <= configured


@when('a user opens the login page using language "{language}"')
def step_login_language(context: runner.Context, language: str) -> None:
    code = {'English': 'en', 'German': 'de'}[language]
    client = Client()
    client.cookies['django_language'] = code
    context.response = client.get('/users/login/')
    context.expected_language_text = LANGUAGE_TEXT[language]


@then('the login page is rendered in that language')
def step_login_translated(context: runner.Context) -> None:
    assert context.expected_language_text in context.response.content.decode('utf-8')


@when('the admin opens the system log list')
def step_open_logs(context: runner.Context) -> None:
    context.response = context.authenticated_client.get('/management/logging/files/')


@when('the admin opens the backup management page')
def step_open_backups(context: runner.Context) -> None:
    context.response = context.authenticated_client.get('/management/backups/')


@when('the admin creates a local database backup')
def step_create_backup(context: runner.Context) -> None:
    with patch('management.views.backup.create_db_backup', return_value='backup_behave.dump.gz') as create_backup:
        context.response = context.authenticated_client.post(
            '/management/backups/', {'create_local_backup': '1'}, follow=True
        )
        context.backup_service_called = create_backup.called


@then('the backup service was invoked')
def step_backup_called(context: runner.Context) -> None:
    assert context.backup_service_called
