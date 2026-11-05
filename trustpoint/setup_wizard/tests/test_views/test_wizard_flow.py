# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Exercise wizard requests with real forms and persisted progress."""

from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest
from django.contrib.auth.models import AnonymousUser
from django.contrib.messages import get_messages
from django.contrib.messages.storage.fallback import FallbackStorage
from django.core.exceptions import ValidationError
from django.urls import reverse

from setup_wizard import views
from setup_wizard.models import SetupWizardConfigModel
from setup_wizard.operational_handoff import OperationalRuntimeSwitchResult


@pytest.fixture(autouse=True)
def bootstrap_routes(settings):
    """Wizard routes are only exposed by the bootstrap URL configuration."""
    settings.ROOT_URLCONF = 'trustpoint.urls_bootstrap'


@pytest.fixture
def wizard_request(rf, django_user_model):
    """Build authenticated requests without the deployment-specific bootstrap middleware."""

    def build(method='get', url='/', data=None):
        request = getattr(rf, method)(url, data=data or {})
        request.user = django_user_model(username='bootstrap')
        request.session = {}
        request._messages = FallbackStorage(request)
        return request

    return build


@pytest.mark.parametrize(
    'view_class,url_name',
    [
        (views.FreshInstallAdminUserView, 'fresh_install_admin_user'),
        (views.FreshInstallDatabaseView, 'fresh_install_database'),
        (views.ConnectExistingDatabaseView, 'connect_existing_database'),
        (views.RestoreBackupDatabaseView, 'restore_backup_database'),
        (views.FreshInstallSummaryView, 'fresh_install_summary'),
    ],
)
def test_wizard_requires_authentication(rf, view_class, url_name):
    request = rf.get(reverse(f'setup_wizard:{url_name}'))
    request.user = AnonymousUser()
    response = view_class.as_view()(request)
    assert response.status_code == 302
    assert 'next=' in response.url
    assert not SetupWizardConfigModel.objects.exists()


@pytest.mark.parametrize(
    'flow,step,url_name',
    [
        ('fresh_install', 'admin_user', 'fresh_install_admin_user'),
        ('fresh_install', 'database', 'fresh_install_database'),
        ('fresh_install', 'backend_config', 'fresh_install_backend_config'),
        ('fresh_install', 'tls_config', 'fresh_install_tls_config'),
        ('fresh_install', 'summary', 'fresh_install_summary'),
        ('connect_existing', 'database', 'connect_existing_database'),
        ('connect_existing', 'backend-config', 'connect_existing_backend_config'),
        ('connect_existing', 'summary', 'connect_existing_summary'),
        ('restore_backup', 'backup-import', 'restore_backup_import'),
        ('restore_backup', 'summary', 'restore_backup_summary'),
        ('unknown', 'summary', None),
        ('fresh_install', 'unknown', None),
        ('', '', None),
    ],
)
def test_index_resumes_recorded_flow(wizard_request, flow, step, url_name):
    config = SetupWizardConfigModel.get_singleton()
    config.bootstrap_active_flow = flow
    config.bootstrap_current_step = step
    config.save()
    response = views.SetupWizardIndexView.as_view()(wizard_request())
    expected = reverse(f'setup_wizard:{url_name}') if url_name else None
    assert response.context_data['continue_url'] == expected


@pytest.mark.parametrize('initial_step', [0, 6])
def test_visiting_fresh_step_records_resume_location_without_relocking_steps(wizard_request, initial_step):
    config = SetupWizardConfigModel.get_singleton()
    config.fresh_install_current_step = initial_step
    config.fresh_install_admin_user_submitted = True
    config.save()
    response = views.FreshInstallDatabaseView.as_view()(wizard_request())
    config.refresh_from_db()
    assert config.bootstrap_active_flow == 'fresh_install'
    assert config.bootstrap_current_step == 'database'
    assert config.fresh_install_current_step == max(initial_step, 1)
    steps = response.context_data['steps']
    assert [step['state'] for step in steps[:2]] == ['done', 'active']
    assert steps[-1]['state'] == ('pending' if initial_step == 0 else 'available')


@pytest.mark.parametrize(
    'view_class,flow',
    [
        (views.ConnectExistingDatabaseView, 'connect_existing'),
        (views.RestoreBackupDatabaseView, 'restore_backup'),
    ],
)
def test_attach_page_records_flow_and_shows_submitted_steps(wizard_request, view_class, flow):
    config = SetupWizardConfigModel.get_singleton()
    config.fresh_install_crypto_storage_submitted = True
    config.save()
    response = view_class.as_view()(wizard_request())
    config.refresh_from_db()
    assert config.bootstrap_active_flow == flow
    assert config.bootstrap_current_step == 'database'
    states = [step['state'] for step in response.context_data['steps']]
    assert states[:3] == ['active', 'done', 'available']


@pytest.fixture
def database_data():
    return {
        'operational_db_host': 'postgres.test',
        'operational_db_port': '5433',
        'operational_db_name': 'wizard_db',
        'operational_db_user': 'wizard_user',
        'operational_db_password': 'test-only-password',
    }


@pytest.mark.parametrize(
    'view_class,next_name',
    [
        (views.FreshInstallDatabaseView, 'fresh_install_crypto_storage'),
        (views.ConnectExistingDatabaseView, 'connect_existing_crypto_storage'),
        (views.RestoreBackupDatabaseView, 'restore_backup_crypto_storage'),
    ],
)
def test_database_submission_saves_and_continues(wizard_request, database_data, view_class, next_name):
    response = view_class.as_view()(wizard_request('post', data=database_data))
    assert response.status_code == 302
    assert response.url == reverse(f'setup_wizard:{next_name}')
    config = SetupWizardConfigModel.get_singleton()
    assert config.operational_db_host == 'postgres.test'
    assert config.operational_db_port == 5433
    assert config.operational_db_password == 'test-only-password'
    assert config.fresh_install_database_submitted is True


@pytest.mark.parametrize('view_class', [views.FreshInstallDatabaseView, views.ConnectExistingDatabaseView])
@pytest.mark.parametrize('error', [None, RuntimeError('connection refused'), RuntimeError()])
def test_database_probe_success_and_failure(wizard_request, database_data, monkeypatch, view_class, error):
    connect = MagicMock()
    connect.side_effect = error
    monkeypatch.setattr(views.psycopg, 'connect', connect)
    request = wizard_request('post', data={**database_data, 'wizard_action': 'test_database'})
    response = view_class.as_view()(request)
    assert connect.call_args.kwargs == {
        'dbname': 'wizard_db',
        'user': 'wizard_user',
        'password': 'test-only-password',
        'host': 'postgres.test',
        'port': 5433,
        'connect_timeout': 5,
    }
    if error is None:
        assert response.status_code == 302
        assert 'PostgreSQL connection successful.' in [str(message) for message in get_messages(request)]
    else:
        assert response.status_code == 200
        errors = response.context_data['form'].non_field_errors()
        assert f'Could not connect to PostgreSQL: {str(error) or "RuntimeError"}' in errors
    assert SetupWizardConfigModel.get_singleton().operational_db_host == 'postgres.test'


def test_invalid_database_submission_does_not_save_or_probe(wizard_request, database_data, monkeypatch):
    connect = Mock()
    monkeypatch.setattr(views.psycopg, 'connect', connect)
    config = SetupWizardConfigModel.get_singleton()
    old_host = config.operational_db_host
    response = views.FreshInstallDatabaseView.as_view()(
        wizard_request(
            'post',
            data={**database_data, 'operational_db_port': 'invalid', 'wizard_action': 'test_database'},
        )
    )
    assert response.status_code == 200
    assert 'operational_db_port' in response.context_data['form'].errors
    connect.assert_not_called()
    config.refresh_from_db()
    assert config.operational_db_host == old_host
    assert config.fresh_install_database_submitted is False


def test_bootstrap_summary_retry_does_not_reapply_database(wizard_request, monkeypatch, settings, tmp_path):
    settings.TRUSTPOINT_IS_BOOTSTRAP = True
    config = SetupWizardConfigModel.get_singleton()
    config.operational_config_applied = True
    config.save()
    pending = tmp_path / 'pending.env'
    refresh = Mock(return_value=SimpleNamespace(pending_env_file=pending))
    apply = Mock(side_effect=AssertionError('database must not be applied twice'))
    switch = Mock(return_value=OperationalRuntimeSwitchResult(switched=True, detail='started'))
    monkeypatch.setattr(views, 'refresh_pending_operational_env', refresh)
    monkeypatch.setattr(views, 'run_operational_handoff', apply)
    monkeypatch.setattr(views, 'run_operational_runtime_switch', switch)
    response = views.FreshInstallSummaryView.as_view()(wizard_request('post'))
    assert response.status_code == 302
    assert response.url == '/users/login/'
    refresh.assert_called_once()
    apply.assert_not_called()
    switch.assert_called_once_with(pending)


def test_bootstrap_switch_failure_retains_applied_flag_for_safe_retry(wizard_request, monkeypatch, settings, tmp_path):
    settings.TRUSTPOINT_IS_BOOTSTRAP = True
    config = SetupWizardConfigModel.get_singleton()
    config.crypto_storage = SetupWizardConfigModel.CryptoStorageType.SoftwareStorage
    config.save()
    apply = Mock(return_value=SimpleNamespace(pending_env_file=tmp_path / 'pending.env'))
    monkeypatch.setattr(views, 'run_operational_handoff', apply)
    monkeypatch.setattr(views, 'run_operational_runtime_switch', Mock(side_effect=ValidationError('switch failed')))
    response = views.FreshInstallSummaryView.as_view()(wizard_request('post'))
    assert response.status_code == 200
    assert 'switch failed' in str(response.context_data['form'].errors)
    config.refresh_from_db()
    assert config.operational_config_applied is True
    assert config.fresh_install_summary_submitted is True
    apply.assert_called_once()


@pytest.mark.parametrize('view_class', [views.ConnectExistingSummaryView, views.RestoreBackupSummaryView])
def test_attach_summary_blocks_apply_when_inspection_fails(wizard_request, monkeypatch, view_class):
    report = SimpleNamespace(can_apply=False)
    monkeypatch.setattr(view_class, '_build_report', lambda self: report)
    handoff = Mock(side_effect=AssertionError('incompatible state must not be applied'))
    monkeypatch.setattr(views, 'run_operational_attach_handoff', handoff)
    response = view_class.as_view()(wizard_request('post'))
    assert response.status_code == 200
    assert response.context_data['compatibility_report'] is report
    assert response.context_data['is_attach_summary'] is True
    assert SetupWizardConfigModel.get_singleton().operational_config_applied is False
    handoff.assert_not_called()


@pytest.mark.parametrize('view_class', [views.ConnectExistingSummaryView, views.RestoreBackupSummaryView])
@pytest.mark.parametrize('switched', [False, True])
def test_attach_summary_applies_and_records_completion(wizard_request, monkeypatch, tmp_path, view_class, switched):
    report = SimpleNamespace(can_apply=True)
    monkeypatch.setattr(view_class, '_build_report', lambda self: report)
    config = SetupWizardConfigModel.get_singleton()
    config.crypto_storage = SetupWizardConfigModel.CryptoStorageType.SoftwareStorage
    config.save()
    pending = tmp_path / 'pending.env'
    handoff = Mock(return_value=SimpleNamespace(pending_env_file=pending))
    switch = Mock(return_value=OperationalRuntimeSwitchResult(switched=switched, detail='test switch'))
    monkeypatch.setattr(views, 'run_operational_attach_handoff', handoff)
    monkeypatch.setattr(views, 'run_operational_runtime_switch', switch)
    request = wizard_request('post')
    response = view_class.as_view()(request)
    assert response.status_code == 302
    assert response.url == '/users/login/'
    config.refresh_from_db()
    assert config.operational_config_applied is True
    assert config.fresh_install_summary_submitted is True
    assert views.SetupWizardCompletedModel.objects.get().setup_completed_at is not None
    handoff.assert_called_once()
    switch.assert_called_once_with(pending)
    messages = [str(message) for message in get_messages(request)]
    assert len(messages) == 1
    assert ('successfully' if switched else 'Restart the runtime') in messages[0]


@pytest.mark.parametrize('view_class', [views.ConnectExistingSummaryView, views.RestoreBackupSummaryView])
def test_attach_summary_handoff_error_leaves_setup_incomplete(wizard_request, monkeypatch, view_class):
    report = SimpleNamespace(can_apply=True)
    monkeypatch.setattr(view_class, '_build_report', lambda self: report)
    config = SetupWizardConfigModel.get_singleton()
    config.crypto_storage = SetupWizardConfigModel.CryptoStorageType.SoftwareStorage
    config.save()
    monkeypatch.setattr(views, 'run_operational_attach_handoff', Mock(side_effect=ValidationError('handoff failed')))
    switch = Mock()
    monkeypatch.setattr(views, 'run_operational_runtime_switch', switch)
    response = view_class.as_view()(wizard_request('post'))
    assert response.status_code == 200
    assert 'handoff failed' in str(response.context_data['form'].non_field_errors())
    config.refresh_from_db()
    assert config.operational_config_applied is False
    assert config.fresh_install_summary_submitted is False
    assert not views.SetupWizardCompletedModel.objects.filter(setup_completed_at__isnull=False).exists()
    switch.assert_not_called()
