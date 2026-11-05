# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""TLS activation keeps staged credentials available until both I/O steps succeed."""

import importlib

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from setup_wizard.management.commands.apply_bootstrap_config import OperationalBootstrapApplier
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard import tls_credential
from setup_wizard.tls_credential import TlsServerCredentialGenerator
from setup_wizard.views import FreshInstallSummaryView


@pytest.fixture(params=[FreshInstallSummaryView, OperationalBootstrapApplier])
def consumer(request):
    """Exercise both activation entry points with their normal exception and execution hooks."""
    cls = request.param
    instance = cls() if cls is FreshInstallSummaryView else cls({'fresh_install': {}})
    return instance, importlib.import_module(cls.__module__)


@pytest.fixture
def staged_credential(tmp_path, monkeypatch):
    """Stage a real TLS key and certificate without using the shared staging directory."""
    monkeypatch.setattr(tls_credential, 'TLS_STAGING_ROOT', tmp_path / 'tls')
    monkeypatch.setattr(tls_credential, 'TLS_PRIVATE_KEY_FILE', tmp_path / 'tls/key.pem')
    monkeypatch.setattr(tls_credential, 'TLS_CERTIFICATE_FILE', tmp_path / 'tls/cert.pem')
    monkeypatch.setattr(tls_credential, 'TLS_CHAIN_FILE', tmp_path / 'tls/chain.pem')
    serializer = TlsServerCredentialGenerator([], [], ['trustpoint.test']).generate_tls_server_credential()
    tls_credential.stage_tls_credential(serializer)
    return serializer


@pytest.mark.parametrize('failure_step', [None, 'pem', 'nginx'])
def test_staging_is_cleared_only_after_pem_write_and_nginx_succeed(
    consumer,
    staged_credential,
    failure_step,
    monkeypatch,
    django_capture_on_commit_callbacks,
):
    """Both entry points apply the saved credential and retain staging on either I/O failure."""
    instance, module = consumer
    observed = []

    def write_pem_files(credential):
        active = ActiveTrustpointTlsServerCredentialModel.objects.get(id=1)
        assert active.credential_id == credential.pk
        assert credential.get_certificate() == staged_credential.certificate
        observed.append('pem')
        if failure_step == 'pem':
            raise RuntimeError('PEM write failed')

    def execute_shell_script(script, mode):
        assert observed == ['pem']
        assert script == module.UPDATE_TLS_NGINX
        assert mode == 'no_hsm'
        assert tls_credential.load_staged_tls_credential() is not None
        observed.append('nginx')
        if failure_step == 'nginx':
            raise RuntimeError('Nginx apply failed')

    monkeypatch.setattr(instance, '_write_pem_files', write_pem_files)
    executor_owner = instance if isinstance(instance, OperationalBootstrapApplier) else module
    monkeypatch.setattr(executor_owner, 'execute_shell_script', execute_shell_script)

    if failure_step:
        with pytest.raises(RuntimeError, match='failed'):
            instance._apply_staged_tls_credential()
        assert tls_credential.load_staged_tls_credential() is not None
    else:
        with django_capture_on_commit_callbacks(execute=True):
            instance._apply_staged_tls_credential()
            assert tls_credential.load_staged_tls_credential() is not None
        assert tls_credential.load_staged_tls_credential() is None
        assert observed == ['pem', 'nginx']


def test_later_transaction_failure_preserves_staging(
    consumer,
    staged_credential,
    monkeypatch,
    django_capture_on_commit_callbacks,
):
    """A later setup write can roll back activation without deleting the key needed for retry."""
    instance, module = consumer
    before = list(ActiveTrustpointTlsServerCredentialModel.objects.values('pk', 'credential_id'))
    monkeypatch.setattr(instance, '_write_pem_files', lambda credential: None)
    executor_owner = instance if isinstance(instance, OperationalBootstrapApplier) else module
    monkeypatch.setattr(executor_owner, 'execute_shell_script', lambda *args: None)

    with django_capture_on_commit_callbacks(execute=True) as callbacks:
        with pytest.raises(IntegrityError), transaction.atomic():
            instance._apply_staged_tls_credential()
            raise IntegrityError('A later setup write failed')
    assert callbacks == []
    assert list(ActiveTrustpointTlsServerCredentialModel.objects.values('pk', 'credential_id')) == before
    assert tls_credential.load_staged_tls_credential().certificate == staged_credential.certificate


def test_missing_staged_credential_preserves_caller_exception(consumer, monkeypatch):
    """Missing staging still raises the exception expected by each caller."""
    instance, module = consumer
    before = list(ActiveTrustpointTlsServerCredentialModel.objects.values('pk', 'credential_id'))
    monkeypatch.setattr(module, 'load_staged_tls_credential', lambda: None)
    expected = ValidationError if isinstance(instance, OperationalBootstrapApplier) else ValueError
    with pytest.raises(expected, match='No staged TLS Server Credential found'):
        instance._apply_staged_tls_credential()
    assert list(ActiveTrustpointTlsServerCredentialModel.objects.values('pk', 'credential_id')) == before
