# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for transactional, permission-checked bulk deletion."""

from unittest.mock import Mock, patch

import pytest
from django.contrib.auth import get_user_model
from django.contrib.messages.storage.fallback import FallbackStorage
from django.core.exceptions import PermissionDenied
from django.test import RequestFactory

from management.models.audit_log import AuditLog
from pki.models import CertificateProfileModel
from pki.views.cert_profiles import CertProfileBulkDeleteConfirmView


def make_delete_view(profile):
    """Prepare an actual bulk-delete view with messages and an authenticated actor."""
    request = RequestFactory().post('/')
    request.user = get_user_model().objects.create_user(username='deleter')
    request.user.has_perm = Mock(return_value=True)
    request.session = {}
    request._messages = FallbackStorage(request)
    view = CertProfileBulkDeleteConfirmView()
    view.setup(request, pks=str(profile.pk))
    return view


def test_bulk_deletion_records_each_deleted_object():
    """Deleting a profile retains its identity in one persisted audit entry."""
    profile = CertificateProfileModel.objects.create(unique_name='delete-me', profile_json={})
    pk = profile.pk
    response = make_delete_view(profile).post()

    assert response.status_code == 302
    assert not CertificateProfileModel.objects.filter(pk=pk).exists()
    entry = AuditLog.objects.get(operation_type=AuditLog.OperationType.CERT_PROFILE_DELETED)
    assert entry.target_object_id == str(pk)


def test_bulk_deletion_rolls_back_if_audit_fails():
    """An audit failure restores the deleted objects and rolls back audit rows."""
    profile = CertificateProfileModel.objects.create(unique_name='keep-me', profile_json={})
    view = make_delete_view(profile)
    with patch('shared.views.audit_security_change', side_effect=RuntimeError('audit unavailable')):
        with pytest.raises(RuntimeError, match='audit unavailable'):
            view.post()

    assert CertificateProfileModel.objects.filter(pk=profile.pk).exists()
    assert not AuditLog.objects.filter(operation_type=AuditLog.OperationType.CERT_PROFILE_DELETED).exists()


def test_bulk_deletion_requires_the_resource_permission():
    """Permission denial leaves both the selected object and audit log unchanged."""
    profile = CertificateProfileModel.objects.create(unique_name='protected-profile', profile_json={})
    view = make_delete_view(profile)
    view.request.user.has_perm.return_value = False
    with pytest.raises(PermissionDenied):
        view.post()

    assert CertificateProfileModel.objects.filter(pk=profile.pk).exists()
    assert not AuditLog.objects.filter(operation_type=AuditLog.OperationType.CERT_PROFILE_DELETED).exists()
