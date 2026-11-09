# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Certificate deletion checks truststore authority while holding the certificate lock."""

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.db import DatabaseError, connection, connections, transaction
from django.db.models import QuerySet
from rest_framework.exceptions import PermissionDenied

from pki.models import CertificateModel
from pki.models.truststore import TruststoreModel, TruststoreOrderModel
from pki.util.x509 import CertificateGenerator
from pki.views.certificates import CertificateViewSet
from users.permissions import AppPermissions


@pytest.fixture
def certificate():
    cert, _ = CertificateGenerator.create_root_ca('Deletion test')
    return CertificateModel.save_certificate(cert)


def test_denied_deletion_keeps_certificate_and_membership(certificate):
    truststore = TruststoreModel.objects.create(
        unique_name='deletion-test', intended_usage=TruststoreModel.IntendedUsage.TLS
    )
    membership = TruststoreOrderModel.objects.create(certificate=certificate, trust_store=truststore, order=0)
    view = CertificateViewSet()
    view.request = SimpleNamespace(user=SimpleNamespace(has_perm=lambda name: name == AppPermissions.MANAGE_CAS))

    with pytest.raises(PermissionDenied):
        view.perform_destroy(certificate)

    assert CertificateModel.objects.filter(pk=certificate.pk).exists()
    assert TruststoreOrderModel.objects.filter(pk=membership.pk).exists()


@pytest.mark.django_db(transaction=True)
def test_certificate_is_locked_before_membership_authorization(certificate):
    if not connection.features.has_select_for_update_nowait:
        pytest.skip('Requires a database with nonblocking row locks, such as PostgreSQL.')
    certificate_pk = certificate.pk
    view = CertificateViewSet()
    view.request = SimpleNamespace(user=SimpleNamespace(has_perm=lambda name: name == AppPermissions.MANAGE_CAS))
    original_exists = QuerySet.exists
    checks = []

    def row_is_locked():
        try:
            with transaction.atomic():
                CertificateModel.objects.select_for_update(nowait=True).get(pk=certificate_pk)
        except DatabaseError:
            return True
        finally:
            connections.close_all()
        return False

    def check_membership(queryset):
        if queryset.model is TruststoreOrderModel:
            with ThreadPoolExecutor(max_workers=1) as pool:
                assert pool.submit(row_is_locked).result(timeout=5)
            checks.append(True)
        return original_exists(queryset)

    with patch.object(QuerySet, 'exists', check_membership):
        view.perform_destroy(certificate)

    assert checks
    assert not CertificateModel.objects.filter(pk=certificate_pk).exists()
