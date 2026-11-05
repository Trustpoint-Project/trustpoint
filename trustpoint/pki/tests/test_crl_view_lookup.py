# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for shared CRL lookup and import behavior."""

import pytest
from django.core.exceptions import ValidationError
from django.http import Http404
from django.test import RequestFactory
from django.utils import timezone

from pki.models import CaModel, CertificateModel, CrlModel
from pki.util.x509 import CertificateGenerator
from pki.views.crls import CrlDetailView, CrlDownloadView, CrlImportView


@pytest.fixture
def lookup_ca():
    """Create a valid keyless CA for CRL lookup tests."""
    certificate, _ = CertificateGenerator.create_root_ca(cn='Lookup CA')
    return CaModel.objects.create(
        unique_name='lookup-ca',
        ca_type=CaModel.CaTypeChoice.KEYLESS,
        certificate=CertificateModel.save_certificate(certificate),
    )


@pytest.mark.parametrize('view_type', [CrlDetailView, CrlDownloadView])
def test_crl_id_takes_precedence_over_ca_id(view_type, lookup_ca):
    """Overlapping CRL and CA IDs resolve the explicit CRL, even if it is inactive."""
    ca = lookup_ca
    active = CrlModel.objects.create(
        pk=ca.pk + 1,
        ca=ca,
        crl_pem='active',
        this_update=timezone.now(),
        is_active=True,
    )
    explicit = CrlModel.objects.create(
        pk=ca.pk,
        ca=ca,
        crl_pem='historical',
        this_update=timezone.now(),
        is_active=False,
    )
    view = view_type()
    view.setup(RequestFactory().get('/'), pk=ca.pk)
    assert view.get_object() == explicit

    explicit.delete()
    assert view.get_object() == active


@pytest.mark.parametrize('view_type', [CrlDetailView, CrlDownloadView])
def test_crl_lookup_raises_404_without_an_active_crl(view_type, lookup_ca):
    """A CA with no active CRL and unknown IDs preserve the 404 response."""
    ca = lookup_ca
    view = view_type()
    view.setup(RequestFactory().get('/'), pk=ca.pk)
    with pytest.raises(Http404):
        view.get_object()
    view.kwargs['pk'] = ca.pk + 100
    with pytest.raises(Http404):
        view.get_object()


def test_crl_import_rejects_unparseable_data():
    """Removing repeated format attempts retains the validation error."""
    with pytest.raises(ValidationError, match='Unable to parse CRL'):
        CrlImportView()._convert_to_pem(b'not a CRL')
