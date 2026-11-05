# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for profile selection shared by CA and owner-credential views."""

import pytest
from django.test import RequestFactory

from devices.views.owner_credentials import (
    OwnerCredentialDefineCertContentDomainCredentialEstView,
    OwnerCredentialDefineCertContentEstView,
)
from pki.models import CertificateProfileModel
from pki.views.issuing_cas import IssuingCaDefineCertContentEstView


@pytest.mark.parametrize(
    'view_type,default_name',
    [
        (IssuingCaDefineCertContentEstView, 'issuing_ca'),
        (OwnerCredentialDefineCertContentEstView, 'dev_owner_id'),
        (OwnerCredentialDefineCertContentDomainCredentialEstView, 'devownerid_domain_credential'),
    ],
)
def test_profile_selection_preserves_defaults_and_request_precedence(view_type, default_name):
    """Views keep their own defaults, explicit GET/POST selection, and ordered fallback."""
    view = view_type()
    factory = RequestFactory()
    assert view._resolve_cert_profile(factory.get('/')) is None

    first = CertificateProfileModel.objects.create(unique_name='first', display_name='A', profile_json={})
    default = CertificateProfileModel.objects.create(unique_name=default_name, display_name='B', profile_json={})
    assert view._resolve_cert_profile(factory.get('/')) == default
    assert view.available_profiles == [first, default]
    assert view._resolve_cert_profile(factory.get('/', {'cert_profile_pk': first.pk})) == first
    assert view._resolve_cert_profile(factory.post('/', {'cert_profile_pk': first.pk})) == first
    assert (
        view._resolve_cert_profile(factory.post(f'/?cert_profile_pk={default.pk}', {'cert_profile_pk': first.pk}))
        == default
    )
    assert view._resolve_cert_profile(factory.get('/', {'cert_profile_pk': 'invalid'})) == default
    assert view._resolve_cert_profile(factory.get('/', {'cert_profile_pk': default.pk + 1000})) == default

    default.delete()
    assert view._resolve_cert_profile(factory.get('/')) == first
