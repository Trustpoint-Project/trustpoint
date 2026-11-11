# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for separating issuing and management CA roles."""

from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError

from management.models import CertificateAuthenticationConfig
from pki.models import CaModel, DomainModel
from pki.services.management_ca import ManagementCAService
from pki.tests.managed_ca_helpers import create_managed_root_ca
from pki.util.x509 import CertificateGenerator

pytestmark = pytest.mark.django_db


def _management_ca(name: str) -> CaModel:
    cert, key = create_managed_root_ca(name)
    return CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=cert,
        private_key=key,
        chain=[],
        unique_name=name,
        ca_role=CaModel.CaRole.MANAGEMENT,
    )


def test_management_ca_reuses_existing_issuing_ca_types() -> None:
    """A management CA is a normal local CA with a role limiting its use."""
    ca = _management_ca('Management Test CA')

    assert ca.ca_type == CaModel.CaTypeChoice.LOCAL_PKCS11
    assert ca.is_management_ca
    assert ca.is_issuing_ca
    assert not ca.can_issue_endpoint_certificates


def test_management_role_rejects_autogen_and_keyless_types() -> None:
    """Auto-generated and keyless CAs cannot become management CAs."""
    for ca_type in (CaModel.CaTypeChoice.KEYLESS, CaModel.CaTypeChoice.AUTOGEN):
        ca = CaModel(unique_name=f'invalid-{ca_type}', ca_type=ca_type, ca_role=CaModel.CaRole.MANAGEMENT)
        with pytest.raises(ValidationError, match='cannot be used as a management CA'):
            ca.full_clean()


def test_domain_rejects_management_ca() -> None:
    """A management CA cannot be assigned to an endpoint domain."""
    ca = _management_ca('Management Domain CA')

    with pytest.raises(ValidationError, match='Management CAs cannot issue'):
        DomainModel.objects.create(unique_name='endpoint-domain', issuing_ca=ca)


def test_existing_domain_blocks_switching_ca_to_management() -> None:
    """A CA already serving an endpoint domain cannot be reclassified."""
    cert, key = create_managed_root_ca('Issuing CA For Domain')
    ca = CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=cert,
        private_key=key,
        chain=[],
        unique_name='issuing-ca-for-domain',
    )
    DomainModel.objects.create(unique_name='issuing-domain', issuing_ca=ca)

    ca.ca_role = CaModel.CaRole.MANAGEMENT
    with pytest.raises(ValidationError, match='assigned to a domain'):
        ca.save()


def test_service_rejects_issuing_ca_for_user_authentication() -> None:
    """Endpoint issuing CAs cannot be selected as the management CA."""
    cert, key = create_managed_root_ca('Endpoint Only CA')
    ca = CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=cert,
        private_key=key,
        chain=[],
        unique_name='endpoint-only-ca',
    )

    with pytest.raises(ValidationError, match='active management CA'):
        ManagementCAService.select_issuing_ca(ca.pk)


def test_service_selects_management_ca_for_user_authentication() -> None:
    """Selecting a management CA persists the choice and disables stale selections."""
    first = _management_ca('Management Select One')
    second = _management_ca('Management Select Two')
    CertificateAuthenticationConfig.objects.create(issuing_ca=first, enabled=True)

    ManagementCAService.select_issuing_ca(second.pk)

    assert ManagementCAService.get_issuing_ca() == second
    assert CertificateAuthenticationConfig.objects.get(issuing_ca=first).enabled is False
    assert CertificateAuthenticationConfig.objects.get(issuing_ca=second).enabled is False
    assert {ca.pk for ca in ManagementCAService.get_available_issuing_cas()} == {first.pk, second.pk}
