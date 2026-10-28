# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Test the DomainModel class."""

import datetime
from typing import Any

from cryptography import x509
from django.utils import timezone
from trustpoint_core import oid

from management.models.organization import OrganizationModel
from pki.models import DomainModel, CaModel

COMMON_NAME = 'Root CA'
UNIQUE_NAME = COMMON_NAME.replace(' ', '_').lower()
CA_TYPE = CaModel.CaTypeChoice.LOCAL_UNPROTECTED

DOMAIN_UNIQUE_NAME = 'domain_name'


def test_attributes_and_properties(domain_instance: dict[str, Any]) -> None:
    """Test that the common_name property returns the certificate's common name."""
    tz = timezone.get_current_timezone()
    current_time = datetime.datetime.now(tz)
    domain = domain_instance.get('domain')
    issuing_ca = domain_instance.get('issuing_ca')
    cert = domain_instance.get('cert')
    if (
        not isinstance(domain, DomainModel)
        or not isinstance(issuing_ca, CaModel)
        or not isinstance(cert, x509.Certificate)
    ):
        msg = 'Domain or IssuingCA not created properly'
        raise TypeError(msg)
    assert domain.unique_name == DOMAIN_UNIQUE_NAME
    assert domain.issuing_ca == issuing_ca
    assert domain.is_active
    time_difference = (current_time - domain.created_at).total_seconds()
    assert time_difference <= 20
    assert domain.signature_suite == oid.SignatureSuite.from_certificate(cert)


def test_domain_can_be_created_without_organization(issuing_ca_instance: dict[str, Any]) -> None:
    """Domain creation works without an organization assignment."""
    domain = DomainModel.objects.create(unique_name='domain-no-org-model', issuing_ca=issuing_ca_instance['issuing_ca'])

    assert domain.organization is None


def test_domain_can_be_assigned_to_organization(issuing_ca_instance: dict[str, Any]) -> None:
    """Domain can reference one organization."""
    organization = OrganizationModel.objects.create(name='Model Org', organization='Model Org O')
    domain = DomainModel.objects.create(
        unique_name='domain-with-org-model',
        issuing_ca=issuing_ca_instance['issuing_ca'],
        organization=organization,
    )

    assert domain.organization_id == organization.id


def test_organization_related_name_contains_multiple_domains(issuing_ca_instance: dict[str, Any]) -> None:
    """One organization can be assigned to multiple domains."""
    organization = OrganizationModel.objects.create(name='Shared Org', organization='Shared Org O')
    DomainModel.objects.create(
        unique_name='domain-shared-org-1',
        issuing_ca=issuing_ca_instance['issuing_ca'],
        organization=organization,
    )
    DomainModel.objects.create(
        unique_name='domain-shared-org-2',
        issuing_ca=issuing_ca_instance['issuing_ca'],
        organization=organization,
    )

    assert organization.domains.count() == 2


def test_deleting_organization_sets_domain_organization_to_none(issuing_ca_instance: dict[str, Any]) -> None:
    """Deleting an organization leaves domains intact and clears the relation."""
    organization = OrganizationModel.objects.create(name='Delete Org', organization='Delete Org O')
    domain = DomainModel.objects.create(
        unique_name='domain-org-set-null',
        issuing_ca=issuing_ca_instance['issuing_ca'],
        organization=organization,
    )

    organization.delete()
    domain.refresh_from_db()

    assert domain.organization is None
