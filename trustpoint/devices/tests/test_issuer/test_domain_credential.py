"""Test suite for validating the Domain Credential functionality."""

from typing import Any

import pytest

from devices.issuer import LocalDomainCredentialIssuer
from devices.models import IssuedCredentialModel
from onboarding.models import OnboardingStatus


@pytest.mark.django_db
def test_issue_domain_credential(device_instance_onboarding: dict[str, Any]) -> None:
    """Test that issuing a domain credential works without mocks."""
    device = device_instance_onboarding['device']

    issuer = LocalDomainCredentialIssuer(device=device, domain=device.domain)

    issued_credential = issuer.issue_domain_credential()

    assert isinstance(issued_credential, IssuedCredentialModel), (
        'The returned object should be an IssuedCredentialModel'
    )
    assert issued_credential.common_name == 'Trustpoint Domain Credential', 'The common name should match the pseudonym'
    assert issued_credential.device == device, 'The issued credential should belong to the correct device'
    assert issued_credential.domain == device.domain, 'The issued credential should belong to the correct domain'
    assert issued_credential.issued_credential_type == IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL, (
        'The issued_credential_type should match DOMAIN_CREDENTIAL'
    )
    assert issued_credential.issued_using_cert_profile == 'Trustpoint Domain Credential', (
        'issued_using_cert_profile should match Trustpoint Domain Credential'
    )

    device.refresh_from_db()
    assert device.onboarding_config.onboarding_status == OnboardingStatus.ONBOARDED, (
        'The device onboarding status should be updated to ONBOARDED'
    )

    db_credential = IssuedCredentialModel.objects.get(pk=issued_credential.pk)
    assert db_credential == issued_credential, 'The credential should be saved correctly in the database'

    cert_chain = issued_credential.credential.get_certificate_chain()
    assert isinstance(cert_chain, list), 'The certificate chain should be a list'
    assert len(cert_chain) > 0, 'The certificate chain should not be empty'
    assert all(cert is not None for cert in cert_chain), 'All certificates in the chain should be valid'
