"""Test suite for validating the TLS Server Credential functionality."""

import ipaddress
from typing import Any

import pytest
from cryptography.x509 import DNSName, IPAddress, SubjectAlternativeName

from devices.issuer import LocalTlsServerCredentialIssuer
from devices.models import IssuedCredentialModel


@pytest.mark.django_db
def test_issue_tls_server_credential(device_instance: dict[str, Any]) -> None:
    """Test that issuing a TLS server credential works without mocks."""
    device = device_instance['device']

    issuer = LocalTlsServerCredentialIssuer(device=device, domain=device.domain)

    common_name = 'Test TLS Server Credential'
    validity_days = 365
    ipv4_addresses: list[ipaddress.IPv4Address] = [ipaddress.IPv4Address('192.168.1.1')]
    ipv6_addresses: list[ipaddress.IPv6Address] = [ipaddress.IPv6Address('2001:db8::1')]
    domain_names = ['example.com']

    issued_credential = issuer.issue_tls_server_credential(
        common_name=common_name,
        ipv4_addresses=ipv4_addresses,
        ipv6_addresses=ipv6_addresses,
        domain_names=domain_names,
        validity_days=validity_days,
    )

    assert isinstance(issued_credential, IssuedCredentialModel), (
        'The returned object should be an IssuedCredentialModel'
    )
    assert issued_credential.common_name == common_name, 'The common name of the issued credential should match'
    assert issued_credential.device == device, 'The issued credential should belong to the correct device'
    assert issued_credential.domain == device.domain, 'The issued credential should belong to the correct domain'
    assert issued_credential.issued_credential_type == IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL
    assert issued_credential.issued_credential_purpose == IssuedCredentialModel.IssuedCredentialPurpose.TLS_SERVER

    db_credential = IssuedCredentialModel.objects.get(pk=issued_credential.pk)
    assert db_credential == issued_credential, 'The credential should be saved correctly in the database'

    certificate = issued_credential.credential.get_certificate()
    san_extension = certificate.extensions.get_extension_for_class(SubjectAlternativeName).value

    san_ip_addresses = san_extension.get_values_for_type(IPAddress)
    for ip in ipv4_addresses:
        assert ip in san_ip_addresses, f'IPv4 address {ip} should be included in the SAN'

    san_dns_names = san_extension.get_values_for_type(DNSName)
    for domain in domain_names:
        assert domain in san_dns_names, f'Domain name {domain} should be included in the SAN'
