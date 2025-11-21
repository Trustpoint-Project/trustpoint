"""Test suite for validating the OPC UA Server Credential functionality."""

import ipaddress
from typing import Any

import pytest
from cryptography.x509 import DNSName, IPAddress, SubjectAlternativeName, UniformResourceIdentifier

from devices.issuer import OpcUaServerCredentialIssuer
from devices.models import IssuedCredentialModel


@pytest.mark.django_db
def test_issue_opc_ua_server_credential(device_instance: dict[str, Any]) -> None:
    """Test that issuing an OPC UA server credential works without mocks."""
    device = device_instance['device']

    issuer = OpcUaServerCredentialIssuer(device=device, domain=device.domain)

    common_name = 'Test OPC UA Server Credential'
    application_uri = 'urn:example:opc-ua:server'
    ipv4_addresses = [ipaddress.IPv4Address('192.168.1.100')]
    ipv6_addresses: list[ipaddress.IPv6Address] = []
    domain_names = ['opc-ua.example.com']
    validity_days = 365

    issued_credential = issuer.issue_opc_ua_server_credential(
        common_name=common_name,
        application_uri=application_uri,
        ipv4_addresses=ipv4_addresses,
        ipv6_addresses=ipv6_addresses,
        domain_names=domain_names,
        validity_days=validity_days,
    )

    assert isinstance(issued_credential, IssuedCredentialModel), (
        'The returned object should be an IssuedCredentialModel'
    )
    assert issued_credential.common_name == common_name, 'The common name should match the input'
    assert issued_credential.device == device, 'The issued credential should belong to the correct device'
    assert issued_credential.domain == device.domain, 'The issued credential should belong to the correct domain'
    assert (
        issued_credential.issued_credential_type == IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL
    ), 'The issued_credential_type should be APPLICATION_CREDENTIAL'
    assert issued_credential.issued_using_cert_profile == 'OPC UA Server', (
        'The issued_using_cert_profile should be OPC UA Server'
    )

    db_credential = IssuedCredentialModel.objects.get(pk=issued_credential.pk)
    assert db_credential == issued_credential, 'The credential should be saved correctly in the database'

    certificate = issued_credential.credential.get_certificate()
    san_extension = certificate.extensions.get_extension_for_class(SubjectAlternativeName).value

    san_uris = san_extension.get_values_for_type(UniformResourceIdentifier)
    assert application_uri in san_uris, f'The application URI {application_uri} should be present in the SAN'

    san_ipv4_addresses = san_extension.get_values_for_type(IPAddress)
    for ip in ipv4_addresses:
        assert ip in san_ipv4_addresses, f'IPv4 address {ip} should be included in the SAN'

    san_dns_names = san_extension.get_values_for_type(DNSName)
    for domain in domain_names:
        assert domain in san_dns_names, f'Domain name {domain} should be included in the SAN'

    cert_chain = issued_credential.credential.get_certificate_chain()
    assert isinstance(cert_chain, list), 'The certificate chain should be a list'
    assert len(cert_chain) > 0, 'The certificate chain should not be empty'
    assert all(cert is not None for cert in cert_chain), 'All certificates in the chain should be valid'
