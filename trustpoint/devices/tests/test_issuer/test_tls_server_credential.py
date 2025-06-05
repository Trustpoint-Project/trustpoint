import ipaddress

import pytest
from cryptography.x509 import DNSName, IPAddress, SubjectAlternativeName

from devices.models import IssuedCredentialModel
from devices.issuer import LocalTlsServerCredentialIssuer

@pytest.mark.django_db
def test_issue_tls_server_credential(test_device):
    """Test that issuing a TLS server credential works without mocks."""
    issuer = LocalTlsServerCredentialIssuer(device=test_device, domain=test_device.domain)

    common_name = "Test TLS Server Credential"
    validity_days = 365
    ipv4_addresses = [ipaddress.IPv4Address("192.168.1.1")]
    ipv6_addresses = [ipaddress.IPv6Address("2001:db8::1")]
    domain_names = ["example.com"]

    issued_credential = issuer.issue_tls_server_credential(
        common_name=common_name,
        ipv4_addresses=ipv4_addresses,
        ipv6_addresses=ipv6_addresses,
        domain_names=domain_names,
        validity_days=validity_days,
    )

    assert isinstance(issued_credential, IssuedCredentialModel), "The returned object should be an IssuedCredentialModel"
    assert issued_credential.common_name == common_name, "The common name of the issued credential should match"
    assert issued_credential.device == test_device, "The issued credential should belong to the correct device"
    assert issued_credential.domain == test_device.domain, "The issued credential should belong to the correct domain"
    assert issued_credential.issued_credential_type == IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL
    assert issued_credential.issued_credential_purpose == IssuedCredentialModel.IssuedCredentialPurpose.TLS_SERVER

    db_credential = IssuedCredentialModel.objects.get(pk=issued_credential.pk)
    assert db_credential == issued_credential, "The credential should be saved correctly in the database"

    certificate = issued_credential.credential.get_certificate()
    san_extension = certificate.extensions.get_extension_for_class(SubjectAlternativeName).value

    san_ipv4_addresses = san_extension.get_values_for_type(IPAddress)
    for ip in ipv4_addresses:
        assert ip in san_ipv4_addresses, f"IPv4 address {ip} should be included in the SAN"

    san_ipv6_addresses = san_extension.get_values_for_type(IPAddress)
    for ip in ipv6_addresses:
        assert ip in san_ipv6_addresses, f"IPv6 address {ip} should be included in the SAN"

    san_dns_names = san_extension.get_values_for_type(DNSName)
    for domain in domain_names:
        assert domain in san_dns_names, f"Domain name {domain} should be included in the SAN"