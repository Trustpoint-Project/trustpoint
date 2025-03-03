"""Fixtures for the PKI pytest suite."""

# ruff: noqa: ERA001  # commented out tests for extensions that are not yet supported

import hashlib
import ipaddress
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import (
    AuthorityKeyIdentifier,
    BasicConstraints,
    DirectoryName,
    DNSName,
    ExtendedKeyUsage,
    IPAddress,
    IssuerAlternativeName,
    KeyUsage,
    NameConstraints,
    NoticeReference,
    OtherName,
    PolicyInformation,
    RegisteredID,
    RFC822Name,
    SubjectAlternativeName,
    SubjectKeyIdentifier,
    UniformResourceIdentifier,
    UserNotice,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier, SubjectInformationAccessOID
from pyasn1.codec.der.encoder import encode  # type: ignore  # noqa: PGH003
from pyasn1.type import char  # type: ignore  # noqa: PGH003

from pki.models.certificate import CertificateModel
from pki.tests import (
    COMMON_NAME,
    COUNTRY_NAME,
    DNS_NAME_VALUE,
    INHIBIT_ANY_POLICY_VALUE,
    INHIBIT_POLICY_MAPPING,
    IP_ADDRESS_VALUE,
    KEY_USAGE_FLAGS,
    ORGANIZATION_NAME,
    OTHER_NAME_CONTENT,
    OTHER_NAME_OID,
    REGISTERED_ID_OID,
    REQUIRE_EXPLICIT_POLICY,
    RFC822_EMAIL,
    URI_VALUE,
)

# ----------------------------
# Basic Self-Signed Certificate Fixture
# ----------------------------

@pytest.fixture
def self_signed_cert_basic(rsa_private_key: rsa.RSAPrivateKey) -> tuple[CertificateModel, x509.Certificate]:
    """Creates a self-signed CA certificate with minimal extensions and saves it to the database once per module.

    We manually unblock the DB because this fixture has 'module' scope.
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME),
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY_NAME),
    ])
    issuer = subject
    now = datetime.now(UTC)

    basic_constraints = BasicConstraints(ca=True, path_length=None)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(rsa_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .add_extension(basic_constraints, critical=True)
        .sign(private_key=rsa_private_key, algorithm=hashes.SHA256())
    )

    cert_model = CertificateModel.save_certificate(cert)
    return (cert_model, cert)

# ----------------------------
# Self-Signed Certificate with Extensions Fixture
# ----------------------------

@pytest.fixture
def self_signed_cert_with_ext(rsa_private_key: rsa.RSAPrivateKey) -> x509.Certificate:
    """Create a self-signed certificate with multiple extensions."""
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME),
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY_NAME),
    ])
    issuer = subject
    now = datetime.now(UTC)

    # Build General Names
    rfc822_name = RFC822Name(RFC822_EMAIL)
    dns_name = DNSName(DNS_NAME_VALUE)
    uri = UniformResourceIdentifier(URI_VALUE)
    directory_name = DirectoryName(
        x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION_NAME)])
    )
    registered_id = RegisteredID(ObjectIdentifier(REGISTERED_ID_OID))
    ip_addr = IPAddress(ipaddress.ip_address(IP_ADDRESS_VALUE))

    other_name_content = char.UTF8String(OTHER_NAME_CONTENT)
    other_name_der = encode(other_name_content)
    other_name = OtherName(
        type_id=ObjectIdentifier(OTHER_NAME_OID),
        value=other_name_der
    )

    serial_number = x509.random_serial_number()

    san = SubjectAlternativeName([
        rfc822_name, dns_name, uri, directory_name, registered_id, ip_addr, other_name
    ])
    ian = IssuerAlternativeName([
        rfc822_name, dns_name, uri, directory_name, registered_id, ip_addr, other_name
    ])

    key_usage = KeyUsage(**KEY_USAGE_FLAGS)

    public_key = rsa_private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_identifier = hashlib.sha1(public_key_bytes).digest()  # noqa: S324  # SHA-1 according to RFC 5280 sec. 4.2.1.2

    aki = AuthorityKeyIdentifier(
        key_identifier=key_identifier,
        authority_cert_issuer=[rfc822_name, dns_name, uri, directory_name, registered_id, ip_addr, other_name],
        authority_cert_serial_number=serial_number
    )
    ski = SubjectKeyIdentifier(digest=key_identifier)

    cp = x509.CertificatePolicies([
        PolicyInformation(
            policy_identifier=ObjectIdentifier('2.23.140.1.1'),
            policy_qualifiers=[
                'https://example-ev-certs.com/cps',
                UserNotice(
                    notice_reference=NoticeReference(
                        organization='Example EV Certification Authority',
                        notice_numbers=[1, 2]
                    ),
                    explicit_text="EV certificates issued under Example EV CA's CP/CPS."
                ),
            ],
        ),
        x509.PolicyInformation(
            policy_identifier=x509.ObjectIdentifier('2.23.140.1.2.1'),
            policy_qualifiers=[
                'https://example-dv-certs.com/cps',
                x509.UserNotice(
                    notice_reference=None,
                    explicit_text='DV certificates issued with minimal identity validation.'
                )
            ]
        )
    ])

    eku = ExtendedKeyUsage([
        ExtendedKeyUsageOID.SERVER_AUTH,
        ExtendedKeyUsageOID.CLIENT_AUTH,
        ExtendedKeyUsageOID.CODE_SIGNING,
        ExtendedKeyUsageOID.EMAIL_PROTECTION,
        ExtendedKeyUsageOID.TIME_STAMPING,
        ExtendedKeyUsageOID.OCSP_SIGNING,
    ])

    name_constraints = NameConstraints(
        permitted_subtrees=[rfc822_name, dns_name, uri],
        excluded_subtrees=[directory_name, registered_id, other_name]
    )

    aia = x509.AuthorityInformationAccess([
        x509.AccessDescription(
            access_method=x509.AuthorityInformationAccessOID.CA_ISSUERS,
            access_location=x509.DNSName(DNS_NAME_VALUE)
        ),
        x509.AccessDescription(
            access_method=x509.AuthorityInformationAccessOID.OCSP,
            access_location=x509.UniformResourceIdentifier(URI_VALUE)
        )
    ])

    sia = x509.SubjectInformationAccess([
        x509.AccessDescription(
            access_method=SubjectInformationAccessOID.CA_REPOSITORY,
            access_location=x509.DNSName(DNS_NAME_VALUE)
        )
    ])

    iap = x509.InhibitAnyPolicy(INHIBIT_ANY_POLICY_VALUE)

    # policy_mappings = x509.PolicyMappings([
    #     x509.PolicyMapping(
    #         issuer_domain_policy=ObjectIdentifier('1.2.3.4.5'),
    #         subject_domain_policy=ObjectIdentifier('1.2.3.4.6')
    #     ),
    #     x509.PolicyMapping(
    #         issuer_domain_policy=ObjectIdentifier('1.2.3.4.7'),
    #         subject_domain_policy=ObjectIdentifier('1.2.3.4.8')
    #     )
    # ])

    policy_constraints = x509.PolicyConstraints(
        inhibit_policy_mapping=INHIBIT_POLICY_MAPPING,
        require_explicit_policy=REQUIRE_EXPLICIT_POLICY
    )


    # freshest_crl = x509.FreshestCRL()
    # CRLDistribution


    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(rsa_private_key.public_key())
        .serial_number(serial_number)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .add_extension(BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(key_usage, critical=True)
        .add_extension(san, critical=False)
        .add_extension(ian, critical=False)
        .add_extension(aki, critical=False)
        .add_extension(ski, critical=False)
        .add_extension(cp, critical=True)
        .add_extension(eku, critical=False)
        .add_extension(name_constraints, critical=True)
        .add_extension(aia, critical=False)
        .add_extension(sia, critical=False)
        .add_extension(iap, critical=False)
        # .add_extension(policy_mappings, critical=False)
        .add_extension(policy_constraints, critical=False)
        .sign(private_key=rsa_private_key, algorithm=hashes.SHA256())
    )
