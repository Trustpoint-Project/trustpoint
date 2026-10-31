# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Adversarial path-validation cases exercised through both RA validation entry points."""

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, rsa

from pki.util.certificate_path import validate_issued_certificate_path
from request.operation_processor.issue_cert import RemoteCaCertificateIssueProcessor
from request.security_hardening import _verify_chain_to_truststore


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _issue(
    key,
    issuer=None,
    issuer_key=None,
    *,
    name='certificate',
    ca=False,
    basic_constraints=True,
    path_length=None,
    key_usage=True,
    key_cert_sign=None,
    before=-1,
    after=30,
    san=None,
    eku=None,
    extensions=(),
):
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)]) if name else x509.Name([])
    issuer_key = issuer_key or key
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(days=before))
        .not_valid_after(now + timedelta(days=after))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    )
    if basic_constraints:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
    if key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca if key_cert_sign is None else key_cert_sign,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if san is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=not bool(name))
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    for value, critical in extensions:
        builder = builder.add_extension(value, critical=critical)
    digest = (
        None
        if isinstance(issuer_key, (mldsa.MLDSA44PrivateKey, mldsa.MLDSA65PrivateKey, mldsa.MLDSA87PrivateKey))
        else hashes.SHA256()
    )
    return builder.sign(issuer_key, digest)


@pytest.fixture
def root():
    key = _key()
    return key, _issue(key, name='trusted root', ca=True)


@pytest.fixture(params=['general-ra', 'cmp-ra'])
def verify_path(request):
    def verify(leaf, anchors, intermediates) -> None:
        if request.param == 'general-ra':
            _verify_chain_to_truststore(leaf, anchors, intermediates)
        else:
            RemoteCaCertificateIssueProcessor._validate_cmp_issued_certificate(
                leaf,
                intermediates,
                anchors,
                leaf.public_key(),
            )

    return verify


def test_valid_path_returns_issuer_order_and_ignores_unrelated_extra_certificates(root):
    root_key, anchor = root
    intermediate_key = _key()
    intermediate = _issue(intermediate_key, anchor, root_key, ca=True)
    leaf = _issue(_key(), intermediate, intermediate_key)
    unrelated = _issue(_key(), name='unrelated', ca=True)
    assert validate_issued_certificate_path(leaf, [anchor], [unrelated, intermediate]) == [leaf, intermediate, anchor]


@pytest.mark.parametrize('eku', [None, [x509.ExtendedKeyUsageOID.SERVER_AUTH], [x509.ExtendedKeyUsageOID.CLIENT_AUTH]])
def test_accepts_domain_server_and_client_credentials(root, verify_path, eku):
    key, anchor = root
    leaf = _issue(_key(), anchor, key, eku=eku)
    verify_path(leaf, [anchor], [])


def test_accepts_empty_subject_with_critical_san(root, verify_path):
    key, anchor = root
    leaf = _issue(_key(), anchor, key, name='', san=[x509.DNSName('device.example.test')])
    verify_path(leaf, [anchor], [])


@pytest.mark.parametrize(
    'options',
    [
        {'ca': False},
        {'ca': True, 'basic_constraints': False},
        {'ca': True, 'key_usage': False},
        {'ca': True, 'key_cert_sign': False},
        {'ca': True, 'before': -30, 'after': -1},
        {'ca': True, 'before': 1, 'after': 30},
    ],
)
def test_rejects_invalid_intermediate(root, verify_path, options):
    root_key, anchor = root
    intermediate_key = _key()
    intermediate = _issue(intermediate_key, anchor, root_key, **options)
    leaf = _issue(_key(), intermediate, intermediate_key)
    with pytest.raises(ValueError):
        verify_path(leaf, [anchor], [intermediate])


@pytest.mark.parametrize('before,after', [(-30, -1), (1, 30)])
def test_rejects_invalid_leaf_validity(root, verify_path, before, after):
    key, anchor = root
    leaf = _issue(_key(), anchor, key, before=before, after=after)
    with pytest.raises(ValueError):
        verify_path(leaf, [anchor], [])


def test_rejects_path_length_violation(root, verify_path):
    root_key, anchor = root
    first_key, second_key = _key(), _key()
    first = _issue(first_key, anchor, root_key, ca=True, path_length=0, name='first')
    second = _issue(second_key, first, first_key, ca=True, name='second')
    leaf = _issue(_key(), second, second_key)
    with pytest.raises(ValueError):
        verify_path(leaf, [anchor], [second, first])


def test_rejects_unsupported_directory_name_constraints(root, verify_path):
    root_key, anchor = root
    intermediate_key = _key()
    permitted_dn = x509.DirectoryName(x509.Name([x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, 'allowed')]))
    intermediate = _issue(
        intermediate_key, anchor, root_key, ca=True,
        extensions=[(x509.NameConstraints([permitted_dn], None), True)],
    )
    leaf = _issue(_key(), intermediate, intermediate_key)
    with pytest.raises(ValueError):
        verify_path(leaf, [anchor], [intermediate])


@pytest.mark.parametrize(
    'names,permitted,excluded,valid',
    [
        ([x509.DNSName('device.example.test')], [x509.DNSName('example.test')], None, True),
        ([x509.DNSName('device.invalid.test')], [x509.DNSName('example.test')], None, False),
        ([x509.DNSName('device.example.test')], None, [x509.DNSName('example.test')], False),
        ([x509.IPAddress(ip_address('192.0.2.10'))], [x509.IPAddress(ip_network('192.0.2.0/24'))], None, True),
        ([x509.IPAddress(ip_address('198.51.100.10'))], [x509.IPAddress(ip_network('192.0.2.0/24'))], None, False),
        (
            [x509.DNSName('device.example.test'), x509.DNSName('device.invalid.test')],
            [x509.DNSName('example.test')],
            None,
            False,
        ),
    ],
)
def test_enforces_name_constraints(root, verify_path, names, permitted, excluded, valid):
    root_key, anchor = root
    intermediate_key = _key()
    intermediate = _issue(
        intermediate_key,
        anchor,
        root_key,
        ca=True,
        extensions=[(x509.NameConstraints(permitted, excluded), True)],
    )
    leaf = _issue(_key(), intermediate, intermediate_key, san=names)
    if valid:
        verify_path(leaf, [anchor], [intermediate])
    else:
        with pytest.raises(ValueError):
            verify_path(leaf, [anchor], [intermediate])


@pytest.mark.parametrize('location', ['leaf', 'intermediate'])
def test_rejects_unknown_critical_extensions(root, verify_path, location):
    root_key, anchor = root
    intermediate_key = _key()
    unknown = [(x509.UnrecognizedExtension(x509.ObjectIdentifier('1.2.3.4.999'), b'\x05\x00'), True)]
    intermediate = _issue(
        intermediate_key,
        anchor,
        root_key,
        ca=True,
        extensions=unknown if location == 'intermediate' else [],
    )
    leaf = _issue(_key(), intermediate, intermediate_key, extensions=unknown if location == 'leaf' else [])
    with pytest.raises(ValueError):
        verify_path(leaf, [anchor], [intermediate])


@pytest.mark.parametrize('critical', [True, False])
def test_rejects_unsupported_certificate_policy_constraints(root, verify_path, critical):
    root_key, anchor = root
    intermediate_key = _key()
    intermediate = _issue(
        intermediate_key,
        anchor,
        root_key,
        ca=True,
        extensions=[(x509.PolicyConstraints(require_explicit_policy=0, inhibit_policy_mapping=None), critical)],
    )
    leaf = _issue(_key(), intermediate, intermediate_key)
    with pytest.raises(ValueError):
        verify_path(leaf, [anchor], [intermediate])


@pytest.mark.parametrize(
    'leaf_eku,valid',
    [
        ([x509.ExtendedKeyUsageOID.SERVER_AUTH], True),
        ([x509.ExtendedKeyUsageOID.CLIENT_AUTH], False),
        (None, False),
        ([x509.ExtendedKeyUsageOID.SERVER_AUTH, x509.ExtendedKeyUsageOID.CLIENT_AUTH], False),
    ],
)
def test_enforces_issuer_extended_key_usage(root, verify_path, leaf_eku, valid):
    root_key, anchor = root
    intermediate_key = _key()
    intermediate = _issue(intermediate_key, anchor, root_key, ca=True, eku=[x509.ExtendedKeyUsageOID.SERVER_AUTH])
    leaf = _issue(_key(), intermediate, intermediate_key, eku=leaf_eku)
    if valid:
        verify_path(leaf, [anchor], [intermediate])
    else:
        with pytest.raises(ValueError):
            verify_path(leaf, [anchor], [intermediate])


def test_untrusted_response_certificates_cannot_establish_trust(root, verify_path):
    _, anchor = root
    attacker_key = _key()
    attacker_root = _issue(attacker_key, ca=True)
    leaf = _issue(_key(), attacker_root, attacker_key)
    with pytest.raises(ValueError):
        verify_path(leaf, [anchor], [attacker_root])


def test_rejects_empty_truststore(root, verify_path):
    key, anchor = root
    leaf = _issue(_key(), anchor, key)
    with pytest.raises(ValueError):
        verify_path(leaf, [], [anchor])


def test_leaf_cannot_be_its_own_trust_anchor(root, verify_path):
    key, anchor = root
    leaf = _issue(_key(), anchor, key)
    with pytest.raises(ValueError):
        verify_path(leaf, [leaf], [anchor])


@pytest.mark.parametrize(
    'root_key',
    [
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        mldsa.MLDSA44PrivateKey.generate(),
        mldsa.MLDSA65PrivateKey.generate(),
        mldsa.MLDSA87PrivateKey.generate(),
    ],
)
def test_supports_rsa_and_mldsa_issuers(root_key, verify_path):
    anchor = _issue(root_key, ca=True)
    leaf = _issue(_key(), anchor, root_key)
    verify_path(leaf, [anchor], [])
