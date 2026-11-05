# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Cryptographic policy parity across live requests, certificates and stored CAs."""

from copy import deepcopy
from datetime import timedelta
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, padding, rsa
from cryptography.x509.oid import SignatureAlgorithmOID
from django.core.management import call_command
from django.utils import timezone
from trustpoint_core.oid import HashAlgorithm, NamedCurve, PublicKeyAlgorithmOid

from management.models import NotificationModel, SecurityConfig
from pki.authorization import PkiSecurityAuthorization
from pki.models import CaModel, CertificateModel, CredentialModel
from pki.security_policy import (
    CryptographicPolicy,
    CryptographicPolicyError,
    PolicyViolationCode,
    SignatureFacts,
    evaluate_cryptographic_policy,
    evaluate_signature,
    public_key_facts,
    signature_facts,
    stored_public_key_facts,
    stored_signature_facts,
)
from pki.util.x509 import CertificateVerifier
from request.authorization.base import SecurityConfigAuthorization
from request.request_context import BaseCertificateRequestContext

pytestmark = pytest.mark.django_db


@pytest.fixture(scope='module')
def policy_keys():
    """Reuse test keys while generating independent certificates and CSRs."""
    return {
        'rsa': rsa.generate_private_key(public_exponent=65537, key_size=2048),
        'ec256': ec.generate_private_key(ec.SECP256R1()),
        'ec384': ec.generate_private_key(ec.SECP384R1()),
        'mldsa44': mldsa.MLDSA44PrivateKey.generate(),
        'mldsa65': mldsa.MLDSA65PrivateKey.generate(),
        'mldsa87': mldsa.MLDSA87PrivateKey.generate(),
    }


def _material(key, *, pss=False, digest=None):
    """Sign a CA certificate and CSR with identical key/signature properties."""
    if digest is None and isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        digest = hashes.SHA256()
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'policy-parity')])
    now = timezone.now()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    )
    csr = x509.CertificateSigningRequestBuilder().subject_name(name)
    options = (
        {'rsa_padding': padding.PSS(mgf=padding.MGF1(digest), salt_length=padding.PSS.DIGEST_LENGTH)} if pss else {}
    )
    return certificate.sign(key, digest, **options), csr.sign(key, digest, **options)


def _config(**overrides):
    """Build a complete, permissive policy source without relying on active DB settings."""
    return SecurityConfig(
        security_mode=SecurityConfig.SecurityModeChoices.LAB,
        **{'rsa_minimum_key_size': 0, 'allow_self_signed_ca': True, 'allow_ca_issuance': True, **overrides},
    )


@pytest.mark.parametrize(
    ('kind', 'overrides', 'code'),
    [
        ('rsa', {'rsa_minimum_key_size': 0}, None),
        ('rsa', {'rsa_minimum_key_size': 2048}, None),
        ('rsa', {'rsa_minimum_key_size': 3072}, PolicyViolationCode.RSA_KEY_TOO_SMALL),
        ('rsa', {'rsa_minimum_key_size': None}, PolicyViolationCode.RSA_FORBIDDEN),
        ('ec256', {'not_permitted_ecc_curve_oids': []}, None),
        (
            'ec256',
            {'not_permitted_ecc_curve_oids': [NamedCurve.SECP256R1.dotted_string]},
            PolicyViolationCode.ECC_CURVE_BLOCKED,
        ),
        ('ec384', {'not_permitted_ecc_curve_oids': [NamedCurve.SECP256R1.dotted_string]}, None),
        (
            'mldsa44',
            {'not_permitted_mldsa_variant_oids': [PublicKeyAlgorithmOid.ML_DSA_44.dotted_string]},
            PolicyViolationCode.MLDSA_VARIANT_BLOCKED,
        ),
        (
            'mldsa65',
            {'not_permitted_mldsa_variant_oids': [PublicKeyAlgorithmOid.ML_DSA_65.dotted_string]},
            PolicyViolationCode.MLDSA_VARIANT_BLOCKED,
        ),
        (
            'mldsa87',
            {'not_permitted_mldsa_variant_oids': [PublicKeyAlgorithmOid.ML_DSA_87.dotted_string]},
            PolicyViolationCode.MLDSA_VARIANT_BLOCKED,
        ),
        ('mldsa65', {'not_permitted_mldsa_variant_oids': [PublicKeyAlgorithmOid.ML_DSA_44.dotted_string]}, None),
        (
            'rsa',
            {'not_permitted_signature_algorithm_oids': [HashAlgorithm.SHA256.dotted_string]},
            PolicyViolationCode.SIGNATURE_HASH_BLOCKED,
        ),
        (
            'ec256',
            {'not_permitted_signature_algorithm_oids': [HashAlgorithm.SHA256.dotted_string]},
            PolicyViolationCode.SIGNATURE_HASH_BLOCKED,
        ),
        ('mldsa44', {'not_permitted_signature_algorithm_oids': [HashAlgorithm.SHA256.dotted_string]}, None),
    ],
)
def test_live_and_stored_policy_decisions_agree(policy_keys, kind, overrides, code):
    """The same material has the same decision at every policy entry point."""
    certificate, csr = _material(policy_keys[kind])
    model = CertificateModel.save_certificate(certificate)
    config = _config(**overrides)
    policy = CryptographicPolicy.from_config(config)
    raw = evaluate_cryptographic_policy(policy, key=public_key_facts(csr.public_key()), signature=signature_facts(csr))
    stored = evaluate_cryptographic_policy(
        policy, key=stored_public_key_facts(model), signature=stored_signature_facts(model)
    )
    assert [failure.code for failure in raw] == [failure.code for failure in stored]
    assert [failure.code for failure in raw] == ([] if code is None else [code])

    target = SimpleNamespace(unique_name='policy-ca', ca_certificate_model=model, crl_validity_hours=24)
    context = BaseCertificateRequestContext(cert_requested=csr)
    checks = [
        lambda: SecurityConfigAuthorization().authorize(context),
        lambda: CertificateVerifier.verify_ca_cert(certificate, [certificate]),
        lambda: PkiSecurityAuthorization().check(target),
    ]
    with (
        patch('request.authorization.base.SecurityConfig.objects.get', return_value=config),
        patch('pki.util.x509.SecurityConfig.objects.first', return_value=config),
    ):
        for check in checks:
            if code is None:
                check()
            else:
                with pytest.raises(ValueError, match=raw[0].message):
                    check()

    credential = CredentialModel.objects.create(
        certificate=model,
        credential_type=CredentialModel.CredentialTypeChoice.ISSUING_CA,
    )
    CaModel.objects.create(
        unique_name='policy-ca', credential=credential, ca_type=CaModel.CaTypeChoice.LOCAL_UNPROTECTED
    )
    requested = deepcopy(SecurityConfig._MODE_DEFAULTS[SecurityConfig.SecurityModeChoices.LAB])
    requested.update(overrides)
    violations = config.check_policy_transition(requested, SecurityConfig.SecurityModeChoices.LAB)
    assert bool(violations) is (code is not None)
    if code is not None:
        assert raw[0].message in ' '.join(violations)


@pytest.mark.parametrize('kind', ['rsa', 'ec256'])
def test_explicit_signature_oid_restrictions_are_shared(policy_keys, kind):
    """An explicit signature OID blocks both live and persisted representations."""
    certificate, csr = _material(policy_keys[kind])
    model = CertificateModel.save_certificate(certificate)
    policy = CryptographicPolicy(blocked_signature_oids=frozenset([certificate.signature_algorithm_oid.dotted_string]))
    assert evaluate_signature(policy, signature_facts(csr))[0].code == PolicyViolationCode.SIGNATURE_BLOCKED
    assert evaluate_signature(policy, stored_signature_facts(model))[0].code == PolicyViolationCode.SIGNATURE_BLOCKED


def test_rsa_pss_uses_parameterized_digest_for_all_representations(policy_keys):
    """RSA-PSS's signature OID alone cannot identify its forbidden SHA-256 digest."""
    certificate, csr = _material(policy_keys['rsa'], pss=True)
    model = CertificateModel.save_certificate(certificate)
    policy = CryptographicPolicy(blocked_signature_oids=frozenset([HashAlgorithm.SHA256.dotted_string]))
    for facts in (signature_facts(certificate), signature_facts(csr), stored_signature_facts(model)):
        assert evaluate_signature(policy, facts)[0].code == PolicyViolationCode.SIGNATURE_HASH_BLOCKED


@pytest.mark.parametrize(
    'oid',
    [
        '1.2.840.113533.7.66.13',  # CMP password-based MAC is not a certificate signature.
        SignatureAlgorithmOID.RSASSA_PSS.dotted_string,  # PSS requires the digest from its parameters.
    ],
)
def test_incomplete_or_non_signature_algorithms_cannot_pass_policy(oid):
    """A recognized identifier alone is insufficient to evaluate a signature safely."""
    assert (
        evaluate_signature(CryptographicPolicy(), SignatureFacts(oid))[0].code == PolicyViolationCode.SIGNATURE_UNKNOWN
    )


def test_corrupted_pss_metadata_returns_a_structured_violation(policy_keys):
    """Unparseable PSS parameters become a policy failure rather than bypassing a transition."""
    certificate, _ = _material(policy_keys['rsa'], pss=True)
    model = CertificateModel.save_certificate(certificate)
    CertificateModel.objects.filter(pk=model.pk).update(cert_pem='corrupted certificate')
    model.refresh_from_db()
    assert (
        evaluate_signature(CryptographicPolicy(), stored_signature_facts(model))[0].code
        == PolicyViolationCode.SIGNATURE_UNKNOWN
    )


def test_sha3_hash_normalization_is_shared(policy_keys):
    """SHA-3 names and OIDs no longer bypass the request-only digest name table."""
    certificate, csr = _material(policy_keys['ec256'], digest=hashes.SHA3_256())
    model = CertificateModel.save_certificate(certificate)
    policy = CryptographicPolicy(blocked_signature_oids=frozenset([HashAlgorithm.SHA3_256.dotted_string]))
    assert evaluate_signature(policy, signature_facts(csr))[0].code == PolicyViolationCode.SIGNATURE_HASH_BLOCKED
    assert (
        evaluate_signature(policy, stored_signature_facts(model))[0].code == PolicyViolationCode.SIGNATURE_HASH_BLOCKED
    )


def test_snapshot_does_not_follow_later_config_mutations(policy_keys):
    """An operation keeps the policy it loaded even when mutable config lists change."""
    config = _config(not_permitted_ecc_curve_oids=[NamedCurve.SECP256R1.dotted_string])
    policy = CryptographicPolicy.from_config(config)
    config.not_permitted_ecc_curve_oids.clear()
    config.rsa_minimum_key_size = None
    assert evaluate_cryptographic_policy(policy, key=public_key_facts(policy_keys['ec256'].public_key()))
    assert not evaluate_cryptographic_policy(policy, key=public_key_facts(policy_keys['rsa'].public_key()))


def test_verification_reads_one_policy_snapshot(policy_keys):
    """All checks within certificate verification share one DB configuration read."""
    certificate, _ = _material(policy_keys['ec256'])
    with patch('pki.util.x509.SecurityConfig.objects.first', return_value=_config()) as lookup:
        CertificateVerifier.verify_ca_cert(certificate, [certificate])
    lookup.assert_called_once_with()


def test_unsigned_builder_checks_its_key_without_inventing_a_signature(policy_keys):
    """A builder has no digest to check yet, but its existing key still obeys policy."""
    component = SecurityConfigAuthorization()
    builder = x509.CertificateBuilder().public_key(policy_keys['ec256'].public_key())
    config = _config(not_permitted_signature_algorithm_oids=[HashAlgorithm.SHA256.dotted_string])
    component._check_key_constraints(builder, config)
    component._check_signature_algorithm(builder, config)
    config.not_permitted_ecc_curve_oids = [NamedCurve.SECP256R1.dotted_string]
    with pytest.raises(CryptographicPolicyError, match='ECC curve'):
        component._check_key_constraints(builder, config)


def test_unknown_signature_and_missing_curve_fail_consistently(policy_keys):
    """Uninterpretable stored material cannot silently pass transition checks."""
    certificate, _ = _material(policy_keys['ec256'])
    model = CertificateModel.save_certificate(certificate)
    CertificateModel.objects.filter(pk=model.pk).update(spki_ec_curve_oid='', signature_algorithm_oid='1.2.3.4.5')
    model.refresh_from_db()
    failures = evaluate_cryptographic_policy(
        CryptographicPolicy(),
        key=stored_public_key_facts(model),
        signature=stored_signature_facts(model),
    )
    assert {failure.code for failure in failures} == {
        PolicyViolationCode.ECC_CURVE_UNKNOWN,
        PolicyViolationCode.SIGNATURE_UNKNOWN,
    }
    assert evaluate_signature(CryptographicPolicy(), SignatureFacts('1.2.3.4.5'))


@pytest.mark.parametrize(
    ('kind', 'overrides', 'command', 'event'),
    [
        ('rsa', {'rsa_minimum_key_size': 3072}, 'check_for_insufficient_key_length', 'INSUFFICIENT_KEY_LENGTH'),
        ('rsa', {'rsa_minimum_key_size': None}, 'check_for_insufficient_key_length', 'INSUFFICIENT_KEY_LENGTH'),
        (
            'ec256',
            {'not_permitted_ecc_curve_oids': [NamedCurve.SECP256R1.dotted_string]},
            'check_for_not_permitted_ecc_curves',
            'WEAK_ECC_CURVE',
        ),
        (
            'ec256',
            {'not_permitted_signature_algorithm_oids': [HashAlgorithm.SHA256.dotted_string]},
            'check_for_not_permitted_signature_algorithms',
            'WEAK_SIGNATURE_ALGORITHM',
        ),
    ],
)
def test_notification_commands_follow_shared_policy_and_deduplicate(policy_keys, kind, overrides, command, event):
    """Notifications report the same violations and remain idempotent on later runs."""
    config = _config(**overrides)
    config.save()
    certificate, _ = _material(policy_keys[kind])
    model = CertificateModel.save_certificate(certificate)
    for _ in range(2):
        call_command(command, stdout=StringIO())
    assert NotificationModel.objects.filter(event=event, certificate=model).count() == 1
