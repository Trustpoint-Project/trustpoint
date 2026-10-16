# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Configuration services of the SCEP server: enabling a domain and provisioning the dedicated server credential."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from django.db import transaction
from trustpoint_core.oid import SignatureSuite
from trustpoint_core.serializer import CredentialSerializer

from onboarding.enums import NoOnboardingPkiProtocol
from pki.models import CaModel
from pki.models.credential import CredentialModel
from pki.util.x509 import _unwrap_mldsa_managed_key, validate_certificate_signing_private_key
from scep.models import ScepServerConfigModel

if TYPE_CHECKING:
    from cryptography.hazmat.primitives import hashes

    from pki.models import DomainModel

SERVER_KEY_BITS = 2048
SERVER_CERT_VALIDITY = datetime.timedelta(days=3 * 365)
SERVER_CERT_RENEW_BEFORE = datetime.timedelta(days=30)

LOCAL_CA_TYPES = frozenset(
    {
        CaModel.CaTypeChoice.AUTOGEN_ROOT,
        CaModel.CaTypeChoice.AUTOGEN,
        CaModel.CaTypeChoice.LOCAL_UNPROTECTED,
        CaModel.CaTypeChoice.LOCAL_PKCS11,
    }
)


class ScepConfigurationError(Exception):
    """SCEP cannot be enabled or served for the domain."""


def get_local_issuing_ca(domain: DomainModel) -> CaModel:
    """Return the domain's issuing CA; SCEP only issues through locally managed CAs."""
    ca = domain.issuing_ca
    if ca is None:
        msg = 'The domain has no issuing CA.'
        raise ScepConfigurationError(msg)
    if ca.ca_type not in LOCAL_CA_TYPES:
        msg = 'SCEP is only supported for locally managed issuing CAs.'
        raise ScepConfigurationError(msg)
    if ca.get_credential() is None:
        msg = 'The issuing CA has no credential.'
        raise ScepConfigurationError(msg)
    return ca


def _issue_server_certificate(domain: DomainModel, public_key: rsa.RSAPublicKey) -> x509.Certificate:
    """Sign the SCEP server certificate (digitalSignature + keyEncipherment) with the domain CA."""
    ca = get_local_issuing_ca(domain)
    issuing_credential = ca.get_credential()
    if issuing_credential is None:
        msg = 'The issuing CA has no credential.'
        raise ScepConfigurationError(msg)
    issuer_cert = issuing_credential.get_certificate()
    suite = SignatureSuite.from_certificate(issuer_cert)
    hash_enum = suite.algorithm_identifier.hash_algorithm
    hash_algorithm: hashes.HashAlgorithm | None = hash_enum.hash_algorithm() if hash_enum is not None else None

    now = datetime.datetime.now(datetime.UTC)
    not_after = min(now + SERVER_CERT_VALIDITY, issuer_cert.not_valid_after_utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [x509.NameAttribute(x509.NameOID.COMMON_NAME, f'Trustpoint SCEP Server ({domain.unique_name})')]
            )
        )
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),  # type: ignore[arg-type]
            critical=False,
        )
    )
    signing_key = validate_certificate_signing_private_key(
        _unwrap_mldsa_managed_key(issuing_credential.get_private_key())
    )
    return builder.sign(private_key=signing_key, algorithm=hash_algorithm)  # type: ignore[arg-type]


def provision_server_credential(domain: DomainModel) -> CredentialModel:
    """Generate a new dedicated RSA server credential for the domain and store it."""
    ca = get_local_issuing_ca(domain)
    issuing_credential = ca.get_credential()
    if issuing_credential is None:
        msg = 'The issuing CA has no credential.'
        raise ScepConfigurationError(msg)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=SERVER_KEY_BITS)
    certificate = _issue_server_certificate(domain, private_key.public_key())
    serializer = CredentialSerializer(
        private_key=private_key,
        certificate=certificate,
        additional_certificates=[issuing_credential.get_certificate(), *issuing_credential.get_certificate_chain()],
    )
    return CredentialModel.save_credential_serializer(serializer, CredentialModel.CredentialTypeChoice.SCEP_SERVER)


def server_credential_is_usable(config: ScepServerConfigModel) -> bool:
    """Check whether the SCEP server credential is still usable."""
    credential = config.server_credential

    if credential is None or credential.certificate is None:
        return False

    cert = credential.get_certificate()

    if cert.not_valid_after_utc - datetime.datetime.now(datetime.UTC) < SERVER_CERT_RENEW_BEFORE:
        return False

    issuing_credential = get_local_issuing_ca(config.domain).get_credential()

    return (
        issuing_credential is not None
        and cert.issuer == issuing_credential.get_certificate().subject
    )


def scep_permitted_by_security_config() -> bool:
    """SCEP is enabled like the other protocols: through the SecurityConfig allow-list."""
    from management.models import SecurityConfig  # noqa: PLC0415

    cfg = SecurityConfig.objects.first()
    if cfg is None:
        return True
    return NoOnboardingPkiProtocol.SCEP.value in (cfg.permitted_no_onboarding_pki_protocols or [])




def ensure_server_credential(domain: DomainModel) -> CredentialModel:
    """Return the SCEP server credential, provisioning it when missing or expiring."""
    from pki.models import DomainModel as DomainModelCls  # noqa: PLC0415

    get_local_issuing_ca(domain)

    with transaction.atomic():
        locked_domain = (
            DomainModelCls.objects
            .select_for_update()
            .get(pk=domain.pk)
        )

        config, _ = ScepServerConfigModel.objects.get_or_create(
            domain=locked_domain,
        )

        if not server_credential_is_usable(config):
            config.server_credential = provision_server_credential(locked_domain)
            config.save(update_fields=['server_credential'])

        credential = config.server_credential

    if credential is None:
        msg = 'Failed to provision SCEP server credential.'
        raise ScepConfigurationError(msg)

    return credential


def get_serving_credential(domain: DomainModel) -> CredentialModel | None:
    """Return the server credential if the SecurityConfig permits SCEP and the domain can serve it."""
    if not domain.is_active or not scep_permitted_by_security_config():
        return None
    if domain.issuing_ca is None or domain.issuing_ca.ca_type not in LOCAL_CA_TYPES:
        return None
    try:
        return ensure_server_credential(domain)
    except ScepConfigurationError:
        return None
