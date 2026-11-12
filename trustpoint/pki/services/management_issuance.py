# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared issuance helpers for certificates signed through management CAs."""

from __future__ import annotations

import contextlib
import datetime as dt
from typing import TYPE_CHECKING, Any, get_args

from cryptography import x509
from django.core.exceptions import ValidationError
from django.db.models import Q
from trustpoint_core.crypto_types import AllowedCertSignHashAlgos
from trustpoint_core.oid import PublicKeyAlgorithmOid, SignatureSuite

from pki.key_types import KEY_TYPE_CHOICES
from pki.models import CaModel
from pki.services.external_csr import external_csr_profile
from pki.services.key_generation import supported_key_type_choices
from pki.util.cert_req_converter import JSONCertRequestConverter
from pki.util.x509 import _unwrap_mldsa_managed_key, validate_certificate_signing_private_key

if TYPE_CHECKING:
    from collections.abc import Sequence

    from django.db.models import QuerySet

    from pki.models.cert_profile import CertificateProfileModel


def available_management_cas() -> QuerySet[CaModel]:
    """Return active management CAs that can issue locally or forward to an external RA."""
    return (
        CaModel.objects.filter(ca_role=CaModel.CaRole.MANAGEMENT, is_active=True)
        .filter(
            Q(credential__certificate__isnull=False)
            | Q(
                ca_type__in=[CaModel.CaTypeChoice.REMOTE_EST_RA, CaModel.CaTypeChoice.REMOTE_CMP_RA],
                certificate__isnull=False,
            )
        )
        .select_related('credential__certificate', 'certificate')
        .order_by('unique_name')
    )


def key_type_for_management_ca(
    ca: CaModel,
    allowed_key_types: Sequence[tuple[str, str]] = KEY_TYPE_CHOICES,
) -> str:
    """Bind the requested key type to the selected management CA's public key."""
    public_key_info = ca.public_key_info
    if public_key_info is None:
        msg = 'The selected management CA has no public key information.'
        raise ValidationError(msg)
    algorithm = public_key_info.public_key_algorithm_oid
    if algorithm == PublicKeyAlgorithmOid.RSA:
        key_type = f'RSA-{public_key_info.key_size}'
    elif algorithm == PublicKeyAlgorithmOid.ECC and public_key_info.named_curve is not None:
        key_type = f'ECC-{public_key_info.named_curve.name}'
    elif algorithm == PublicKeyAlgorithmOid.ML_DSA_44:
        key_type = 'MLDSA-44'
    elif algorithm == PublicKeyAlgorithmOid.ML_DSA_65:
        key_type = 'MLDSA-65'
    elif algorithm == PublicKeyAlgorithmOid.ML_DSA_87:
        key_type = 'MLDSA-87'
    else:
        msg = 'The selected management CA key type cannot be used for this certificate.'
        raise ValidationError(msg)
    if key_type not in {value for value, _label in supported_key_type_choices(allowed_key_types)}:
        msg = 'The selected management CA key type cannot be used for this certificate.'
        raise ValidationError(msg)
    return key_type


def sign_certificate_request(
    csr: x509.CertificateSigningRequest,
    cert_profile: CertificateProfileModel,
    issuing_ca: CaModel,
) -> tuple[x509.Certificate, list[x509.Certificate]]:
    """Sign a CSR with a local management CA and return the leaf plus issuer chain."""
    if issuing_ca.credential is None:
        msg = 'Management CA has no credential.'
        raise ValueError(msg)
    ca_credential = issuing_ca.credential
    ca_cert = ca_credential.get_certificate()

    builder = x509.CertificateBuilder().subject_name(csr.subject).public_key(csr.public_key())
    for extension in csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)

    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(dt.datetime.now(dt.UTC) - dt.timedelta(hours=1))
    builder = builder.not_valid_after(
        dt.datetime.now(dt.UTC)
        + JSONCertRequestConverter.validity_period_from_json(cert_profile.profile.get('validity', {}))
    )

    with contextlib.suppress(ValueError):
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),  # type: ignore[arg-type]
            critical=False,
        )
    with contextlib.suppress(ValueError):
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)

    issuer_key = _unwrap_mldsa_managed_key(ca_credential.get_private_key())
    issuer_key = validate_certificate_signing_private_key(issuer_key)
    signature_suite = SignatureSuite.from_certificate(ca_cert)
    hash_algorithm_enum = signature_suite.algorithm_identifier.hash_algorithm
    hash_algorithm = None if hash_algorithm_enum is None else hash_algorithm_enum.hash_algorithm()
    if hash_algorithm is not None and not isinstance(hash_algorithm, get_args(AllowedCertSignHashAlgos)):
        msg = f'Unsupported CA signature hash algorithm: {type(hash_algorithm)}'
        raise TypeError(msg)
    leaf = builder.sign(private_key=issuer_key, algorithm=hash_algorithm)
    return leaf, [ca_cert, *ca_credential.get_certificate_chain()]


def external_ca_est_context_kwargs(
    ca: CaModel,
    cert_profile: CertificateProfileModel,
    *,
    allow_ca_certificate_request: bool,
    external_profile: bool = True,
) -> dict[str, Any]:
    """Build EST enrollment context arguments from a management CA acting as RA."""
    config = ca.no_onboarding_config
    if config is None or config.trust_store is None:
        msg = 'The external management CA has no enrollment truststore.'
        raise ValueError(msg)
    profile = external_csr_profile(cert_profile) if external_profile else cert_profile
    return {
        'operation': 'simpleenroll',
        'protocol': 'est',
        'domain': None,
        'cert_profile_str': profile.unique_name,
        'certificate_profile_model': profile,
        'allow_ca_certificate_request': allow_ca_certificate_request,
        'est_server_host': ca.remote_host,
        'est_server_port': ca.remote_port,
        'est_server_path': ca.remote_path,
        'est_username': ca.est_username,
        'est_password': config.est_password,
        'est_server_truststore': config.trust_store,
    }


def external_ca_cmp_context_kwargs(
    ca: CaModel,
    cert_profile: CertificateProfileModel,
    *,
    allow_ca_certificate_request: bool,
    external_profile: bool = True,
) -> dict[str, Any]:
    """Build CMP enrollment context arguments from a management CA acting as RA."""
    config = ca.no_onboarding_config
    if config is None or config.trust_store is None:
        msg = 'The external management CA has no enrollment truststore.'
        raise ValueError(msg)
    profile = external_csr_profile(cert_profile) if external_profile else cert_profile
    return {
        'operation': 'certification',
        'protocol': 'cmp',
        'domain': None,
        'cert_profile_str': profile.unique_name,
        'certificate_profile_model': profile,
        'allow_ca_certificate_request': allow_ca_certificate_request,
        'cmp_server_host': ca.remote_host,
        'cmp_server_port': ca.remote_port,
        'cmp_server_path': ca.remote_path,
        'cmp_shared_secret': config.cmp_shared_secret,
        'cmp_server_truststore': config.trust_store,
    }
