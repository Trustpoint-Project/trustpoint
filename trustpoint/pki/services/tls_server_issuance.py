# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""TLS server certificate finalization and local Issuing CA issuance."""

from __future__ import annotations

import contextlib
import datetime as dt
from typing import TYPE_CHECKING, Any, get_args

from cryptography import x509
from django.db import transaction
from trustpoint_core.crypto_types import AllowedCertSignHashAlgos
from trustpoint_core.oid import SignatureSuite

from pki.models import CaModel, CredentialModel
from pki.models.certificate import CertificateModel
from pki.models.credential import CertificateChainOrderModel, PrimaryCredentialCertificate
from pki.services.external_csr import build_external_csr, certificate_matches_credential
from pki.util.cert_req_converter import JSONCertRequestConverter
from pki.util.certificate_path import validate_issued_certificate_path
from pki.util.x509 import _unwrap_mldsa_managed_key, validate_certificate_signing_private_key

if TYPE_CHECKING:
    from pki.models.cert_profile import CertificateProfileModel
    from pki.models.truststore import TruststoreModel

__all__ = ['finalize_tls_server_enrollment', 'issue_tls_server_local']


@transaction.atomic
def _attach_certificate(
    credential: CredentialModel,
    leaf: x509.Certificate,
    issuer_chain_leaf_first: list[x509.Certificate],
) -> None:
    """Attach an issued leaf and root-first issuer chain to a pending credential."""
    pending = CredentialModel.objects.select_for_update().get(pk=credential.pk)
    if pending.certificate_id is not None:
        msg = 'This credential already has a certificate.'
        raise ValueError(msg)
    if not certificate_matches_credential(leaf, pending):
        msg = 'The issued certificate does not match the pending key.'
        raise ValueError(msg)

    leaf_model = CertificateModel.save_certificate(leaf)
    pending.certificate = leaf_model
    pending.save(update_fields=['certificate'])
    PrimaryCredentialCertificate.objects.update_or_create(
        credential=pending,
        defaults={'certificate': leaf_model, 'is_primary': True},
    )
    # Chain entries are stored root-first, matching the existing external-CSR finalize.
    for order, issuer in enumerate(reversed(issuer_chain_leaf_first)):
        CertificateChainOrderModel.objects.create(
            credential=pending,
            certificate=CertificateModel.save_certificate(issuer),
            primary_certificate=leaf_model,
            order=order,
        )


def finalize_tls_server_enrollment(
    credential: CredentialModel,
    issued_cert: x509.Certificate,
    extra_certs: list[x509.Certificate],
    truststore: TruststoreModel,
) -> CredentialModel:
    """Validate the EST-issued certificate path and attach it to the pending credential."""
    anchors = [
        entry.certificate.get_certificate_serializer().as_crypto()
        for entry in truststore.truststoreordermodel_set.order_by('order')
    ]
    path = validate_issued_certificate_path(issued_cert, anchors, list(extra_certs))
    _attach_certificate(credential, issued_cert, path[1:])
    return credential


def issue_tls_server_local(
    credential: CredentialModel,
    cert_profile: CertificateProfileModel,
    content: dict[str, Any],
    issuing_ca: CaModel,
) -> CredentialModel:
    """Issue a TLS server credential from a local Issuing CA hosted in Trustpoint."""
    if issuing_ca.credential is None:
        msg = 'Issuing CA has no credential.'
        raise ValueError(msg)
    ca_credential = issuing_ca.credential
    ca_cert = ca_credential.get_certificate()

    csr = build_external_csr(credential, cert_profile, content, allow_ca=False)

    builder = x509.CertificateBuilder().subject_name(csr.subject).public_key(csr.public_key())
    for ext in csr.extensions:
        builder = builder.add_extension(ext.value, ext.critical)

    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(dt.datetime.now(dt.UTC) - dt.timedelta(hours=1))
    builder = builder.not_valid_after(
        dt.datetime.now(dt.UTC)
        + JSONCertRequestConverter.validity_period_from_json(cert_profile.profile.get('validity', {}))
    )

    with contextlib.suppress(ValueError):  # extension already present in CSR
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),  # type: ignore[arg-type]
            critical=False,
        )
    with contextlib.suppress(ValueError):  # extension already present in CSR
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

    _attach_certificate(credential, leaf, [ca_cert, *ca_credential.get_certificate_chain()])
    return credential
