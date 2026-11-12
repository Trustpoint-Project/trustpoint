# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""TLS server certificate finalization and local Issuing CA issuance."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.db import transaction

from pki.models import CaModel, CredentialModel
from pki.models.certificate import CertificateModel
from pki.models.credential import CertificateChainOrderModel, PrimaryCredentialCertificate
from pki.services.cmp_enrollment import enroll_cmp
from pki.services.est_enrollment import enroll_est
from pki.services.external_csr import build_external_csr, certificate_matches_credential
from pki.services.management_issuance import (
    external_ca_cmp_context_kwargs,
    external_ca_est_context_kwargs,
    sign_certificate_request,
)
from pki.util.certificate_path import validate_issued_certificate_path
from pki.util.certificate_request import build_request_data
from request.request_context import CmpCertificateRequestContext, EstCertificateRequestContext

if TYPE_CHECKING:
    from cryptography import x509

    from pki.models.cert_profile import CertificateProfileModel
    from pki.models.truststore import TruststoreModel

__all__ = ['finalize_tls_server_enrollment', 'issue_tls_server_local', 'issue_tls_server_remote']


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
    """Issue a TLS server credential from a local management CA hosted in Trustpoint."""
    csr = build_external_csr(credential, cert_profile, content, allow_ca=False)
    leaf, issuer_chain = sign_certificate_request(csr, cert_profile, issuing_ca)
    _attach_certificate(credential, leaf, issuer_chain)
    return credential


def issue_tls_server_remote(
    credential: CredentialModel,
    cert_profile: CertificateProfileModel,
    content: dict[str, Any],
    ca: CaModel,
) -> CredentialModel:
    """Request a TLS server certificate from an external management CA acting as RA."""
    config = ca.no_onboarding_config
    if config is None or config.trust_store is None:
        msg = 'The external management CA has no enrollment truststore.'
        raise ValueError(msg)
    anchors = ca.chain_truststore or config.trust_store
    request_data = build_request_data(content, keep_empty_sans=True)

    if ca.ca_type == CaModel.CaTypeChoice.REMOTE_EST_RA:
        est_context = EstCertificateRequestContext(
            **external_ca_est_context_kwargs(ca, cert_profile, allow_ca_certificate_request=False)
        )
        est_context.request_data = request_data
        est_context.owner_credential = credential
        issued_cert, extra_certs = enroll_est(est_context)
    elif ca.ca_type == CaModel.CaTypeChoice.REMOTE_CMP_RA:
        cmp_context = CmpCertificateRequestContext(
            **external_ca_cmp_context_kwargs(ca, cert_profile, allow_ca_certificate_request=False)
        )
        cmp_context.request_data = request_data
        cmp_context.owner_credential = credential
        issued_cert, extra_certs = enroll_cmp(cmp_context, sender_kid=ca.cmp_sender_kid)
    else:
        msg = f'Management CA type {ca.get_ca_type_display()} cannot issue TLS certificates.'
        raise ValueError(msg)

    return finalize_tls_server_enrollment(credential, issued_cert, list(extra_certs), anchors)
