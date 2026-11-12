# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared request configuration for DevOwnerID enrollment."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from cryptography import x509
from trustpoint_core.oid import KeyPairGenerator
from trustpoint_core.serializer import PrivateKeySerializer

from pki.models import CaModel, RemoteIssuedCredentialModel
from pki.models.certificate import CertificateModel
from pki.models.credential import (
    CertificateChainOrderModel,
    CredentialModel,
    IDevIDReferenceModel,
    PrimaryCredentialCertificate,
)
from pki.services.cmp_enrollment import enroll_cmp
from pki.services.est_enrollment import enroll_est
from pki.services.external_csr import build_external_csr, certificate_matches_credential
from pki.services.management_issuance import (
    external_ca_cmp_context_kwargs,
    external_ca_est_context_kwargs,
    key_type_for_management_ca,
    sign_certificate_request,
)
from pki.util.certificate_request import build_request_data, public_key_info_from_key_type

if TYPE_CHECKING:
    import logging

    from pki.models.cert_profile import CertificateProfileModel
    from request.request_context import CmpCertificateRequestContext, EstCertificateRequestContext


def create_pending_dev_owner_id(management_ca: CaModel) -> RemoteIssuedCredentialModel:
    """Generate a fresh key pair and a key-only DevOwnerID credential for a management CA."""
    key_type = key_type_for_management_ca(management_ca)
    private_key = KeyPairGenerator.generate_key_pair_for_public_key_info(public_key_info_from_key_type(key_type))
    private_key_pem = PrivateKeySerializer(private_key).as_pkcs8_pem().decode()
    credential_model = CredentialModel.objects.create(
        credential_type=CredentialModel.CredentialTypeChoice.DEV_OWNER_ID,
        private_key=private_key_pem,
        certificate=None,
    )
    return RemoteIssuedCredentialModel.objects.create(
        common_name='',
        issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
        certificate_profile=None,
        credential=credential_model,
        ca=management_ca,
    )


def _persist_owner_credential_enrollment(
    context: Any,
    pending_issued: RemoteIssuedCredentialModel,
    issued_cert: x509.Certificate,
    *,
    logger: logging.Logger,
    domain_credential: bool,
) -> None:
    """Validate the issued certificate against the pending key and persist it with role metadata."""
    signing_credential = pending_issued.credential
    if not certificate_matches_credential(issued_cert, signing_credential):
        msg = 'The upstream certificate does not match the pending key.'
        raise ValueError(msg)
    try:
        is_ca = issued_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    csr = context.cert_requested
    if not isinstance(csr, x509.CertificateSigningRequest):
        msg = 'Enrollment did not produce a CSR request.'
        raise TypeError(msg)
    requested_ca = any(isinstance(ext.value, x509.BasicConstraints) and ext.value.ca for ext in csr.extensions)
    if is_ca != requested_ca:
        msg = 'The upstream certificate CA role does not match the request.'
        raise ValueError(msg)

    cert_model = CertificateModel.save_certificate(issued_cert)
    signing_credential.certificate = cert_model
    signing_credential.save()
    PrimaryCredentialCertificate.objects.get_or_create(
        credential=signing_credential,
        certificate=cert_model,
        defaults={'is_primary': True},
    )
    pending_issued.common_name = cert_model.common_name or pending_issued.common_name
    pending_issued.certificate_profile = context.certificate_profile_model
    pending_issued.save(update_fields=['common_name', 'certificate_profile'])
    if domain_credential:
        return

    try:
        san_ext = issued_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for san in san_ext.value:
            if isinstance(san, x509.UniformResourceIdentifier) and san.value.startswith('dev-owner:'):
                IDevIDReferenceModel.objects.get_or_create(
                    dev_owner_id=pending_issued,
                    idevid_ref=san.value,
                    defaults={'dev_owner_id_certificate': cert_model},
                )
    except x509.ExtensionNotFound:
        logger.warning(
            'Issued DevOwnerID certificate for "%s" has no SAN; no IDevID refs stored.',
            pending_issued.common_name,
        )


def enroll_owner_credential_est(
    context: EstCertificateRequestContext,
    pending_issued: RemoteIssuedCredentialModel,
    *,
    logger: logging.Logger,
    domain_credential: bool = False,
) -> None:
    """Enroll with the pending key via EST, then persist the certificate."""
    if context.certificate_profile_model is None:
        msg = 'A certificate profile is required for owner credential enrollment.'
        raise ValueError(msg)
    context.owner_credential = pending_issued.credential
    issued_cert, _ = enroll_est(context)
    _persist_owner_credential_enrollment(
        context, pending_issued, issued_cert, logger=logger, domain_credential=domain_credential
    )


def enroll_owner_credential_cmp(
    context: CmpCertificateRequestContext,
    pending_issued: RemoteIssuedCredentialModel,
    *,
    logger: logging.Logger,
    sender_kid: int | None = None,
) -> None:
    """Enroll with the pending key via CMP, then persist the certificate."""
    if context.certificate_profile_model is None:
        msg = 'A certificate profile is required for owner credential enrollment.'
        raise ValueError(msg)
    context.owner_credential = pending_issued.credential
    issued_cert, _ = enroll_cmp(context, sender_kid=sender_kid)
    _persist_owner_credential_enrollment(context, pending_issued, issued_cert, logger=logger, domain_credential=False)


def persist_owner_credential_certificate(  # noqa: PLR0913
    pending_issued: RemoteIssuedCredentialModel,
    cert_profile: CertificateProfileModel,
    csr: x509.CertificateSigningRequest,
    issued_cert: x509.Certificate,
    chain: list[x509.Certificate],
    *,
    logger: logging.Logger,
) -> None:
    """Persist an externally issued DevOwnerID certificate for a pending key."""
    context = SimpleNamespace(cert_requested=csr, certificate_profile_model=cert_profile)
    _persist_owner_credential_enrollment(
        context,
        pending_issued,
        issued_cert,
        logger=logger,
        domain_credential=False,
    )
    if chain and pending_issued.credential is not None and pending_issued.credential.certificate is not None:
        issuers = [cert for cert in chain if cert != issued_cert]
        for order, issuer in enumerate(reversed(issuers)):
            CertificateChainOrderModel.objects.create(
                credential=pending_issued.credential,
                certificate=CertificateModel.save_certificate(issuer),
                primary_certificate=pending_issued.credential.certificate,
                order=order,
            )


def issue_owner_credential_from_management_ca(
    pending_issued: RemoteIssuedCredentialModel,
    cert_profile: CertificateProfileModel,
    content: dict[str, Any],
    ca: CaModel,
    *,
    logger: logging.Logger,
) -> None:
    """Issue a DevOwnerID locally or request it from an external management CA."""
    if ca.is_issuing_ca:
        csr = build_external_csr(pending_issued.credential, cert_profile, content, allow_ca=True)
        issued_cert, _chain = sign_certificate_request(csr, cert_profile, ca)
        local_context = SimpleNamespace(cert_requested=csr, certificate_profile_model=cert_profile)
        _persist_owner_credential_enrollment(
            local_context,
            pending_issued,
            issued_cert,
            logger=logger,
            domain_credential=False,
        )
        return

    if ca.ca_type == CaModel.CaTypeChoice.REMOTE_EST_RA:
        from request.request_context import EstCertificateRequestContext  # noqa: PLC0415

        est_context = EstCertificateRequestContext(
            **external_ca_est_context_kwargs(
                ca,
                cert_profile,
                allow_ca_certificate_request=True,
                external_profile=False,
            )
        )
        est_context.request_data = build_request_data(content)
        enroll_owner_credential_est(est_context, pending_issued, logger=logger)
        return

    if ca.ca_type == CaModel.CaTypeChoice.REMOTE_CMP_RA:
        from request.request_context import CmpCertificateRequestContext  # noqa: PLC0415

        cmp_context = CmpCertificateRequestContext(
            **external_ca_cmp_context_kwargs(
                ca,
                cert_profile,
                allow_ca_certificate_request=True,
                external_profile=False,
            )
        )
        cmp_context.request_data = build_request_data(content)
        enroll_owner_credential_cmp(
            cmp_context,
            pending_issued,
            logger=logger,
            sender_kid=ca.cmp_sender_kid,
        )
        return

    msg = f'Management CA type {ca.get_ca_type_display()} cannot issue DevOwnerID certificates.'
    raise ValueError(msg)
