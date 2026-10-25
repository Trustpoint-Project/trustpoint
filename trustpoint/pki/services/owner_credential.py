# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared request configuration for remote owner-credential enrollment."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from cryptography import x509
from trustpoint_core.oid import KeyPairGenerator
from trustpoint_core.serializer import PrivateKeySerializer

from pki.models import OwnerCredentialModel, RemoteIssuedCredentialModel
from pki.models.certificate import CertificateModel
from pki.models.credential import CredentialModel, IDevIDReferenceModel, PrimaryCredentialCertificate
from pki.util.certificate_request import public_key_info_from_key_type
from request.clients import EstClient
from request.operation_processor.csr_build import ProfileAwareCsrBuilder
from request.operation_processor.csr_sign import EstDeviceCsrSignProcessor

if TYPE_CHECKING:
    import logging
    from collections.abc import Callable

    from pki.models.cert_profile import CertificateProfileModel
    from request.request_context import EstCertificateRequestContext


def build_owner_credential_est_context_kwargs(
    owner_credential: OwnerCredentialModel,
    cert_profile: CertificateProfileModel,
    *,
    translate: Callable[[str], str] = str,
) -> dict[str, Any]:
    """Build EST authentication and truststore arguments for basic auth or mTLS."""
    kwargs: dict[str, Any] = {
        'operation': 'simpleenroll',
        'protocol': 'est',
        'domain': None,
        'cert_profile_str': cert_profile.unique_name,
        'certificate_profile_model': cert_profile,
        'allow_ca_certificate_request': True,
        'est_server_host': owner_credential.remote_host,
        'est_server_port': owner_credential.remote_port,
        'est_server_path': owner_credential.remote_path,
    }
    is_onboarding = (
        owner_credential.owner_credential_type == OwnerCredentialModel.OwnerCredentialTypeChoice.REMOTE_EST_ONBOARDING
    )
    if is_onboarding:
        onboarding_config = owner_credential.onboarding_config
        kwargs['est_server_truststore'] = onboarding_config.trust_store if onboarding_config else None
        domain_cred_issued = owner_credential.domain_credential
        if domain_cred_issued is None or domain_cred_issued.credential is None:
            msg = translate(
                'No domain credential found for this owner credential. Please issue a domain credential first.'
            )
            raise ValueError(msg)
        dc = domain_cred_issued.credential
        if dc.certificate is None:
            msg = translate('The domain credential has no certificate. Please issue a domain credential first.')
            raise ValueError(msg)
        kwargs['est_client_cert_pem'] = dc.certificate.cert_pem
        kwargs['est_client_key_pem'] = dc.private_key
    else:
        no_onboarding = owner_credential.no_onboarding_config
        kwargs['est_username'] = owner_credential.est_username
        kwargs['est_password'] = no_onboarding.est_password if no_onboarding else None
        kwargs['est_server_truststore'] = no_onboarding.trust_store if no_onboarding else None
    return kwargs


def create_pending_owner_credential(
    owner_credential: OwnerCredentialModel,
    cert_profile: CertificateProfileModel,
    cred_type: RemoteIssuedCredentialModel.RemoteIssuedCredentialType,
    credential_model_type: CredentialModel.CredentialTypeChoice,
) -> RemoteIssuedCredentialModel:
    """Generate a fresh key pair and create a key-only RemoteIssuedCredentialModel."""
    key_type = owner_credential.key_type or 'ECC-SECP256R1'
    private_key = KeyPairGenerator.generate_key_pair_for_public_key_info(public_key_info_from_key_type(key_type))
    private_key_pem = PrivateKeySerializer(private_key).as_pkcs8_pem().decode()
    credential_model = CredentialModel.objects.create(
        credential_type=credential_model_type,
        private_key=private_key_pem,
        certificate=None,
    )
    return RemoteIssuedCredentialModel.objects.create(
        common_name=owner_credential.unique_name,
        issued_credential_type=cred_type,
        issued_using_cert_profile=cert_profile.unique_name,
        credential=credential_model,
        owner_credential=owner_credential,
    )


def build_domain_credential_est_context_kwargs(
    owner_credential: OwnerCredentialModel,
    cert_profile: CertificateProfileModel,
) -> dict[str, Any]:
    """Build basic-auth EST arguments for the domain-credential endpoint."""
    onboarding = owner_credential.onboarding_config
    return {
        'operation': 'simpleenroll',
        'protocol': 'est',
        'domain': None,
        'cert_profile_str': cert_profile.unique_name,
        'certificate_profile_model': cert_profile,
        'allow_ca_certificate_request': False,
        'est_server_host': owner_credential.remote_host,
        'est_server_port': owner_credential.remote_port,
        'est_server_path': owner_credential.remote_path_domain_credential,
        'est_username': owner_credential.est_username,
        'est_password': onboarding.est_password if onboarding else None,
        'est_server_truststore': onboarding.trust_store if onboarding else None,
    }


def enroll_owner_credential_est(
    context: EstCertificateRequestContext,
    owner_credential: OwnerCredentialModel,
    pending_issued: RemoteIssuedCredentialModel,
    *,
    logger: logging.Logger,
    domain_credential: bool = False,
) -> None:
    """Enroll with the pending key, then persist the certificate and role-specific metadata."""
    signing_credential = pending_issued.credential
    context.owner_credential = signing_credential
    csr_builder = ProfileAwareCsrBuilder()
    csr_builder.process_operation(context)
    csr = csr_builder.get_csr()
    context.cert_requested = csr

    csr_signer = EstDeviceCsrSignProcessor()
    csr_signer.process_operation(context)
    signed_csr = csr_signer.get_signed_csr()

    est_client = EstClient(context)
    issued_cert = est_client.simple_enroll(signed_csr)

    cert_model = CertificateModel.save_certificate(issued_cert)
    signing_credential.certificate = cert_model
    signing_credential.save()
    PrimaryCredentialCertificate.objects.get_or_create(
        credential=signing_credential,
        certificate=cert_model,
        defaults={'is_primary': True},
    )
    pending_issued.common_name = cert_model.common_name or owner_credential.unique_name
    if domain_credential:
        pending_issued.issued_using_cert_profile = cast('str', context.cert_profile_str)
        pending_issued.save(update_fields=['common_name', 'issued_using_cert_profile'])
        return
    pending_issued.save(update_fields=['common_name'])

    try:
        san_ext = issued_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for san in san_ext.value:
            if isinstance(san, x509.UniformResourceIdentifier) and san.value.startswith('dev-owner:'):
                IDevIDReferenceModel.objects.get_or_create(
                    dev_owner_id=owner_credential,
                    idevid_ref=san.value,
                    defaults={'dev_owner_id_certificate': cert_model},
                )
    except x509.ExtensionNotFound:
        logger.warning(
            'Issued DevOwnerID certificate for "%s" has no SAN; no IDevID refs stored.',
            owner_credential.unique_name,
        )
