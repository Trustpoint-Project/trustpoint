# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared request configuration for remote owner-credential enrollment."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pki.models import OwnerCredentialModel

if TYPE_CHECKING:
    from collections.abc import Callable

    from pki.models.cert_profile import CertificateProfileModel


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
