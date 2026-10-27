# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Create fixture credentials through the application's profile-based issuance pipeline."""

import copy
import json
from pathlib import Path
from typing import Any

from cryptography import x509
from trustpoint_core.crypto_types import PublicKey

from devices.models import DeviceModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.issued_credential import IssuedCredentialModel
from request.operation_processor.issue_cert import CertificateIssueProcessor
from request.operation_processor.issue_cred import CredentialIssueProcessor
from request.profile_validator import ProfileValidator
from request.request_context import ManualCredentialRequestContext


def issue_test_credential(  # noqa: PLR0913 - Test requests can supply either key material or profile-specific content.
    device: DeviceModel,
    profile_name: str,
    *,
    common_name: str | None = None,
    public_key: PublicKey | None = None,
    extensions: list[tuple[x509.ExtensionType, bool]] | None = None,
    profile_data: dict[str, Any] | None = None,
) -> IssuedCredentialModel:
    """Issue using a default profile (or an explicit test policy), preserving external public keys.

    This fixture helper applies profile policy and runs the real issuance processors.
    Authentication, authorization, and protocol completion belong to the test's caller.
    """
    domain = device.domain
    if domain is None:
        msg = 'A device domain is required for fixture issuance.'
        raise ValueError(msg)

    definition = copy.deepcopy(profile_data)
    if definition is None:
        profile_path = Path(__file__).resolve().parents[1] / 'default_certificate_profiles' / f'{profile_name}.json'
        definition = json.loads(profile_path.read_text())
    # Fixture issuance has no HTTPS installation; keep the profile's CRL URL deterministic.
    crl_urls = definition.get('ext', {}).get('crl_distribution_points', {}).get('uris', {})
    if isinstance(crl_urls, dict) and isinstance(crl_urls.get('value'), list):
        crl_urls['value'] = [url.replace('{tls_certificate.ip_address.1}', '127.0.0.1') for url in crl_urls['value']]
    profile, _ = CertificateProfileModel.objects.get_or_create(
        unique_name=profile_name,
        defaults={
            'profile_json': definition,
            'display_name': definition.get('display_name', profile_name),
            'credential_type': definition.get('credential_type', 'application'),
        },
    )
    if profile_data is not None:
        profile.profile_json = definition
        profile.save(update_fields=['profile_json'])

    subject = [
        x509.NameAttribute(x509.NameOID.DOMAIN_COMPONENT, domain.unique_name),
        x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, device.serial_number),
        x509.NameAttribute(x509.NameOID.USER_ID, str(device.pk)),
    ]
    if common_name is not None:
        subject.insert(0, x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name))
    builder = x509.CertificateBuilder().subject_name(x509.Name(subject))
    if public_key is not None:
        builder = builder.public_key(public_key)
    for extension, critical in extensions or []:
        builder = builder.add_extension(extension, critical)

    context = ManualCredentialRequestContext(
        device=device,
        domain=domain,
        cert_profile_str=profile_name,
        certificate_profile_model=profile,
        cert_requested=builder,
    )
    ProfileValidator.validate(context)
    if public_key is None:
        CredentialIssueProcessor().process_operation(context)
    else:
        CertificateIssueProcessor().process_operation(context)
    if context.issued_credential is None:
        msg = 'The issuance pipeline did not return a fixture credential.'
        raise ValueError(msg)
    return context.issued_credential
