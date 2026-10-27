# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Profile-based renewal of the local GDS Push client identity."""

from cryptography import x509
from django.db import transaction

from devices.models import DeviceModel
from pki.models import IssuedCredentialModel
from pki.models.certificate import RevokedCertificateModel
from pki.services.revocation import revoke_primary_certificate
from request.authorization.manual import ManualAuthorization
from request.operation_processor import CredentialIssueProcessor
from request.request_context import ManualCredentialRequestContext, ManualIssuanceMethod


@transaction.atomic
def renew_gds_push_domain_credential(device: DeviceModel) -> IssuedCredentialModel:
    """Issue a replacement before revoking the old identity; roll back both on failure."""
    if device.device_type != DeviceModel.DeviceType.OPC_UA_GDS_PUSH or device.domain is None:
        message = 'Domain credential renewal requires an OPC UA GDS Push device with a domain.'
        raise ValueError(message)
    previous = (
        IssuedCredentialModel.objects.filter(
            device=device,
            domain=device.domain,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
            credential__certificate__isnull=False,
            credential__certificate__revoked_certificate__isnull=True,
        )
        .order_by('-created_at', '-pk')
        .first()
    )
    if previous is None:
        message = 'Issue an initial domain credential before enabling periodic renewal.'
        raise ValueError(message)

    certificate = previous.credential.get_certificate()
    builder = x509.CertificateBuilder().subject_name(certificate.subject)
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        pass
    else:
        builder = builder.add_extension(san.value, critical=san.critical)
    profile = device.domain.get_domain_credential_profile()
    context = ManualCredentialRequestContext(
        device=device,
        domain=device.domain,
        cert_profile_str=profile.unique_name,
        manual_issuance_method=ManualIssuanceMethod.TRUSTPOINT_GENERATED,
        cert_requested=builder,
    )
    ManualAuthorization().authorize(context)
    CredentialIssueProcessor().process_operation(context)
    replacement = context.issued_credential
    if replacement is None or not replacement.is_valid_domain_credential()[0]:
        message = 'Domain credential renewal did not produce a valid replacement.'
        raise ValueError(message)
    revoked, reason = revoke_primary_certificate(
        previous.pk,
        RevokedCertificateModel.ReasonCode.SUPERSEDED,
    )
    if not revoked:
        raise ValueError(reason)
    return replacement
