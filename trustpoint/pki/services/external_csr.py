# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared operations for externally issued certificate requests."""

from copy import copy, deepcopy
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from django.core.exceptions import ValidationError
from django.db import transaction
from django.http import HttpResponse

from pki.models import CredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.certificate import CertificateModel
from pki.models.credential import CertificateChainOrderModel, PrimaryCredentialCertificate
from pki.util.cert_profile import alias_map
from pki.util.certificate_request import build_request_data
from request.operation_processor.csr_build import ProfileAwareCsrBuilder
from request.request_context import CmpCertificateRequestContext


def certificate_matches_credential(certificate: x509.Certificate, credential: CredentialModel) -> bool:
    """Compare the certificate's public key with the existing managed key."""
    expected = credential.get_private_key().public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    actual = certificate.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return actual == expected


def parse_single_certificate(data: bytes) -> x509.Certificate:
    """Accept exactly one PEM or DER certificate, never a bundle or container."""
    if not data or len(data) > 64 * 1024:
        msg = 'Upload one certificate, at most 64 KiB.'
        raise ValidationError(msg)
    try:
        if data.lstrip().startswith(b'-----BEGIN'):
            certificate = x509.load_pem_x509_certificate(data)
            if data.strip() != certificate.public_bytes(Encoding.PEM).strip():
                msg = 'Upload only the issued leaf certificate, not a bundle.'
                raise ValidationError(msg)
        else:
            certificate = x509.load_der_x509_certificate(data)
            if data != certificate.public_bytes(Encoding.DER):
                msg = 'Upload only the issued leaf certificate.'
                raise ValidationError(msg)
    except ValueError as exception:
        msg = 'Unable to parse the issued certificate.'
        raise ValidationError(msg) from exception
    return certificate


def request_data_from_content(content: dict[str, Any]) -> dict[str, Any]:
    """Convert external CSR content, retaining string coercion and empty SAN lists."""
    return build_request_data(content, stringify_san_items=True, keep_empty_sans=True)


def external_csr_profile(profile: CertificateProfileModel) -> CertificateProfileModel:
    """Use an isolated profile without CRL settings owned by the external issuer."""
    definition = deepcopy(profile.profile)
    for field in ('ext', 'extensions'):
        extensions = definition.get(field)
        if isinstance(extensions, dict):
            for name in list(extensions):
                if alias_map.get(name, name) == 'crl_distribution_points':
                    del extensions[name]
    external_profile = copy(profile)
    external_profile.profile_json = definition
    return external_profile


def build_external_csr(
    credential: CredentialModel, profile: CertificateProfileModel, content: dict[str, Any], *, allow_ca: bool = False,
) -> x509.CertificateSigningRequest:
    """Build a profile-aware CSR using the existing credential's managed key."""
    context = CmpCertificateRequestContext(
        operation='certification', protocol='cmp', domain=None,
        cert_profile_str=profile.unique_name, certificate_profile_model=external_csr_profile(profile),
        allow_ca_certificate_request=allow_ca,
    )
    context.request_data = request_data_from_content(content)
    context.owner_credential = credential
    builder = ProfileAwareCsrBuilder()
    builder.process_operation(context)
    return builder.get_csr()


def csr_download_response(csr: x509.CertificateSigningRequest, filename: str) -> HttpResponse:
    """Return the CSR as a PEM attachment."""
    response = HttpResponse(csr.public_bytes(Encoding.PEM), content_type='application/pkcs10')
    response['Content-Disposition'] = f'attachment; filename="{filename}.csr"'
    return response


@transaction.atomic
def finalize_external_certificate(
    credential: CredentialModel, certificate: x509.Certificate, chain: list[x509.Certificate] | None = None,
) -> None:
    """Attach a leaf and root-first issuer chain without replacing the pending key."""
    pending = CredentialModel.objects.select_for_update().get(pk=credential.pk)
    if pending.certificate_id is not None:
        msg = 'This credential already has a certificate.'
        raise ValidationError(msg)
    if not certificate_matches_credential(certificate, pending):
        msg = 'The issued certificate does not match the pending key.'
        raise ValidationError(msg)
    leaf = CertificateModel.save_certificate(certificate)
    pending.certificate = leaf
    pending.save(update_fields=['certificate'])
    PrimaryCredentialCertificate.objects.update_or_create(
        credential=pending, defaults={'certificate': leaf, 'is_primary': True},
    )
    for order, issuer in enumerate(reversed((chain or [certificate])[1:])):
        CertificateChainOrderModel.objects.create(
            credential=pending, certificate=CertificateModel.save_certificate(issuer),
            primary_certificate=leaf, order=order,
        )
