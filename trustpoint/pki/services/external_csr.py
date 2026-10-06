"""Shared operations for externally issued certificate requests."""

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
    """Convert the flat certificate-content form values into profile request data."""
    subject_fields = (
        'common_name', 'organization_name', 'organizational_unit_name', 'country_name',
        'state_or_province_name', 'locality_name', 'email_address',
    )
    san_fields = ('dns_names', 'ip_addresses', 'rfc822_names', 'uris')
    return {
        'subj': {field: content[field] for field in subject_fields if content.get(field)},
        'ext': {'subject_alternative_name': {
            field: (
                [str(value).strip() for value in content[field] if str(value).strip()]
                if isinstance(content[field], list)
                else [value.strip() for value in str(content[field]).split(',') if value.strip()]
            ) for field in san_fields if content.get(field)
        }},
        'validity': {
            field: int(content[field]) for field in ('days', 'hours', 'minutes', 'seconds')
            if content.get(field) is not None
        },
    }


def build_external_csr(
    credential: CredentialModel, profile: CertificateProfileModel, content: dict[str, Any], *, allow_ca: bool = False,
) -> x509.CertificateSigningRequest:
    """Build a profile-aware CSR using the existing credential's managed key."""
    context = CmpCertificateRequestContext(
        operation='certification', protocol='cmp', domain=None,
        cert_profile_str=profile.unique_name, certificate_profile_model=profile,
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
