# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Validate and resolve the profile used for user TLS client certificates."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from trustpoint_core.oid import KeyPairGenerator

from pki.models import DomainModel
from pki.services.management_ca import ManagementCAService
from pki.services.management_issuance import sign_certificate_builder
from pki.util.cert_profile import JSONProfileVerifier, ProfileValidationError
from pki.util.cert_req_converter import JSONCertRequestConverter
from request.request_context import ManualCredentialRequestContext
from request.template_vars import resolve_template_variables
from users.models import TrustpointUser

if TYPE_CHECKING:
    from trustpoint_core.crypto_types import PrivateKey

    from pki.models import CaModel, CertificateProfileModel


def user_client_certificate_request(profile: CertificateProfileModel, issuing_ca: CaModel) -> dict[str, Any]:
    """Return resolved defaults, rejecting profiles that cannot safely authenticate a user."""
    context = ManualCredentialRequestContext(domain=DomainModel(issuing_ca=issuing_ca))
    resolved_profile = resolve_template_variables(profile.profile, context)
    try:
        request = JSONProfileVerifier(resolved_profile).apply_profile_to_request({'type': 'cert_request'})
    except ProfileValidationError as exc:
        raise ValidationError(str(exc)) from exc
    request = resolve_template_variables(request, context)
    extensions = request.get('extensions', {})
    if extensions.get('subject_alternative_name', {}).get('critical', False):
        raise ValidationError(_('User certificate profiles must use a noncritical Subject Alternative Name extension.'))
    usage = extensions.get('key_usage', {})
    if (
        'basic_constraints' not in extensions
        or extensions['basic_constraints'].get('ca', False)
        or not usage.get('digital_signature', False)
        or usage.get('key_cert_sign', False)
        or usage.get('crl_sign', False)
        or not any(
            name.replace('_', '').lower() in ('clientauth', ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string)
            for name in extensions.get('extended_key_usage', {}).get('usages', [])
        )
    ):
        raise ValidationError(
            _(
                'Choose an end-entity profile with digital signature key usage and TLS client authentication, '
                'without certificate or CRL signing key usage.'
            )
        )
    JSONCertRequestConverter.from_json(request)
    return request


def user_client_certificate_builder(
    issuing_ca: CaModel,
    identity: x509.Name,
    *,
    validity_days: int,
) -> x509.CertificateBuilder:
    """Apply configured defaults while preserving identity and the issuer's validity limits."""
    config = getattr(issuing_ca, 'user_authentication_config', None)
    profile = config.certificate_profile if config is not None else None
    now = timezone.now()
    issuer = issuing_ca.get_certificate()
    if issuer is None:
        raise ValidationError(_('The management CA has no certificate.'))
    remaining_days = (issuer.not_valid_after_utc - now).days + 1
    request = (
        user_client_certificate_request(profile, issuing_ca)
        if profile is not None
        else {
            'type': 'cert_request',
            'extensions': {
                'basic_constraints': {'ca': False, 'critical': True},
                'key_usage': {'digital_signature': True, 'critical': True},
                'extended_key_usage': {'usages': ['client_auth']},
            },
            'validity': {'days': min(validity_days, remaining_days)},
        }
    )
    profile_subject = JSONCertRequestConverter.from_json(request)._subject_name  # noqa: SLF001
    identity_oids = {NameOID.USER_ID, NameOID.SERIAL_NUMBER, NameOID.UNSTRUCTURED_NAME}
    attributes = [attribute for attribute in profile_subject or [] if attribute.oid not in identity_oids]
    identity_attributes = list(identity)
    if not any(attribute.oid == NameOID.COMMON_NAME for attribute in attributes):
        attributes.insert(0, identity_attributes[0])
    subject = x509.Name([*attributes, *identity_attributes[1:]])
    request['subject'] = {}
    validity = request.get('validity', {})
    if validity.get('not_before') and validity.get('not_after'):
        not_before, not_after = validity['not_before'], validity['not_after']
    else:
        not_before = now - timedelta(minutes=5)
        not_after = now + JSONCertRequestConverter.validity_period_from_json(validity)
    request['validity'] = {'not_before': not_before, 'not_after': not_after}
    return JSONCertRequestConverter.from_json(request).subject_name(subject)


def create_user_client_certificate(
    user_id: int,
    subject_identifier: str,
    *,
    validity_days: int = 365,
    issuing_ca: CaModel | None = None,
) -> tuple[x509.Certificate, PrivateKey]:
    """Issue through the shared management CA signer, keeping the user's key in memory."""
    if validity_days <= 0:
        raise ValidationError(_('The validity period must be a positive number of days.'))
    try:
        user = TrustpointUser.objects.get(
            pk=user_id,
            account_type=TrustpointUser.AccountType.HUMAN,
            is_active=True,
        )
    except TrustpointUser.DoesNotExist as exc:
        raise ValidationError(_('No active human user exists with ID %(id)s.'), params={'id': user_id}) from exc
    if issuing_ca is None:
        issuing_ca = ManagementCAService.get_issuing_ca()
    if issuing_ca is None or issuing_ca.credential is None:
        raise ValidationError(_('No management CA is configured for user certificate issuance.'))
    issuer_certificate = issuing_ca.get_certificate()
    if issuer_certificate is None:
        raise ValidationError(_('The management CA has no certificate.'))
    private_key = KeyPairGenerator.generate_key_pair_for_certificate(issuer_certificate)
    identity = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, 'trustpoint-client-certificate'),
            x509.NameAttribute(NameOID.USER_ID, user.username),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, str(user.pk)),
            x509.NameAttribute(NameOID.UNSTRUCTURED_NAME, subject_identifier),
        ]
    )
    builder = user_client_certificate_builder(issuing_ca, identity, validity_days=validity_days)
    certificate, _chain = sign_certificate_builder(builder.public_key(private_key.public_key()), issuing_ca)
    return certificate, private_key
