# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Identity and transaction constraints for RFC 9483 certificate updates."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography import x509
from pyasn1.codec.der import decoder, encoder  # type: ignore[import-untyped]
from pyasn1_modules import rfc4211  # type: ignore[import-untyped]

from cmp.util import NameParser
from request.message_parser.rfc9480 import build_pki_message_spec

if TYPE_CHECKING:
    from cmp.models import CmpTransactionModel
    from request.request_context import CmpBaseRequestContext, CmpCertificateRequestContext


def validate_key_update_identity(
    context: CmpCertificateRequestContext, *, profile_validated: bool = False,
) -> None:
    """Require the old certificate's identity in both the request and issued template."""
    certificate = context.client_certificate
    if certificate is None or context.domain is None:
        msg = 'CMP key update requires an authenticated certificate and domain.'
        raise ValueError(msg)
    ca = context.domain.get_issuing_ca_or_value_error()
    credential = ca.get_credential()
    if credential is None:
        msg = 'CMP key update requires the addressed CA certificate.'
        raise ValueError(msg)
    certificate.verify_directly_issued_by(credential.get_certificate())

    builder = context.cert_requested_profile_validated if profile_validated else context.cert_requested
    if not isinstance(builder, x509.CertificateBuilder):
        msg = 'CMP key update requires a certificate template.'
        raise TypeError(msg)
    subject = builder._subject_name  # noqa: SLF001 - cryptography exposes no builder getters.
    extensions = builder._extensions  # noqa: SLF001
    san = next(
        (extension.value for extension in extensions if isinstance(extension.value, x509.SubjectAlternativeName)), None,
    )
    try:
        old_san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        old_san = None
    # A name may be supplied in subject, SAN, or both; any supplied identity must match.
    if not subject and san is None:
        msg = 'CMP key update must contain the existing subject or subjectAltName.'
        raise ValueError(msg)
    if subject and subject != certificate.subject:
        msg = 'CMP key update must preserve the existing subject.'
        raise ValueError(msg)
    if san is not None and san != old_san:
        msg = 'CMP key update must preserve the existing subjectAltName.'
        raise ValueError(msg)
    if profile_validated and (subject != certificate.subject or san != old_san):
        msg = 'CMP key update profile must preserve the existing subject and subjectAltName.'
        raise ValueError(msg)

    _validate_old_cert_id(context, certificate)


def _validate_old_cert_id(context: CmpCertificateRequestContext, certificate: x509.Certificate) -> None:
    message = context.parsed_message
    if message is None:
        msg = 'CMP key update requires a parsed message.'
        raise ValueError(msg)
    controls = message['body']['kur'][0]['certReq']['controls']
    for control in controls:
        if str(control['type']) != '1.3.6.1.5.5.7.5.1.5':  # id-regCtrl-oldCertID
            continue
        old_id, remainder = decoder.decode(control['value'].asOctets(), asn1Spec=rfc4211.CertId())
        if remainder or old_id['issuer'].getName() != 'directoryName':
            msg = 'Invalid CMP oldCertID.'
            raise ValueError(msg)
        if (int(old_id['serialNumber']) != certificate.serial_number
                or NameParser.parse_name(old_id['issuer']['directoryName']) != certificate.issuer):
            msg = 'CMP oldCertID does not identify the protection certificate.'
            raise ValueError(msg)


def validate_key_update_followup(context: CmpBaseRequestContext, transaction: CmpTransactionModel) -> None:
    """Keep update polling and confirmation bound to the original protection certificate."""
    original, remainder = decoder.decode(bytes(transaction.request_der), asn1Spec=build_pki_message_spec())
    if remainder or not original['extraCerts'].hasValue() or context.client_certificate is None:
        msg = 'CMP key update transaction has no original protection certificate.'
        raise ValueError(msg)
    certificate = x509.load_der_x509_certificate(encoder.encode(original['extraCerts'][0]))
    if certificate != context.client_certificate:
        msg = 'CMP key update follow-up must use the original protection certificate.'
        raise ValueError(msg)
