# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Serializers for the REST PKI certificate enrollment API."""

from typing import Any

from rest_framework import serializers

from pki.models.certificate import RevokedCertificateModel


class CertificateEnrollRequestSerializer(serializers.Serializer[Any]):
    r"""Serializer for certificate enrollment requests."""

    device_id = serializers.IntegerField(
        help_text='Primary key of the target device. Must be a no-onboarding device.',
    )
    cert_profile = serializers.CharField(
        help_text='Unique name of the certificate profile to use for issuance.',
    )
    csr = serializers.CharField(
        help_text=(
            r'PEM or Base64-DER encoded PKCS#10 Certificate Signing Request. '
            r'Literal newlines and escaped \n sequences are both accepted.'
        ),
    )

    def validate_csr(self, value: str) -> str:
        r"""Normalise the CSR string so it can be parsed regardless of how newlines were encoded."""
        return value.replace('\\n', '\n').strip()


class CertificateEnrollResponseSerializer(serializers.Serializer[Any]):
    """Serializer for the certificate enrollment response."""

    certificate = serializers.CharField(
        help_text='PEM-encoded issued certificate.',
    )
    certificate_chain = serializers.ListField(
        child=serializers.CharField(),
        help_text='List of PEM-encoded CA certificates forming the chain.',
    )


class CertificateRevokeRequestSerializer(serializers.Serializer[Any]):
    r"""Serializer for certificate revocation requests."""

    issued_credential_id = serializers.IntegerField(
        help_text='Primary key of the issued credential whose certificate shall be revoked.',
    )
    revocation_reason = serializers.ChoiceField(
        choices=RevokedCertificateModel.ReasonCode.choices,
        default=RevokedCertificateModel.ReasonCode.UNSPECIFIED,
        help_text='RFC 5280 revocation reason code. Defaults to "unspecified".',
    )


class CertificateRevokeResponseSerializer(serializers.Serializer[Any]):
    """Serializer for the certificate revocation response."""

    detail = serializers.CharField(
        help_text='Human-readable outcome of the revocation.',
    )
    issued_credential_id = serializers.IntegerField(
        help_text='Primary key of the issued credential that was revoked.',
    )
