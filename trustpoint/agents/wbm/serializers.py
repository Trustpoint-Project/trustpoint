"""DRF serializers for the WBM agent API endpoints."""

from typing import Any

from rest_framework import serializers


class WbmSubmitCsrRequestSerializer(serializers.Serializer[Any]):
    r"""Serializer for POST /agents/wbm/submit-csr/ request bodies."""

    job_id = serializers.IntegerField(
        help_text='Primary key of the AgentJob in PENDING_CSR state.',
    )
    csr_pem = serializers.CharField(
        help_text=(
            r'PEM-encoded PKCS#10 Certificate Signing Request. '
            r'Literal newlines and escaped \n sequences are both accepted.'
        ),
    )

    def validate_csr_pem(self, value: str) -> str:
        r"""Normalise the CSR PEM string regardless of how newlines were encoded."""
        return value.replace('\\n', '\n').strip()


class WbmPushResultRequestSerializer(serializers.Serializer[Any]):
    """Serializer for POST /agents/wbm/push-result/ request bodies."""

    job_id = serializers.IntegerField(
        help_text='Primary key of the AgentJob in IN_PROGRESS state.',
    )
    status = serializers.ChoiceField(
        choices=['succeeded', 'failed'],
        help_text="Outcome of the push operation: 'succeeded' or 'failed'.",
    )
    detail = serializers.CharField(
        required=False,
        default='',
        allow_blank=True,
        help_text='Optional human-readable description of the outcome.',
    )


class WbmCheckInResponseSerializer(serializers.Serializer[Any]):
    """Serializer for the GET /agents/wbm/check-in/ response."""

    poll_interval_seconds = serializers.IntegerField(
        help_text='Recommended interval (in seconds) before the next check-in.',
    )
    jobs = serializers.ListField(
        child=serializers.DictField(),
        help_text='List of pending job descriptors for the agent to process.',
    )


class WbmSubmitCsrResponseSerializer(serializers.Serializer[Any]):
    """Serializer for the POST /agents/wbm/submit-csr/ response."""

    cert_pem = serializers.CharField(
        help_text='PEM-encoded issued end-entity certificate.',
    )
    ca_bundle_pem = serializers.CharField(
        help_text='PEM-encoded CA certificate chain (issuer → root).',
    )


class WbmPushResultResponseSerializer(serializers.Serializer[Any]):
    """Serializer for the POST /agents/wbm/push-result/ response."""

    status = serializers.CharField(
        help_text="Acknowledged status echoed from the request ('succeeded' or 'failed').",
    )
