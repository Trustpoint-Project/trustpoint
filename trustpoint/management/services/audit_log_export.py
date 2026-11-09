# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Create fixed, signed snapshots of filtered audit entries."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from management.models.traceability import TraceabilityCredentialModel
from management.services.traceability_signing import TraceabilityCredentialService
from util.audit_log_export import AUDIT_EXPORT_CONTEXT, base64url_encode, certificate_signature_algorithm, encode_json

if TYPE_CHECKING:
    from django.db.models import QuerySet

    from management.models.audit_log import AuditLog

# shortcut: snapshots buffer up to 10,000 entries; stream signed files if larger exports are needed.
MAX_EXPORT_ENTRIES = 10_000


@transaction.atomic
def create_signed_export(
    entries: QuerySet[AuditLog],
    credential: TraceabilityCredentialModel,
    filters: dict[str, str],
) -> dict[str, Any]:
    """Capture entries before signing can generate additional crypto audit events."""
    selected = entries.order_by('timestamp', 'pk').values(
        'id',
        'timestamp',
        'operation_type',
        'target_content_type__app_label',
        'target_content_type__model',
        'target_object_id',
        'target_display',
        'actor_id',
        'actor__username',
        'details',
    )[: MAX_EXPORT_ENTRIES + 1]
    rows: list[dict[str, Any]] = [{**row, 'timestamp': row['timestamp'].isoformat()} for row in selected]
    if len(rows) > MAX_EXPORT_ENTRIES:
        msg = f'Export limited to {MAX_EXPORT_ENTRIES:,} entries. Narrow the audit log filters.'
        raise ValidationError(msg)
    logical = TraceabilityCredentialModel.objects.select_for_update().get(pk=credential.pk)
    if not logical.is_usable or logical.current_generation is None:
        msg = 'The selected traceability credential is not currently usable.'
        raise ValidationError(msg)
    generation = logical.current_generation
    certificate = generation.credential.certificate_or_error.get_certificate_serializer().as_crypto()
    digest, algorithm = certificate_signature_algorithm(certificate)
    payload = {
        'context': AUDIT_EXPORT_CONTEXT,
        'exported_at': timezone.now().isoformat(),
        'filters': filters,
        'range': {
            'first_entry_id': rows[0]['id'] if rows else None,
            'last_entry_id': rows[-1]['id'] if rows else None,
            'first_timestamp': rows[0]['timestamp'] if rows else None,
            'last_timestamp': rows[-1]['timestamp'] if rows else None,
        },
        'entry_count': len(rows),
        'entries': rows,
        'signer': {
            'credential_id': logical.pk,
            'credential_name': logical.name,
            'generation_id': generation.pk,
            'generation_number': generation.generation_number,
            'certificate_fingerprint_sha256': certificate.fingerprint(hashes.SHA256()).hex(),
            'algorithm': algorithm,
        },
    }
    protected = base64url_encode(
        encode_json(
            {
                'alg': algorithm,
                'cty': 'application/json',
                'x5c': [base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode('ascii')],
            }
        )
    )
    encoded_payload = base64url_encode(encode_json(payload))
    signing_input = f'{protected}.{encoded_payload}'.encode('ascii')
    signed = TraceabilityCredentialService.sign(traceability_credential=logical, data=signing_input)
    r, s = decode_dss_signature(signed.signature)
    raw_signature = r.to_bytes(digest.digest_size, 'big') + s.to_bytes(digest.digest_size, 'big')
    return {
        'protected': protected,
        'payload': encoded_payload,
        'signature': base64url_encode(raw_signature),
    }
