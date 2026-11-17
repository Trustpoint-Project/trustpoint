# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Backfill the audit hash chain and create the singleton signing configuration."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from typing import Any, ClassVar

from django.db import migrations, models

GENESIS_HASH = '0' * 64
BACKFILL_BATCH_SIZE = 500


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        allow_nan=False,
    ).encode('utf-8')


def _entry_payload(entry: Any, sequence: int, previous_hash: str, actor_label: str, target_type: str) -> dict[str, Any]:
    timestamp = entry.timestamp
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=dt.UTC)
    return {
        'v': 1,
        'sequence': sequence,
        'previous_hash': previous_hash,
        'timestamp': timestamp.astimezone(dt.UTC).isoformat(timespec='microseconds'),
        'operation_type': entry.operation_type,
        'target_type': target_type,
        'target_object_id': entry.target_object_id,
        'target_display': entry.target_display,
        'actor_label': actor_label,
        'details': entry.details or {},
    }


def backfill_audit_chain(apps: Any, schema_editor: Any) -> None:
    """Hash existing rows in stable order and anchor the signing configuration row."""
    del schema_editor
    audit_log = apps.get_model('management', 'AuditLog')
    signing_config = apps.get_model('management', 'AuditSigningConfig')

    previous_hash = GENESIS_HASH
    batch: list[Any] = []
    rows = (
        audit_log.objects.select_related('actor', 'target_content_type')
        .order_by('timestamp', 'pk')
        .iterator(chunk_size=BACKFILL_BATCH_SIZE)
    )
    for sequence, entry in enumerate(rows, start=1):
        actor_label = entry.actor.username[:255] if entry.actor_id and entry.actor else ''
        target_type = f'{entry.target_content_type.app_label}.{entry.target_content_type.model}'[:255]
        payload = _entry_payload(entry, sequence, previous_hash, actor_label, target_type)
        entry_hash = hashlib.sha256(_canonical_json(payload)).hexdigest()
        entry.sequence = sequence
        entry.previous_hash = previous_hash
        entry.entry_hash = entry_hash
        entry.actor_label = actor_label
        entry.target_type = target_type
        batch.append(entry)
        previous_hash = entry_hash
        if len(batch) >= BACKFILL_BATCH_SIZE:
            audit_log.objects.bulk_update(
                batch,
                ['sequence', 'previous_hash', 'entry_hash', 'actor_label', 'target_type'],
            )
            batch = []
    if batch:
        audit_log.objects.bulk_update(
            batch,
            ['sequence', 'previous_hash', 'entry_hash', 'actor_label', 'target_type'],
        )
    signing_config.objects.get_or_create(pk=1)


class Migration(migrations.Migration):
    """Add the required hash-chain columns after backfilling existing events."""

    dependencies: ClassVar[list[tuple[str, str]]] = [('management', '0013_audit_signing')]

    operations: ClassVar[list[Any]] = [
        migrations.RunPython(backfill_audit_chain, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='auditlog',
            name='actor_label',
            field=models.CharField(blank=True, default='', editable=False, max_length=255),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='entry_hash',
            field=models.CharField(editable=False, max_length=64, unique=True),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='previous_hash',
            field=models.CharField(editable=False, max_length=64),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='sequence',
            field=models.PositiveBigIntegerField(editable=False, unique=True),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='target_type',
            field=models.CharField(editable=False, max_length=255),
        ),
    ]
