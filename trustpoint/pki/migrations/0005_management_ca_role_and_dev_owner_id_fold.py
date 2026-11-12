# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Management CA role and DevOwnerID ownership changes."""

from typing import Any, ClassVar

import django.db.models.deletion
from django.db import migrations, models

MANAGEMENT_CA_NAMES = ('Management Root CA', 'Management Issuing CA')
MANAGEMENT_CAPABLE_TYPES = [2, 3, 4, 5, 6, 7, 8]


def mark_builtin_management_cas(apps: Any, _schema_editor: Any) -> None:
    """Keep existing generated management CAs usable after adding the role field."""
    ca_model = apps.get_model('pki', 'CaModel')
    ca_model.objects.filter(
        unique_name__in=MANAGEMENT_CA_NAMES,
        ca_type__in=MANAGEMENT_CAPABLE_TYPES,
    ).update(ca_role=1)


def fold_owner_credentials(apps: Any, _schema_editor: Any) -> None:
    """Move the IDevID references onto the credential rows.

    shortcut: rollback cannot restore the owner grouping, upgrade only (branch is unreleased).
    """
    remote = apps.get_model('pki', 'RemoteIssuedCredentialModel')
    reference = apps.get_model('pki', 'IDevIDReferenceModel')

    for ref in reference.objects.all().iterator():
        owner_id = ref.dev_owner_id_id
        candidates = remote.objects.filter(owner_credential_id=owner_id).order_by('-created_at')
        target = None
        if ref.dev_owner_id_certificate_id is not None:
            target = candidates.filter(credential__certificate_id=ref.dev_owner_id_certificate_id).first()
        if target is None:
            target = candidates.first()
        if target is None:
            ref.delete()
            continue
        ref.dev_owner_id_id = target.pk
        ref.save(update_fields=['dev_owner_id'])


class Migration(migrations.Migration):
    """Add the management CA role and fold DevOwnerID ownership into credential rows."""

    dependencies: ClassVar[list[Any]] = [
        ('onboarding', '0003_encrypt_no_onboarding_credentials'),
        ('pki', '0004_tp_v1_0_1_dev0'),
    ]

    operations: ClassVar[list[Any]] = [
        migrations.AddField(
            model_name='camodel',
            name='ca_role',
            field=models.IntegerField(
                choices=[(0, 'Issuing CA'), (1, 'Management CA')],
                db_index=True,
                default=0,
                help_text='Issuing CAs serve endpoints; management CAs only issue Trustpoint management certificates.',
                verbose_name='CA Role',
            ),
        ),
        migrations.AddConstraint(
            model_name='camodel',
            constraint=models.CheckConstraint(
                condition=models.Q(
                    ('ca_role', 0), models.Q(('ca_role', 1), ('ca_type__in', [2, 3, 4, 5, 6, 7, 8])), _connector='OR'
                ),
                name='management_ca_role_constraint',
                violation_error_message='Management CAs cannot use this CA type',
            ),
        ),
        migrations.RunPython(mark_builtin_management_cas, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='idevidreferencemodel',
            name='dev_owner_id',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='idevid_ref_set',
                to='pki.remoteissuedcredentialmodel',
            ),
        ),
        migrations.RunPython(fold_owner_credentials, migrations.RunPython.noop),
        # shortcut: keep the legacy owner column/table in the database for one release so
        # base-branch code can still boot after a rollback; drop them in a follow-up release.
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.RemoveField(
                    model_name='remoteissuedcredentialmodel',
                    name='owner_credential',
                ),
                migrations.DeleteModel(
                    name='OwnerCredentialModel',
                ),
            ],
            database_operations=[],
        ),
    ]
