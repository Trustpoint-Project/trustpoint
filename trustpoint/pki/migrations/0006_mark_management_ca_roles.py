# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations

MANAGEMENT_CA_NAMES = ('Management Root CA', 'Management Issuing CA')
MANAGEMENT_CAPABLE_TYPES = [2, 3, 4, 5, 6, 7, 8]


def mark_builtin_management_cas(apps, _schema_editor):
    """Keep existing generated management CAs usable after adding the role field."""
    ca_model = apps.get_model('pki', 'CaModel')
    ca_model.objects.filter(
        unique_name__in=MANAGEMENT_CA_NAMES,
        ca_type__in=MANAGEMENT_CAPABLE_TYPES,
    ).update(ca_role=1)


class Migration(migrations.Migration):
    dependencies = [
        ('pki', '0005_tp_v1_0_1_dev0'),
    ]

    operations = [
        migrations.RunPython(mark_builtin_management_cas, migrations.RunPython.noop),
    ]
