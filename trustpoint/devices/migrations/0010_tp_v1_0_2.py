# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0009_tp_v1_0_2'),
    ]

    operations = [
        migrations.CreateModel(
            name='GdsPushOperationLock',
            fields=[
                ('device', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='gds_push_operation_lock', serialize=False, to='devices.devicemodel')),
                ('acquired_at', models.DateTimeField()),
                ('expires_at', models.DateTimeField()),
            ],
        ),
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_managed_trustlist_fingerprints',
            field=models.JSONField(blank=True, default=list, help_text='SHA-256 fingerprints of the CA certificates and CRLs last managed by Trustpoint.', verbose_name='Managed Trust-List Fingerprints'),
        ),
    ]
