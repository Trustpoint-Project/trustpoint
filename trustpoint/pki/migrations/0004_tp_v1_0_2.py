# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('devices', '0003_tp_v1_0_2'),
        ('pki', '0003_tp_v1_0_1'),
    ]

    operations = [
        migrations.CreateModel(
            name='CaRolloverTrustlistDeployment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('both_deployed_at', models.DateTimeField(auto_now=True)),
                ('certificate_replaced_at', models.DateTimeField(blank=True, null=True)),
                (
                    'device',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='ca_rollover_trustlist_deployments',
                        to='devices.devicemodel',
                    ),
                ),
                (
                    'rollover',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='trustlist_deployments',
                        to='pki.carollovermodel',
                    ),
                ),
            ],
            options={
                'constraints': [
                    models.UniqueConstraint(
                        fields=('rollover', 'device'), name='unique_rollover_trustlist_deployment_per_device'
                    )
                ],
            },
        ),
    ]
