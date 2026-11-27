# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('devices', '0008_tp_v1_0_2'),
    ]

    operations = [
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_certificate_inventory',
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text='Certificate groups, trust lists and rejected certificates read from the device.',
                verbose_name='Last Certificate Inventory',
            ),
        ),
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_certificate_inventory_updated_at',
            field=models.DateTimeField(blank=True, null=True, verbose_name='Certificate Inventory Updated At'),
        ),
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_server_validation',
            field=models.CharField(
                choices=[
                    ('pinned', 'Pinned leaf certificate (truststore order 0)'),
                    ('ca', 'CA chain validation (truststore CA certificates)'),
                ],
                default='pinned',
                help_text='Pinned validation requires the exact server certificate at truststore order 0. CA validation reads the current server certificate and accepts it when it chains to a CA in the truststore, which allows certificate rotation.',
                max_length=16,
                verbose_name='Server Certificate Validation',
            ),
        ),
    ]
