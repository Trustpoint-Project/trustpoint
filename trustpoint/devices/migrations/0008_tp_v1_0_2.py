# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('devices', '0007_tp_v1_0_2'),
    ]

    operations = [
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_minimum_key_size',
            field=models.PositiveIntegerField(
                default=0,
                help_text='Reject a newly issued server certificate below this key size. 0 means no check.',
                verbose_name='Minimum Certificate Key Size (bits)',
            ),
        ),
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_reject_sha1',
            field=models.BooleanField(
                default=True,
                help_text='Reject a newly issued server certificate that is signed with SHA-1.',
                verbose_name='Reject SHA-1 Signed Server Certificates',
            ),
        ),
    ]
