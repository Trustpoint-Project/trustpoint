# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('management', '0004_tp_v1_0_1_dev0'),
    ]

    operations = [
        migrations.RenameField(
            model_name='securityconfig',
            old_name='allow_auto_gen_pki',
            new_name='allow_self_signed_ca_creation',
        ),
        migrations.AlterField(
            model_name='securityconfig',
            name='allow_self_signed_ca_creation',
            field=models.BooleanField(default=False, help_text='Allow enabling local self-signed CA creation.'),
        ),
    ]
