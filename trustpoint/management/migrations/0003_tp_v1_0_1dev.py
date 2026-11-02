# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import util.ssh
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('management', '0002_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='backupoptions',
            name='host_key',
            field=models.TextField(
                blank=True,
                default='',
                help_text='Verified OpenSSH server public key (key type and Base64 data, with an optional comment).',
                validators=[util.ssh.validate_ssh_host_key],
                verbose_name='Server host public key',
            ),
        ),
    ]
