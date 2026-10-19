# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('pki', '0003_tp_v1_0_dev0'),
    ]

    operations = [
        migrations.CreateModel(
            name='ScepServerConfigModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='scep_config', to='pki.domainmodel')),
                ('server_credential', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='pki.credentialmodel')),
            ],
        ),
    ]
