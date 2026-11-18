# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('discovery', '0003_discoveryport_port_range'),
    ]

    operations = [
        migrations.AddField(
            model_name='discoveryscan',
            name='claimed_at',
            field=models.DateTimeField(null=True),
        ),
    ]
