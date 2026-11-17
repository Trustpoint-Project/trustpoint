# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('discovery', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='DiscoveryScan',
            fields=[
                ('id', models.PositiveSmallIntegerField(default=1, editable=False, primary_key=True, serialize=False)),
                ('scan_id', models.UUIDField(editable=False, null=True)),
                ('is_running', models.BooleanField(default=False)),
                ('stop_pending', models.BooleanField(default=False)),
                ('start_ip', models.GenericIPAddressField(default='10.100.13.1', protocol='IPv4')),
                ('end_ip', models.GenericIPAddressField(default='10.100.13.254', protocol='IPv4')),
                ('started_at', models.DateTimeField(null=True)),
            ],
        ),
    ]
