# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.core.validators
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
                ('claimed_at', models.DateTimeField(null=True)),
                ('started_at', models.DateTimeField(null=True)),
            ],
        ),
        migrations.AlterField(
            model_name='discoveryport',
            name='port_number',
            field=models.PositiveIntegerField(
                unique=True,
                validators=[
                    django.core.validators.MinValueValidator(1),
                    django.core.validators.MaxValueValidator(65535),
                ],
            ),
        ),
    ]
