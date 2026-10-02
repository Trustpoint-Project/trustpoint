# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('onboarding', '0002_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='onboardingconfigmodel',
            name='cmp_shared_secret_expires_at',
            field=models.DateTimeField(blank=True, default=None, null=True, verbose_name='CMP Shared Secret Expiry'),
        ),
    ]
