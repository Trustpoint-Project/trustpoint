# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Adds an optional expiry timestamp for the CMP shared secret (challenge password)."""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('onboarding', '0002_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='onboardingconfigmodel',
            name='cmp_shared_secret_expires_at',
            field=models.DateTimeField(
                blank=True,
                default=None,
                null=True,
                verbose_name='CMP Shared Secret Expiry',
            ),
        ),
    ]
