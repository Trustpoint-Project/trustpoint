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
            name='credential_expires_at',
            field=models.DateTimeField(blank=True, default=None, help_text='Expiry for CMP shared-secret and EST/REST password authentication. Null means no expiry.', null=True, verbose_name='Credential Expiry'),
        ),
    ]
