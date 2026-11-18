# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


def enable_default_lockout(apps, schema_editor):
    """Apply the new default to installations that never configured a limit."""
    account_security = apps.get_model('management', 'AccountSecurityConfig')
    account_security.objects.filter(failed_login_attempts__isnull=True).update(failed_login_attempts=5)


class Migration(migrations.Migration):
    dependencies = [
        ('management', '0004_tp_v1_0_1_dev0'),
    ]

    operations = [
        migrations.AlterField(
            model_name='accountsecurityconfig',
            name='failed_login_attempts',
            field=models.PositiveIntegerField(blank=True, default=5, null=True),
        ),
        migrations.RunPython(enable_default_lockout, migrations.RunPython.noop),
    ]
