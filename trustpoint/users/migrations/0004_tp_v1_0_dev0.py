# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0003_tp_v1_0_dev0'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='groupprofile',
            name='is_protected',
        ),
        migrations.AddField(
            model_name='groupprofile',
            name='is_deletion_protected',
            field=models.BooleanField(default=False, help_text='Prevents the role from being deleted.', verbose_name='deletion-protected role'),
        ),
        migrations.AddField(
            model_name='groupprofile',
            name='is_modification_protected',
            field=models.BooleanField(default=False, help_text='Prevents the role from being modified.', verbose_name='modification-protected role'),
        ),
    ]
