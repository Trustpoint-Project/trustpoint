# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0005_tp_v1_0_dev0'),
    ]

    operations = [
        migrations.AddField(
            model_name='trustpointuser',
            name='must_change_password',
            field=models.BooleanField(default=False, help_text='Require this user to change their password at the next login.', verbose_name='must change password'),
        ),
    ]
