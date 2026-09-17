# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0006_tp_v1_0_dev0'),
    ]

    operations = [
        migrations.AddField(
            model_name='trustpointuser',
            name='view_mode',
            field=models.CharField(choices=[('standard', 'Standard View'), ('simplified', 'Simplified View')], default='standard', help_text='Choose between standard and simplified views.', max_length=10, verbose_name='view mode'),
        ),
    ]
