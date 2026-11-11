# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('onboarding', '0003_encrypt_no_onboarding_credentials'),
        ('pki', '0004_tp_v1_0_1_dev0'),
    ]

    operations = [
        migrations.AddField(
            model_name='camodel',
            name='ca_role',
            field=models.IntegerField(
                choices=[(0, 'Issuing CA'), (1, 'Management CA')],
                db_index=True,
                default=0,
                help_text='Issuing CAs serve endpoints; management CAs only issue Trustpoint management certificates.',
                verbose_name='CA Role',
            ),
        ),
        migrations.AddConstraint(
            model_name='camodel',
            constraint=models.CheckConstraint(
                condition=models.Q(
                    ('ca_role', 0), models.Q(('ca_role', 1), ('ca_type__in', [2, 3, 4, 5, 6, 7, 8])), _connector='OR'
                ),
                name='management_ca_role_constraint',
                violation_error_message='Management CAs cannot use this CA type',
            ),
        ),
    ]
