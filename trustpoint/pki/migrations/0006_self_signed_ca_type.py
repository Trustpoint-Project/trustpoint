# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('onboarding', '0003_encrypt_no_onboarding_credentials'),
        ('pki', '0005_management_ca_role_and_dev_owner_id_fold'),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name='camodel',
            name='ca_mode_constraint',
        ),
        migrations.RemoveConstraint(
            model_name='camodel',
            name='management_ca_role_constraint',
        ),
        migrations.AlterField(
            model_name='camodel',
            name='ca_type',
            field=models.IntegerField(
                blank=True,
                choices=[
                    (-1, 'Keyless CA'),
                    (0, 'Auto-Generated Root (Legacy)'),
                    (1, 'Auto-Generated (Legacy)'),
                    (2, 'Local-Legacy Software'),
                    (3, 'Local-Managed Backend'),
                    (4, 'Remote-EST-RA'),
                    (5, 'Remote-CMP-RA'),
                    (6, 'Remote-Issuing-EST'),
                    (7, 'Remote-Issuing-CMP'),
                    (8, 'Remote-Issuing-CSR'),
                    (9, 'Self-Signed'),
                ],
                help_text='Type of CA - KEYLESS for keyless CAs',
                null=True,
                verbose_name='CA Type',
            ),
        ),
        migrations.AddConstraint(
            model_name='camodel',
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(('ca_type', -1), ('certificate__isnull', False), ('credential__isnull', True)),
                    models.Q(('ca_type__in', [4, 5]), ('credential__isnull', True)),
                    models.Q(
                        ('ca_type__in', [0, 1, 2, 3, 6, 7, 8, 9]),
                        ('certificate__isnull', True),
                        ('credential__isnull', False),
                    ),
                    _connector='OR',
                ),
                name='ca_mode_constraint',
                violation_error_message='Invalid CA configuration',
            ),
        ),
        migrations.AddConstraint(
            model_name='camodel',
            constraint=models.CheckConstraint(
                condition=models.Q(
                    ('ca_role', 0), models.Q(('ca_role', 1), ('ca_type__in', [2, 3, 4, 5, 6, 7, 8, 9])), _connector='OR'
                ),
                name='management_ca_role_constraint',
                violation_error_message='Management CAs cannot use this CA type',
            ),
        ),
    ]
