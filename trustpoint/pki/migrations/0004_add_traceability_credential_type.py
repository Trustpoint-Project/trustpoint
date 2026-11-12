# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):
    replaces = [('pki', '0004_tp_v1_0_1_dev0')]

    dependencies = [
        ('pki', '0003_issued_credential_certificate_profile'),
    ]

    operations = [
        migrations.AlterField(
            model_name='certificateprofilemodel',
            name='credential_type',
            field=models.CharField(
                choices=[
                    ('application', 'Application Credential'),
                    ('domain', 'Domain Credential'),
                    ('traceability_credential', 'Traceability Credential'),
                ],
                default='application',
                max_length=32,
            ),
        ),
        migrations.AlterField(
            model_name='credentialmodel',
            name='credential_type',
            field=models.IntegerField(
                choices=[
                    (0, 'Trustpoint TLS Server'),
                    (1, 'Root CA'),
                    (2, 'Issuing CA'),
                    (3, 'Issued Credential'),
                    (4, 'DevOwnerID'),
                    (5, 'Signer'),
                    (6, 'SCEP Server'),
                    (7, 'Traceability Credential'),
                ],
                verbose_name='Credential Type',
            ),
        ),
    ]
