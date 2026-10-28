# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.utils.timezone
import onboarding.models
import util.encrypted_fields
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='DeviceSecretAssignmentLock',
            fields=[
                ('id', models.PositiveSmallIntegerField(default=1, editable=False, primary_key=True, serialize=False)),
            ],
        ),
        migrations.CreateModel(
            name='NoOnboardingConfigModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cmp_secret_version', models.PositiveBigIntegerField(default=0, editable=False)),
                ('est_password_version', models.PositiveBigIntegerField(default=0, editable=False)),
                ('scep_secret_version', models.PositiveBigIntegerField(default=0, editable=False)),
                ('scep_challenge', util.encrypted_fields.EncryptedCharField(blank=True, default='', max_length=256, verbose_name='SCEP Challenge Password')),
                ('scep_challenge_digest', models.CharField(blank=True, db_index=True, default='', help_text='SHA-256 of the high-entropy challenge; used only to locate the device.', max_length=64, verbose_name='SCEP Challenge Lookup Digest')),
                ('scep_challenge_expires_at', models.DateTimeField(blank=True, null=True, verbose_name='SCEP Challenge Expiry')),
                ('scep_challenge_consumed_at', models.DateTimeField(blank=True, null=True, verbose_name='SCEP Enrollment Authorization Consumed')),
                ('scep_transactions', models.JSONField(blank=True, default=dict, help_text='Issued SCEP transactions by transactionID: request digest, message type, certificate.', verbose_name='SCEP Transactions')),
                ('pki_protocols', models.PositiveIntegerField(blank=True, default=0, verbose_name='Pki Protocol Bitwise Flag')),
                ('est_password', models.CharField(blank=True, default='', max_length=128, verbose_name='EST Password')),
                ('cmp_shared_secret', models.CharField(blank=True, default='', max_length=128, verbose_name='CMP Shared Secret')),
            ],
            options={
                'abstract': False,
            },
            bases=(onboarding.models.AbstractPkiProtocolModel, models.Model),
        ),
        migrations.CreateModel(
            name='OnboardingConfigModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cmp_secret_version', models.PositiveBigIntegerField(default=0, editable=False)),
                ('est_password_version', models.PositiveBigIntegerField(default=0, editable=False)),
                ('scep_secret_version', models.PositiveBigIntegerField(default=0, editable=False)),
                ('scep_challenge', util.encrypted_fields.EncryptedCharField(blank=True, default='', max_length=256, verbose_name='SCEP Challenge Password')),
                ('scep_challenge_digest', models.CharField(blank=True, db_index=True, default='', help_text='SHA-256 of the high-entropy challenge; used only to locate the device.', max_length=64, verbose_name='SCEP Challenge Lookup Digest')),
                ('scep_challenge_expires_at', models.DateTimeField(blank=True, null=True, verbose_name='SCEP Challenge Expiry')),
                ('scep_challenge_consumed_at', models.DateTimeField(blank=True, null=True, verbose_name='SCEP Enrollment Authorization Consumed')),
                ('scep_transactions', models.JSONField(blank=True, default=dict, help_text='Issued SCEP transactions by transactionID: request digest, message type, certificate.', verbose_name='SCEP Transactions')),
                ('pki_protocols', models.PositiveIntegerField(blank=True, default=0, verbose_name='Pki Protocol Bitwise Flag')),
                ('onboarding_status', models.IntegerField(choices=[(1, 'Pending'), (2, 'Onboarded')], default=1, verbose_name='Onboarding Status')),
                ('onboarding_protocol', models.PositiveIntegerField(choices=[(0, 'Manual Onboarding'), (1, 'CMP - IDevID'), (2, 'CMP - Shared Secret'), (3, 'EST - IDevID'), (4, 'EST - Username & Password'), (5, 'AOKI'), (6, 'BRSKI'), (7, 'OPC - GDS Push'), (8, 'REST - Username & Password'), (9, 'Agent')], verbose_name='Onboarding Protocol')),
                ('est_password', util.encrypted_fields.EncryptedCharField(blank=True, default='', max_length=128, verbose_name='EST Password')),
                ('cmp_shared_secret', util.encrypted_fields.EncryptedCharField(blank=True, default='', max_length=128, verbose_name='CMP Shared Secret')),
                ('credential_expires_at', models.DateTimeField(blank=True, default=None, help_text='Expiry for CMP shared-secret and EST/REST password authentication. Null means no expiry.', null=True, verbose_name='Credential Expiry')),
            ],
            options={
                'abstract': False,
            },
            bases=(onboarding.models.AbstractPkiProtocolModel, models.Model),
        ),
        migrations.CreateModel(
            name='DeviceSecretUse',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('config_label', models.CharField(max_length=100)),
                ('config_pk', models.PositiveBigIntegerField()),
                ('credential', models.CharField(max_length=32)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={
                'indexes': [models.Index(fields=['config_label', 'config_pk', 'credential'], name='device_secret_use_config_idx')],
            },
        ),
    ]
