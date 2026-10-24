# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.utils.timezone
import util.encrypted_fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('onboarding', '0002_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='DeviceSecretAssignmentLock',
            fields=[
                ('id', models.PositiveSmallIntegerField(default=1, editable=False, primary_key=True, serialize=False)),
            ],
        ),
        migrations.RemoveField(
            model_name='onboardingconfigmodel',
            name='opc_password',
        ),
        migrations.RemoveField(
            model_name='onboardingconfigmodel',
            name='opc_trust_store',
        ),
        migrations.RemoveField(
            model_name='onboardingconfigmodel',
            name='opc_user',
        ),
        migrations.AddField(
            model_name='noonboardingconfigmodel',
            name='cmp_secret_version',
            field=models.PositiveBigIntegerField(default=0, editable=False),
        ),
        migrations.AddField(
            model_name='noonboardingconfigmodel',
            name='est_password_version',
            field=models.PositiveBigIntegerField(default=0, editable=False),
        ),
        migrations.AddField(
            model_name='noonboardingconfigmodel',
            name='scep_challenge',
            field=util.encrypted_fields.EncryptedCharField(blank=True, default='', max_length=256, verbose_name='SCEP Challenge Password'),
        ),
        migrations.AddField(
            model_name='noonboardingconfigmodel',
            name='scep_challenge_consumed_at',
            field=models.DateTimeField(blank=True, null=True, verbose_name='SCEP Enrollment Authorization Consumed'),
        ),
        migrations.AddField(
            model_name='noonboardingconfigmodel',
            name='scep_challenge_digest',
            field=models.CharField(blank=True, db_index=True, default='', help_text='SHA-256 of the high-entropy challenge; used only to locate the device.', max_length=64, verbose_name='SCEP Challenge Lookup Digest'),
        ),
        migrations.AddField(
            model_name='noonboardingconfigmodel',
            name='scep_challenge_expires_at',
            field=models.DateTimeField(blank=True, null=True, verbose_name='SCEP Challenge Expiry'),
        ),
        migrations.AddField(
            model_name='noonboardingconfigmodel',
            name='scep_secret_version',
            field=models.PositiveBigIntegerField(default=0, editable=False),
        ),
        migrations.AddField(
            model_name='noonboardingconfigmodel',
            name='scep_transactions',
            field=models.JSONField(blank=True, default=dict, help_text='Issued SCEP transactions by transactionID: request digest, message type, certificate.', verbose_name='SCEP Transactions'),
        ),
        migrations.AddField(
            model_name='onboardingconfigmodel',
            name='cmp_secret_version',
            field=models.PositiveBigIntegerField(default=0, editable=False),
        ),
        migrations.AddField(
            model_name='onboardingconfigmodel',
            name='credential_expires_at',
            field=models.DateTimeField(blank=True, default=None, help_text='Expiry for CMP shared-secret and EST/REST password authentication. Null means no expiry.', null=True, verbose_name='Credential Expiry'),
        ),
        migrations.AddField(
            model_name='onboardingconfigmodel',
            name='est_password_version',
            field=models.PositiveBigIntegerField(default=0, editable=False),
        ),
        migrations.AddField(
            model_name='onboardingconfigmodel',
            name='scep_challenge',
            field=util.encrypted_fields.EncryptedCharField(blank=True, default='', max_length=256, verbose_name='SCEP Challenge Password'),
        ),
        migrations.AddField(
            model_name='onboardingconfigmodel',
            name='scep_challenge_consumed_at',
            field=models.DateTimeField(blank=True, null=True, verbose_name='SCEP Enrollment Authorization Consumed'),
        ),
        migrations.AddField(
            model_name='onboardingconfigmodel',
            name='scep_challenge_digest',
            field=models.CharField(blank=True, db_index=True, default='', help_text='SHA-256 of the high-entropy challenge; used only to locate the device.', max_length=64, verbose_name='SCEP Challenge Lookup Digest'),
        ),
        migrations.AddField(
            model_name='onboardingconfigmodel',
            name='scep_challenge_expires_at',
            field=models.DateTimeField(blank=True, null=True, verbose_name='SCEP Challenge Expiry'),
        ),
        migrations.AddField(
            model_name='onboardingconfigmodel',
            name='scep_secret_version',
            field=models.PositiveBigIntegerField(default=0, editable=False),
        ),
        migrations.AddField(
            model_name='onboardingconfigmodel',
            name='scep_transactions',
            field=models.JSONField(blank=True, default=dict, help_text='Issued SCEP transactions by transactionID: request digest, message type, certificate.', verbose_name='SCEP Transactions'),
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
