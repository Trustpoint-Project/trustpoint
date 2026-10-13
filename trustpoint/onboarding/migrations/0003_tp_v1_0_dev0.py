# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.db.models.deletion
import util.encrypted_fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('onboarding', '0002_initial'),
        ('pki', '0002_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='noonboardingconfigmodel',
            name='scep_certificate_profile',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='pki.certificateprofilemodel', verbose_name='SCEP Certificate Profile'),
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
            name='scep_transactions',
            field=models.JSONField(blank=True, default=dict, help_text='Issued SCEP transactions by transactionID: request digest, message type, certificate.', verbose_name='SCEP Transactions'),
        ),
        migrations.AddField(
            model_name='onboardingconfigmodel',
            name='credential_expires_at',
            field=models.DateTimeField(blank=True, default=None, help_text='Expiry for CMP shared-secret and EST/REST password authentication. Null means no expiry.', null=True, verbose_name='Credential Expiry'),
        ),
        migrations.AddField(
            model_name='onboardingconfigmodel',
            name='scep_certificate_profile',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='pki.certificateprofilemodel', verbose_name='SCEP Certificate Profile'),
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
            name='scep_transactions',
            field=models.JSONField(blank=True, default=dict, help_text='Issued SCEP transactions by transactionID: request digest, message type, certificate.', verbose_name='SCEP Transactions'),
        ),
    ]
