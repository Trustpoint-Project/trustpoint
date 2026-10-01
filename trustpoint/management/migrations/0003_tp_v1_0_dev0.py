# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.core.validators
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('management', '0002_initial'),
        ('pki', '0002_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='AccountSecurityConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('api_credential_expiry_days', models.PositiveIntegerField(blank=True, default=None, null=True)),
                ('idle_timeout_minutes', models.PositiveIntegerField(default=30)),
                ('failed_login_attempts', models.PositiveIntegerField(blank=True, default=None, null=True)),
            ],
            options={
                'verbose_name': 'account security configuration',
                'verbose_name_plural': 'account security configuration',
            },
        ),
        migrations.CreateModel(
            name='CertificateAuthenticationConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('enabled', models.BooleanField(default=False, verbose_name='Enable certificate authentication')),
                ('issuing_ca', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='user_authentication_config', to='pki.camodel')),
            ],
            options={
                'verbose_name': 'Certificate authentication configuration',
                'verbose_name_plural': 'Certificate authentication configurations',
            },
        ),
        migrations.CreateModel(
            name='PasswordPolicy',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('require_otp', models.BooleanField(default=False, help_text='Require an authenticator code for every password login. Users without OTP must set it up first.', verbose_name='Require OTP')),
                ('minimum_length', models.PositiveIntegerField(default=8, help_text='Minimum number of characters in a password.')),
                ('prevent_password_reuse', models.BooleanField(default=True, help_text='Require a new password to differ from the immediately preceding password.')),
                ('password_expiry_days', models.PositiveIntegerField(blank=True, default=None, help_text='Leave empty to keep passwords valid indefinitely.', null=True)),
                ('user_similarity_enabled', models.BooleanField(default=True, help_text='Reject passwords that are too similar to the user information checked by Django.')),
                ('max_similarity', models.FloatField(default=0.7, help_text='Similarity threshold from 0.1 to 1.0. Lower values make the check stricter.', validators=[django.core.validators.MinValueValidator(0.1), django.core.validators.MaxValueValidator(1.0)])),
                ('reject_common_passwords', models.BooleanField(default=True, help_text='Reject passwords found in the common-password list.')),
                ('common_password_list_data', models.BinaryField(blank=True, default=bytes, help_text='Custom common-password list contents in plain text or gzip format, included in database backups.')),
                ('common_password_list_name', models.CharField(blank=True, default='', help_text='Original filename of the custom common-password list.', max_length=255)),
                ('reject_numeric_passwords', models.BooleanField(default=True, help_text='Reject passwords that consist entirely of digits.')),
                ('last_updated', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Password Policy',
                'verbose_name_plural': 'Password Policies',
            },
        ),
        migrations.DeleteModel(
            name='InternationalizationConfig',
        ),
        migrations.DeleteModel(
            name='UIConfig',
        ),
        migrations.AddField(
            model_name='securityconfig',
            name='not_permitted_mldsa_variant_oids',
            field=models.JSONField(blank=True, default=list, help_text='JSON list of ML-DSA variant OIDs (from trustpoint_core.oid.PublicKeyAlgorithmOid) not permitted at the current security level.'),
        ),
        migrations.AlterField(
            model_name='securityconfig',
            name='auto_gen_pki_key_algorithm',
            field=models.CharField(choices=[('RSA2048SHA256', 'RSA2048'), ('RSA4096SHA256', 'RSA4096'), ('SECP256R1SHA256', 'SECP256R1'), ('MLDSA44', 'ML-DSA-44'), ('MLDSA65', 'ML-DSA-65'), ('MLDSA87', 'ML-DSA-87')], default='RSA2048SHA256', max_length=24),
        ),
        migrations.AlterField(
            model_name='securityconfig',
            name='permitted_onboarding_protocols',
            field=models.JSONField(blank=True, default=list, help_text='JSON list of allowed OnboardingProtocol integer values (MANUAL=0, CMP_IDEVID=1, CMP_SHARED_SECRET=2, EST_IDEVID=3, EST_USERNAME_PASSWORD=4, AOKI=5, BRSKI=6, OPC_GDS_PUSH=7, REST_USERNAME_PASSWORD=8, AGENT=9).'),
        ),
    ]
