# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('management', '0002_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='AccountSecurityConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password_minimum_length', models.PositiveIntegerField(default=8)),
                ('password_similarity', models.BooleanField(default=True)),
                ('password_common', models.BooleanField(default=True)),
                ('password_numeric', models.BooleanField(default=True)),
                ('password_prevent_reuse', models.BooleanField(default=True)),
                ('password_expiry_days', models.PositiveIntegerField(blank=True, default=None, null=True)),
                ('api_credential_expiry_days', models.PositiveIntegerField(blank=True, default=None, null=True)),
                ('idle_timeout_minutes', models.PositiveIntegerField(default=30)),
                ('failed_login_attempts', models.PositiveIntegerField(blank=True, default=None, null=True)),
            ],
            options={
                'verbose_name': 'account security configuration',
                'verbose_name_plural': 'account security configuration',
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
