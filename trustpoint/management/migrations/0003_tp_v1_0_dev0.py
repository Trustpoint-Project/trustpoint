# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('management', '0002_initial'),
        ('pki', '0003_tp_v1_0_dev0'),
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
        migrations.CreateModel(
            name='TraceabilityCredentialGenerationModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('generation_number', models.PositiveIntegerField()),
                ('status', models.CharField(choices=[('ACTIVE', 'Active'), ('RETIRED', 'Retired')], max_length=8)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('activated_at', models.DateTimeField()),
                ('retired_at', models.DateTimeField(blank=True, null=True)),
                ('credential', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='traceability_generation', to='pki.credentialmodel')),
            ],
            options={
                'ordering': ['generation_number'],
            },
        ),
        migrations.CreateModel(
            name='TraceabilityCredentialModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255, unique=True)),
                ('description', models.TextField(blank=True, default='')),
                ('curve', models.CharField(choices=[('1.2.840.10045.3.1.7', 'SECP256R1'), ('1.3.132.0.34', 'SECP384R1')], max_length=64)),
                ('purposes', models.JSONField(default=list)),
                ('status', models.CharField(choices=[('ACTIVE', 'Active'), ('RETIRED', 'Retired')], default='ACTIVE', max_length=8)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('retired_at', models.DateTimeField(blank=True, null=True)),
                ('current_generation', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='management.traceabilitycredentialgenerationmodel')),
            ],
            options={
                'ordering': ['-created_at'],
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
        migrations.AddField(
            model_name='traceabilitycredentialgenerationmodel',
            name='traceability_credential',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='generations', to='management.traceabilitycredentialmodel'),
        ),
        migrations.AddConstraint(
            model_name='traceabilitycredentialgenerationmodel',
            constraint=models.UniqueConstraint(fields=('traceability_credential', 'generation_number'), name='traceability_signing_generation_number_unique'),
        ),
        migrations.AddConstraint(
            model_name='traceabilitycredentialgenerationmodel',
            constraint=models.UniqueConstraint(condition=models.Q(('status', 'ACTIVE')), fields=('traceability_credential',), name='traceability_signing_one_active_generation'),
        ),
    ]
