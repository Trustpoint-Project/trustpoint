# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Create traceability identities, assignment settings, and signing generation history."""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('management', '0003_tp_v1_0_1dev'),
        ('pki', '0004_add_traceability_credential_type'),
    ]

    operations = [
        migrations.CreateModel(
            name='TraceabilityCredentialGenerationModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('generation_number', models.PositiveIntegerField()),
                ('status', models.CharField(choices=[('ACTIVE', 'Active'), ('RETIRED', 'Retired')], max_length=8)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('activated_at', models.DateTimeField()),
                ('retired_at', models.DateTimeField(blank=True, null=True)),
                (
                    'credential',
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name='traceability_generation',
                        to='pki.credentialmodel',
                    ),
                ),
            ],
            options={
                'ordering': ['generation_number'],
            },
        ),
        migrations.CreateModel(
            name='TraceabilityCredentialModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'assignment_method',
                    models.CharField(
                        choices=[
                            ('MANAGEMENT_CA', 'Issue from Management CA'),
                            ('PKCS12', 'PKCS#12 file'),
                            ('SEPARATE_FILES', 'Separate files'),
                            ('CSR', 'Generate CSR'),
                        ],
                        max_length=16,
                    ),
                ),
                (
                    'management_ca',
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name='+',
                        to='pki.camodel',
                    ),
                ),
                (
                    'pending_credential',
                    models.OneToOneField(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name='+',
                        to='pki.credentialmodel',
                    ),
                ),
                ('pending_csr', models.TextField(blank=True, default='')),
                ('name', models.CharField(max_length=255, unique=True)),
                ('description', models.TextField(blank=True, default='')),
                (
                    'curve',
                    models.CharField(
                        choices=[('1.2.840.10045.3.1.7', 'SECP256R1'), ('1.3.132.0.34', 'SECP384R1')],
                        blank=True,
                        default='',
                        max_length=64,
                    ),
                ),
                (
                    'status',
                    models.CharField(
                        choices=[('UNASSIGNED', 'Awaiting credential'), ('ACTIVE', 'Active'), ('RETIRED', 'Retired')],
                        default='UNASSIGNED',
                        max_length=10,
                    ),
                ),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('retired_at', models.DateTimeField(blank=True, null=True)),
                (
                    'current_generation',
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name='+',
                        to='management.traceabilitycredentialgenerationmodel',
                    ),
                ),
            ],
            options={
                'ordering': ['-created_at'],
                'constraints': [
                    models.UniqueConstraint(
                        fields=('status',),
                        condition=models.Q(status='ACTIVE'),
                        name='traceability_one_active_credential',
                    )
                ],
            },
        ),
        migrations.AddField(
            model_name='traceabilitycredentialgenerationmodel',
            name='traceability_credential',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                related_name='generations',
                to='management.traceabilitycredentialmodel',
            ),
        ),
        migrations.AddConstraint(
            model_name='traceabilitycredentialgenerationmodel',
            constraint=models.UniqueConstraint(
                fields=('traceability_credential', 'generation_number'),
                name='traceability_signing_generation_number_unique',
            ),
        ),
        migrations.AddConstraint(
            model_name='traceabilitycredentialgenerationmodel',
            constraint=models.UniqueConstraint(
                condition=models.Q(('status', 'ACTIVE')),
                fields=('status',),
                name='traceability_signing_one_active_generation',
            ),
        ),
    ]
