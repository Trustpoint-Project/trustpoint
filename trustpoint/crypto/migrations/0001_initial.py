"""Initial persistence models for the crypto provider profile store."""

from __future__ import annotations

import django.db.models.deletion
from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='CryptoProviderProfileModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True)),
                ('module_path', models.TextField()),
                ('token_label', models.CharField(blank=True, max_length=128, null=True)),
                ('token_serial', models.CharField(blank=True, max_length=128, null=True)),
                ('slot_id', models.PositiveIntegerField(blank=True, null=True)),
                ('auth_source', models.CharField(choices=[('inline', 'Inline'), ('env', 'Environment variable'), ('file', 'File path')], max_length=16)),
                (
                    'auth_source_ref',
                    models.TextField(
                        help_text='Inline PIN, environment variable name, or PIN file path depending on auth_source.',
                    ),
                ),
                ('max_sessions', models.PositiveIntegerField(default=8)),
                ('borrow_timeout_seconds', models.FloatField(default=5.0)),
                ('rw_sessions', models.BooleanField(default=True)),
                ('allow_legacy_label_lookup', models.BooleanField(default=False)),
                ('active', models.BooleanField(default=False)),
                (
                    'last_probe_status',
                    models.CharField(
                        choices=[('never', 'Never probed'), ('success', 'Success'), ('failure', 'Failure')],
                        default='never',
                        max_length=16,
                    ),
                ),
                ('last_probe_at', models.DateTimeField(blank=True, null=True)),
                ('last_probe_error', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'crypto_provider_profile',
            },
        ),
        migrations.CreateModel(
            name='CryptoProviderCapabilitySnapshotModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'status',
                    models.CharField(
                        choices=[('never', 'Never probed'), ('success', 'Success'), ('failure', 'Failure')],
                        max_length=16,
                    ),
                ),
                ('probed_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('probe_hash', models.CharField(db_index=True, max_length=64)),
                ('token_label', models.CharField(blank=True, max_length=128, null=True)),
                ('token_serial', models.CharField(blank=True, max_length=128, null=True)),
                ('token_model', models.CharField(blank=True, max_length=128, null=True)),
                ('token_manufacturer', models.CharField(blank=True, max_length=128, null=True)),
                ('slot_id', models.PositiveIntegerField(blank=True, null=True)),
                ('snapshot', models.JSONField(default=dict)),
                ('error_summary', models.TextField(blank=True, null=True)),
                (
                    'profile',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='capability_snapshots',
                        to='crypto.cryptoproviderprofilemodel',
                    ),
                ),
            ],
            options={
                'db_table': 'crypto_provider_capability_snapshot',
                'ordering': ['-probed_at', '-id'],
            },
        ),
        migrations.AddField(
            model_name='cryptoproviderprofilemodel',
            name='current_capability_snapshot',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='+',
                to='crypto.cryptoprovidercapabilitysnapshotmodel',
            ),
        ),
        migrations.AddIndex(
            model_name='cryptoproviderprofilemodel',
            index=models.Index(fields=['active'], name='crypto_prov_active_1f7151_idx'),
        ),
        migrations.AddIndex(
            model_name='cryptoproviderprofilemodel',
            index=models.Index(fields=['name'], name='crypto_prov_name_6da1e9_idx'),
        ),
        migrations.AddIndex(
            model_name='cryptoproviderprofilemodel',
            index=models.Index(fields=['token_serial'], name='crypto_prov_token_s_1b1624_idx'),
        ),
        migrations.AddConstraint(
            model_name='cryptoproviderprofilemodel',
            constraint=models.UniqueConstraint(
                condition=models.Q(('active', True)),
                fields=('active',),
                name='crypto_single_active_provider_profile',
            ),
        ),
        migrations.AddIndex(
            model_name='cryptoprovidercapabilitysnapshotmodel',
            index=models.Index(fields=['profile', 'probed_at'], name='crypto_capa_profile_34a5e4_idx'),
        ),
        migrations.AddIndex(
            model_name='cryptoprovidercapabilitysnapshotmodel',
            index=models.Index(fields=['profile', 'status'], name='crypto_capa_profile_8981a4_idx'),
        ),
        migrations.AddIndex(
            model_name='cryptoprovidercapabilitysnapshotmodel',
            index=models.Index(fields=['token_serial'], name='crypto_capa_token_s_1124d1_idx'),
        ),
    ]
