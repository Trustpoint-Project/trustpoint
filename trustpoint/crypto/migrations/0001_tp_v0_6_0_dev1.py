import django.db.models.deletion
import django.utils.timezone
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='CryptoProviderCapabilitySnapshotModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(choices=[('never', 'Never probed'), ('success', 'Success'), ('failure', 'Failure')], max_length=16)),
                ('probed_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('probe_hash', models.CharField(db_index=True, max_length=64)),
                ('error_summary', models.TextField(blank=True, null=True)),
            ],
            options={
                'db_table': 'crypto_provider_capability_snapshot',
                'ordering': ['-probed_at', '-id'],
            },
        ),
        migrations.CreateModel(
            name='CryptoProviderProfileModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True)),
                ('backend_kind', models.CharField(choices=[('pkcs11', 'PKCS#11'), ('software', 'Software'), ('rest', 'REST')], max_length=16)),
                ('active', models.BooleanField(default=False)),
                ('last_probe_status', models.CharField(choices=[('never', 'Never probed'), ('success', 'Success'), ('failure', 'Failure')], default='never', max_length=16)),
                ('last_probe_at', models.DateTimeField(blank=True, null=True)),
                ('last_probe_error', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('current_capability_snapshot', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='crypto.cryptoprovidercapabilitysnapshotmodel')),
            ],
            options={
                'db_table': 'crypto_provider_profile',
            },
        ),
        migrations.CreateModel(
            name='CryptoProviderCapabilityRestDetailModel',
            fields=[
                ('snapshot', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='rest_detail', serialize=False, to='crypto.cryptoprovidercapabilitysnapshotmodel')),
                ('snapshot_payload', models.JSONField(default=dict)),
            ],
            options={
                'db_table': 'crypto_provider_capability_rest_detail',
            },
        ),
        migrations.CreateModel(
            name='CryptoProviderCapabilitySoftwareDetailModel',
            fields=[
                ('snapshot', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='software_detail', serialize=False, to='crypto.cryptoprovidercapabilitysnapshotmodel')),
                ('snapshot_payload', models.JSONField(default=dict)),
            ],
            options={
                'db_table': 'crypto_provider_capability_software_detail',
            },
        ),
        migrations.CreateModel(
            name='CryptoProviderRestConfigModel',
            fields=[
                ('profile', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='rest_config', serialize=False, to='crypto.cryptoproviderprofilemodel')),
                ('base_url', models.URLField()),
                ('auth_type', models.CharField(choices=[('none', 'None'), ('bearer_env', 'Bearer token from environment'), ('api_key_env', 'API key from environment'), ('mtls', 'Mutual TLS')], max_length=24)),
                ('auth_ref', models.TextField(blank=True, null=True)),
                ('timeout_seconds', models.FloatField(default=5.0)),
                ('verify_tls', models.BooleanField(default=True)),
            ],
            options={
                'db_table': 'crypto_provider_rest_config',
            },
        ),
        migrations.CreateModel(
            name='CryptoProviderSoftwareConfigModel',
            fields=[
                ('profile', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='software_config', serialize=False, to='crypto.cryptoproviderprofilemodel')),
                ('encryption_source', models.CharField(choices=[('env', 'Environment variable'), ('file', 'File path'), ('dev_plaintext', 'Dev plaintext only')], default='env', max_length=24)),
                ('encryption_source_ref', models.TextField(blank=True, help_text='Environment variable name or file path containing the encryption secret.', null=True)),
                ('allow_exportable_private_keys', models.BooleanField(default=False)),
            ],
            options={
                'db_table': 'crypto_provider_software_config',
            },
        ),
        migrations.AddField(
            model_name='cryptoprovidercapabilitysnapshotmodel',
            name='profile',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='capability_snapshots', to='crypto.cryptoproviderprofilemodel'),
        ),
        migrations.CreateModel(
            name='CryptoManagedKeyModel',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('alias', models.CharField(help_text='Stable application-unique key alias.', max_length=255, unique=True)),
                ('provider_label', models.CharField(blank=True, help_text='Optional provider-side diagnostic label.', max_length=255, null=True)),
                ('algorithm', models.CharField(max_length=16)),
                ('public_key_fingerprint_sha256', models.CharField(help_text='SHA-256 fingerprint of SubjectPublicKeyInfo DER, hex encoded.', max_length=64)),
                ('signing_execution_mode', models.CharField(default='complete_backend', help_text='How Trustpoint is allowed to execute managed-key signing.', max_length=32)),
                ('policy_snapshot', models.JSONField(default=dict, help_text='Persisted summary of the key policy at creation time.')),
                ('status', models.CharField(choices=[('active', 'Active'), ('missing', 'Missing from provider'), ('mismatch', 'Public key mismatch'), ('error', 'Verification error')], default='active', max_length=16)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('last_verified_at', models.DateTimeField(blank=True, null=True)),
                ('last_verification_error', models.TextField(blank=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('provider_profile', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='managed_keys', to='crypto.cryptoproviderprofilemodel')),
            ],
            options={
                'db_table': 'crypto_managed_key',
            },
        ),
        migrations.CreateModel(
            name='CryptoManagedKeyPkcs11BindingModel',
            fields=[
                ('managed_key', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='pkcs11_binding', serialize=False, to='crypto.cryptomanagedkeymodel')),
                ('key_id_hex', models.CharField(help_text='Hex-encoded PKCS#11 CKA_ID used as the primary provider-side identity.', max_length=128)),
                ('provider_profile', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='pkcs11_key_bindings', to='crypto.cryptoproviderprofilemodel')),
            ],
            options={
                'db_table': 'crypto_managed_key_pkcs11_binding',
            },
        ),
        migrations.CreateModel(
            name='CryptoManagedKeyRestBindingModel',
            fields=[
                ('managed_key', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='rest_binding', serialize=False, to='crypto.cryptomanagedkeymodel')),
                ('remote_key_id', models.CharField(max_length=255)),
                ('remote_key_version', models.CharField(blank=True, max_length=128, null=True)),
                ('provider_profile', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='rest_key_bindings', to='crypto.cryptoproviderprofilemodel')),
            ],
            options={
                'db_table': 'crypto_managed_key_rest_binding',
            },
        ),
        migrations.CreateModel(
            name='CryptoManagedKeySoftwareBindingModel',
            fields=[
                ('managed_key', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='software_binding', serialize=False, to='crypto.cryptomanagedkeymodel')),
                ('key_handle', models.CharField(max_length=128)),
                ('encrypted_private_key_pkcs8_der', models.BinaryField()),
                ('encryption_metadata', models.JSONField(default=dict)),
                ('provider_profile', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='software_key_bindings', to='crypto.cryptoproviderprofilemodel')),
            ],
            options={
                'db_table': 'crypto_managed_key_software_binding',
            },
        ),
        migrations.CreateModel(
            name='CryptoProviderCapabilityPkcs11DetailModel',
            fields=[
                ('snapshot', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='pkcs11_detail', serialize=False, to='crypto.cryptoprovidercapabilitysnapshotmodel')),
                ('token_label', models.CharField(blank=True, max_length=128, null=True)),
                ('token_serial', models.CharField(blank=True, max_length=128, null=True)),
                ('token_model', models.CharField(blank=True, max_length=128, null=True)),
                ('token_manufacturer', models.CharField(blank=True, max_length=128, null=True)),
                ('slot_id', models.PositiveIntegerField(blank=True, null=True)),
                ('snapshot_payload', models.JSONField(default=dict)),
            ],
            options={
                'db_table': 'crypto_provider_capability_pkcs11_detail',
                'indexes': [models.Index(fields=['token_serial'], name='crypto_prov_token_s_a8cfd0_idx')],
            },
        ),
        migrations.CreateModel(
            name='CryptoProviderPkcs11ConfigModel',
            fields=[
                ('profile', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='pkcs11_config', serialize=False, to='crypto.cryptoproviderprofilemodel')),
                ('module_path', models.TextField()),
                ('token_label', models.CharField(blank=True, max_length=128, null=True)),
                ('token_serial', models.CharField(blank=True, max_length=128, null=True)),
                ('slot_id', models.PositiveIntegerField(blank=True, null=True)),
                ('auth_source', models.CharField(choices=[('env', 'Environment variable'), ('file', 'File path')], max_length=16)),
                ('auth_source_ref', models.TextField(help_text='Environment variable name or PIN file path depending on auth_source.')),
                ('max_sessions', models.PositiveIntegerField(default=8)),
                ('borrow_timeout_seconds', models.FloatField(default=5.0)),
                ('rw_sessions', models.BooleanField(default=True)),
            ],
            options={
                'db_table': 'crypto_provider_pkcs11_config',
                'indexes': [models.Index(fields=['token_serial'], name='crypto_prov_token_s_720868_idx'), models.Index(fields=['token_label'], name='crypto_prov_token_l_8de9e8_idx')],
            },
        ),
        migrations.AddIndex(
            model_name='cryptoproviderprofilemodel',
            index=models.Index(fields=['active'], name='crypto_prov_active_7f09ba_idx'),
        ),
        migrations.AddIndex(
            model_name='cryptoproviderprofilemodel',
            index=models.Index(fields=['backend_kind'], name='crypto_prov_backend_bbf2e3_idx'),
        ),
        migrations.AddIndex(
            model_name='cryptoproviderprofilemodel',
            index=models.Index(fields=['name'], name='crypto_prov_name_66fada_idx'),
        ),
        migrations.AddConstraint(
            model_name='cryptoproviderprofilemodel',
            constraint=models.UniqueConstraint(condition=models.Q(('active', True)), fields=('active',), name='crypto_single_active_provider_profile'),
        ),
        migrations.AddIndex(
            model_name='cryptoprovidercapabilitysnapshotmodel',
            index=models.Index(fields=['profile', 'probed_at'], name='crypto_prov_profile_b0c76f_idx'),
        ),
        migrations.AddIndex(
            model_name='cryptoprovidercapabilitysnapshotmodel',
            index=models.Index(fields=['profile', 'status'], name='crypto_prov_profile_d3dbe3_idx'),
        ),
        migrations.AddIndex(
            model_name='cryptomanagedkeymodel',
            index=models.Index(fields=['provider_profile', 'status'], name='crypto_mana_provide_b8a6e6_idx'),
        ),
        migrations.AddIndex(
            model_name='cryptomanagedkeymodel',
            index=models.Index(fields=['alias'], name='crypto_mana_alias_a5f06b_idx'),
        ),
        migrations.AddIndex(
            model_name='cryptomanagedkeypkcs11bindingmodel',
            index=models.Index(fields=['provider_profile', 'key_id_hex'], name='crypto_mana_provide_6d8e34_idx'),
        ),
        migrations.AddConstraint(
            model_name='cryptomanagedkeypkcs11bindingmodel',
            constraint=models.UniqueConstraint(fields=('provider_profile', 'key_id_hex'), name='crypto_pkcs11_binding_unique_profile_key_id'),
        ),
        migrations.AddIndex(
            model_name='cryptomanagedkeyrestbindingmodel',
            index=models.Index(fields=['provider_profile', 'remote_key_id'], name='crypto_mana_provide_f6228e_idx'),
        ),
        migrations.AddConstraint(
            model_name='cryptomanagedkeyrestbindingmodel',
            constraint=models.UniqueConstraint(fields=('provider_profile', 'remote_key_id', 'remote_key_version'), name='crypto_rest_binding_unique_remote_key'),
        ),
        migrations.AddIndex(
            model_name='cryptomanagedkeysoftwarebindingmodel',
            index=models.Index(fields=['provider_profile', 'key_handle'], name='crypto_mana_provide_3791e3_idx'),
        ),
        migrations.AddConstraint(
            model_name='cryptomanagedkeysoftwarebindingmodel',
            constraint=models.UniqueConstraint(fields=('provider_profile', 'key_handle'), name='crypto_software_binding_unique_profile_key_handle'),
        ),
    ]
