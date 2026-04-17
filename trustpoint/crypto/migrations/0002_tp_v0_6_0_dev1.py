import django.db.models.deletion
import django.utils.timezone
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('crypto', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='CryptoManagedKeyModel',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('alias', models.CharField(help_text='Stable Trustpoint application-facing key alias.', max_length=255, unique=True)),
                ('key_id_hex', models.CharField(help_text='Hex-encoded PKCS#11 CKA_ID used as the primary provider-side identity.', max_length=128)),
                ('label', models.CharField(blank=True, help_text='Optional human-readable PKCS#11 label.', max_length=255, null=True)),
                ('algorithm', models.CharField(max_length=16)),
                ('public_key_fingerprint_sha256', models.CharField(help_text='SHA-256 fingerprint of SubjectPublicKeyInfo DER, hex encoded.', max_length=64)),
                ('policy_snapshot', models.JSONField(default=dict, help_text='Persisted summary of the key policy at creation time.')),
                ('status', models.CharField(choices=[('active', 'Active'), ('missing', 'Missing from provider'), ('mismatch', 'Public key mismatch'), ('error', 'Verification error')], default='active', max_length=16)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('last_verified_at', models.DateTimeField(blank=True, null=True)),
                ('last_verification_error', models.TextField(blank=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'crypto_managed_key',
            },
        ),
        migrations.RenameIndex(
            model_name='cryptoprovidercapabilitysnapshotmodel',
            new_name='crypto_prov_profile_b0c76f_idx',
            old_name='crypto_capa_profile_34a5e4_idx',
        ),
        migrations.RenameIndex(
            model_name='cryptoprovidercapabilitysnapshotmodel',
            new_name='crypto_prov_profile_d3dbe3_idx',
            old_name='crypto_capa_profile_8981a4_idx',
        ),
        migrations.RenameIndex(
            model_name='cryptoprovidercapabilitysnapshotmodel',
            new_name='crypto_prov_token_s_dcf1e8_idx',
            old_name='crypto_capa_token_s_1124d1_idx',
        ),
        migrations.RenameIndex(
            model_name='cryptoproviderprofilemodel',
            new_name='crypto_prov_active_7f09ba_idx',
            old_name='crypto_prov_active_1f7151_idx',
        ),
        migrations.RenameIndex(
            model_name='cryptoproviderprofilemodel',
            new_name='crypto_prov_name_66fada_idx',
            old_name='crypto_prov_name_6da1e9_idx',
        ),
        migrations.RenameIndex(
            model_name='cryptoproviderprofilemodel',
            new_name='crypto_prov_token_s_f2cce0_idx',
            old_name='crypto_prov_token_s_1b1624_idx',
        ),
        migrations.AlterField(
            model_name='cryptoproviderprofilemodel',
            name='auth_source',
            field=models.CharField(choices=[('env', 'Environment variable'), ('file', 'File path')], max_length=16),
        ),
        migrations.AlterField(
            model_name='cryptoproviderprofilemodel',
            name='auth_source_ref',
            field=models.TextField(help_text='Environment variable name or PIN file path depending on auth_source.'),
        ),
        migrations.AddField(
            model_name='cryptomanagedkeymodel',
            name='provider_profile',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='managed_keys', to='crypto.cryptoproviderprofilemodel'),
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
            model_name='cryptomanagedkeymodel',
            index=models.Index(fields=['key_id_hex'], name='crypto_mana_key_id__47f4a8_idx'),
        ),
        migrations.AddConstraint(
            model_name='cryptomanagedkeymodel',
            constraint=models.UniqueConstraint(fields=('provider_profile', 'key_id_hex'), name='crypto_managed_key_unique_profile_key_id'),
        ),
    ]
