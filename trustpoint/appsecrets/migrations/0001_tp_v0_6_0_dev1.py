import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AppSecretBackendModel',
            fields=[
                ('singleton_id', models.PositiveSmallIntegerField(default=1, editable=False, help_text='Singleton primary key. Always 1.', primary_key=True, serialize=False)),
                ('backend_kind', models.CharField(choices=[('pkcs11', 'PKCS#11'), ('software', 'Software')], max_length=16)),
            ],
            options={
                'db_table': 'app_secret_backend',
            },
        ),
        migrations.CreateModel(
            name='AppSecretPkcs11ConfigModel',
            fields=[
                ('backend', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='pkcs11_config', serialize=False, to='appsecrets.appsecretbackendmodel')),
                ('module_path', models.TextField()),
                ('token_label', models.CharField(blank=True, max_length=128, null=True)),
                ('token_serial', models.CharField(blank=True, max_length=128, null=True)),
                ('slot_id', models.PositiveIntegerField(blank=True, null=True)),
                ('auth_source', models.CharField(choices=[('file', 'PIN file'), ('env', 'Environment variable')], max_length=16)),
                ('auth_source_ref', models.TextField(help_text='Environment variable name or PIN file path depending on auth_source.')),
                ('kek_label', models.CharField(default='trustpoint-app-secret-kek', max_length=128)),
                ('wrapped_dek', models.BinaryField(blank=True, help_text='DEK wrapped by the HSM KEK.', null=True)),
                ('backup_encrypted_dek', models.BinaryField(blank=True, help_text='Reserved for password-based DEK backup protection.', null=True)),
            ],
            options={
                'db_table': 'app_secret_pkcs11_config',
            },
        ),
        migrations.CreateModel(
            name='AppSecretSoftwareConfigModel',
            fields=[
                ('backend', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='software_config', serialize=False, to='appsecrets.appsecretbackendmodel')),
                ('raw_dek', models.BinaryField(blank=True, help_text='Development-only DEK storage.', null=True)),
            ],
            options={
                'db_table': 'app_secret_software_config',
            },
        ),
    ]
