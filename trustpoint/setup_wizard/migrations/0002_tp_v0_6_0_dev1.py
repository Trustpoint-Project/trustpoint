import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pki', '0002_tp_v0_6_0_dev1'),
        ('setup_wizard', '0001_tp_v0_5_0'),
    ]

    operations = [
        migrations.CreateModel(
            name='SetupWizardConfigModel',
            fields=[
                ('singleton_id', models.PositiveSmallIntegerField(default=1, editable=False, help_text='Singleton primary key. Always 1.', primary_key=True, serialize=False)),
                ('fresh_install_current_step', models.PositiveSmallIntegerField(blank=True, choices=[(0, 'Crypto-Storage'), (1, 'Backend-Config'), (2, 'Demo-Data'), (3, 'TLS-Config'), (4, 'Summary')], default=0)),
                ('fresh_install_crypto_storage_submitted', models.BooleanField(default=False, help_text='Whether the crypto storage step was submitted.')),
                ('fresh_install_backend_config_submitted', models.BooleanField(default=False, help_text='Whether the backend configuration step was submitted.')),
                ('fresh_install_demo_data_submitted', models.BooleanField(default=False, help_text='Whether the demo data step was submitted.')),
                ('fresh_install_tls_config_submitted', models.BooleanField(default=False, help_text='Whether the TLS config step was submitted.')),
                ('fresh_install_summary_submitted', models.BooleanField(default=False, help_text='Whether the summary step was submitted.')),
                ('fresh_install_tls_mode', models.CharField(choices=[('generate', 'Generate credential'), ('pkcs12', 'Upload PKCS#12'), ('separate_files', 'Upload separate files')], default='generate', help_text='Selected TLS configuration mode during the fresh-install wizard.', max_length=32)),
                ('crypto_storage', models.PositiveSmallIntegerField(choices=[(0, 'Software Storage'), (1, 'HSM Storage'), (2, 'REST Backend')], default=0)),
                ('fresh_install_pkcs11_module_path', models.TextField(blank=True, default='', help_text='Configured PKCS#11 module path staged during the fresh-install wizard.')),
                ('fresh_install_pkcs11_token_label', models.CharField(blank=True, default='', help_text='Configured PKCS#11 token label staged during the fresh-install wizard.', max_length=128)),
                ('fresh_install_pkcs11_token_serial', models.CharField(blank=True, default='', help_text='Configured PKCS#11 token serial staged during the fresh-install wizard.', max_length=128)),
                ('fresh_install_pkcs11_slot_id', models.PositiveIntegerField(blank=True, help_text='Configured PKCS#11 slot id staged during the fresh-install wizard.', null=True)),
                ('fresh_install_pkcs11_auth_source', models.CharField(choices=[('file', 'PIN file'), ('env', 'Environment variable')], default='file', help_text='How the PKCS#11 backend resolves the user PIN during the fresh-install wizard.', max_length=16)),
                ('fresh_install_pkcs11_auth_source_ref', models.TextField(blank=True, default='', help_text='PIN file path or environment variable name staged during the fresh-install wizard.')),
                ('inject_demo_data', models.BooleanField(default=True, help_text='Inject demo data.')),
                ('fresh_install_tls_credential', models.ForeignKey(blank=True, help_text='Pending TLS server credential staged during the fresh-install wizard.', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='pki.credentialmodel')),
            ],
        ),
        migrations.DeleteModel(
            name='SetupWizardConfigurationModel',
        ),
    ]
