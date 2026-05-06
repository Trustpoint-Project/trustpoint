from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('setup_wizard', '0001_tp_v0_5_0'),
    ]

    operations = [
        migrations.CreateModel(
            name='SetupWizardConfigModel',
            fields=[
                ('singleton_id', models.PositiveSmallIntegerField(default=1, editable=False, help_text='Singleton primary key. Always 1.', primary_key=True, serialize=False)),
                ('fresh_install_current_step', models.PositiveSmallIntegerField(blank=True, choices=[(0, 'Admin User'), (1, 'Database'), (2, 'Crypto-Storage'), (3, 'Backend-Config'), (4, 'Demo-Data'), (5, 'TLS-Config'), (6, 'Summary')], default=0)),
                ('fresh_install_admin_user_submitted', models.BooleanField(default=False, help_text='Whether the operational admin-user step was submitted.')),
                ('fresh_install_database_submitted', models.BooleanField(default=False, help_text='Whether the operational database step was submitted.')),
                ('fresh_install_crypto_storage_submitted', models.BooleanField(default=False, help_text='Whether the crypto storage step was submitted.')),
                ('fresh_install_backend_config_submitted', models.BooleanField(default=False, help_text='Whether the backend configuration step was submitted.')),
                ('fresh_install_demo_data_submitted', models.BooleanField(default=False, help_text='Whether the demo data step was submitted.')),
                ('fresh_install_tls_config_submitted', models.BooleanField(default=False, help_text='Whether the TLS config step was submitted.')),
                ('fresh_install_summary_submitted', models.BooleanField(default=False, help_text='Whether the summary step was submitted.')),
                ('fresh_install_tls_mode', models.CharField(choices=[('generate', 'Generate credential'), ('pkcs12', 'Upload PKCS#12'), ('separate_files', 'Upload separate files')], default='generate', help_text='Selected TLS configuration mode during the fresh-install wizard.', max_length=32)),
                ('operational_admin_username', models.CharField(blank=True, default='admin', help_text='Username for the first operational administrator.', max_length=150)),
                ('operational_admin_email', models.EmailField(blank=True, default='', help_text='Email address for the first operational administrator.', max_length=254)),
                ('operational_admin_password_hash', models.CharField(blank=True, default='', help_text='Hashed password for the first operational administrator.', max_length=256)),
                ('operational_db_host', models.CharField(blank=True, default='postgres', help_text='Operational PostgreSQL host name or IP address.', max_length=255)),
                ('operational_db_port', models.PositiveIntegerField(default=5432, help_text='Operational PostgreSQL TCP port.')),
                ('operational_db_name', models.CharField(blank=True, default='trustpoint_db', help_text='Operational PostgreSQL database name.', max_length=128)),
                ('operational_db_user', models.CharField(blank=True, default='admin', help_text='Operational PostgreSQL user name.', max_length=128)),
                ('operational_db_password', models.CharField(blank=True, default='', help_text='Operational PostgreSQL password.', max_length=256)),
                ('operational_config_applied', models.BooleanField(default=False, help_text='Whether the bootstrap configuration was applied to the operational runtime.')),
                ('crypto_storage', models.PositiveSmallIntegerField(choices=[(0, 'Software Storage'), (1, 'HSM Storage'), (2, 'REST Backend')], default=0)),
                ('fresh_install_pkcs11_module_path', models.TextField(blank=True, default='', help_text='Configured PKCS#11 module path staged during the fresh-install wizard.')),
                ('fresh_install_pkcs11_token_label', models.CharField(blank=True, default='', help_text='Configured PKCS#11 token label staged during the fresh-install wizard.', max_length=128)),
                ('fresh_install_pkcs11_token_serial', models.CharField(blank=True, default='', help_text='Configured PKCS#11 token serial staged during the fresh-install wizard.', max_length=128)),
                ('fresh_install_pkcs11_slot_id', models.PositiveIntegerField(blank=True, help_text='Configured PKCS#11 slot id staged during the fresh-install wizard.', null=True)),
                ('fresh_install_pkcs11_auth_source', models.CharField(choices=[('file', 'PIN file'), ('env', 'Environment variable')], default='file', help_text='How the PKCS#11 backend resolves the user PIN during the fresh-install wizard.', max_length=16)),
                ('fresh_install_pkcs11_auth_source_ref', models.TextField(blank=True, default='', help_text='PIN file path or environment variable name staged during the fresh-install wizard.')),
                ('fresh_install_pkcs11_config_path', models.TextField(blank=True, default='', help_text='Optional vendor PKCS#11 configuration file staged during the fresh-install wizard.')),
                ('fresh_install_pkcs11_config_env_var', models.CharField(blank=True, default='', help_text='Environment variable that points the PKCS#11 library to the vendor configuration file.', max_length=128)),
                ('inject_demo_data', models.BooleanField(default=True, help_text='Inject demo data.')),
            ],
        ),
        migrations.DeleteModel(
            name='SetupWizardConfigurationModel',
        ),
    ]
