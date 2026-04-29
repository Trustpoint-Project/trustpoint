from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('setup_wizard', '0002_tp_v0_6_0_dev1'),
    ]

    operations = [
        migrations.AlterField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_current_step',
            field=models.PositiveSmallIntegerField(
                blank=True,
                choices=[
                    (0, 'Admin User'),
                    (1, 'Database'),
                    (2, 'Crypto-Storage'),
                    (3, 'Backend-Config'),
                    (4, 'Demo-Data'),
                    (5, 'TLS-Config'),
                    (6, 'Summary'),
                ],
                default=0,
            ),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_admin_user_submitted',
            field=models.BooleanField(
                default=False,
                help_text='Whether the operational admin-user step was submitted.',
            ),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_database_submitted',
            field=models.BooleanField(
                default=False,
                help_text='Whether the operational database step was submitted.',
            ),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='operational_admin_username',
            field=models.CharField(
                blank=True,
                default='admin',
                help_text='Username for the first operational administrator.',
                max_length=150,
            ),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='operational_admin_email',
            field=models.EmailField(
                blank=True,
                default='',
                help_text='Email address for the first operational administrator.',
                max_length=254,
            ),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='operational_admin_password_hash',
            field=models.CharField(
                blank=True,
                default='',
                help_text='Hashed password for the first operational administrator.',
                max_length=256,
            ),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='operational_db_host',
            field=models.CharField(
                blank=True,
                default='postgres',
                help_text='Operational PostgreSQL host name or IP address.',
                max_length=255,
            ),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='operational_db_port',
            field=models.PositiveIntegerField(
                default=5432,
                help_text='Operational PostgreSQL TCP port.',
            ),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='operational_db_name',
            field=models.CharField(
                blank=True,
                default='trustpoint_db',
                help_text='Operational PostgreSQL database name.',
                max_length=128,
            ),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='operational_db_user',
            field=models.CharField(
                blank=True,
                default='admin',
                help_text='Operational PostgreSQL user name.',
                max_length=128,
            ),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='operational_db_password',
            field=models.CharField(
                blank=True,
                default='',
                help_text='Operational PostgreSQL password.',
                max_length=256,
            ),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='operational_config_applied',
            field=models.BooleanField(
                default=False,
                help_text='Whether the bootstrap configuration was applied to the operational runtime.',
            ),
        ),
        migrations.RemoveField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_tls_credential',
        ),
    ]
