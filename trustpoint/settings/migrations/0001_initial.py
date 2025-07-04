# Generated by Django 5.1.9 on 2025-06-18 11:31

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('notifications', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='AppVersion',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('version', models.CharField(max_length=17)),
                ('last_updated', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'App Version',
            },
        ),
        migrations.CreateModel(
            name='BackupOptions',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('host', models.CharField(max_length=255, verbose_name='Host')),
                ('port', models.PositiveIntegerField(default=2222, verbose_name='Port')),
                ('user', models.CharField(max_length=128, verbose_name='Username')),
                ('local_storage', models.BooleanField(default=True, verbose_name='Use local storage')),
                ('auth_method', models.CharField(choices=[('password', 'Password'), ('ssh_key', 'SSH Key')], max_length=10, verbose_name='Authentication Method')),
                ('password', models.CharField(blank=True, help_text='Plain‐text password for SFTP.', max_length=128, verbose_name='Password')),
                ('private_key', models.TextField(blank=True, help_text='Paste the private key here (PEM).', verbose_name='SSH Private Key (PEM format)')),
                ('key_passphrase', models.CharField(blank=True, help_text='Passphrase for the private key, if any.', max_length=128, verbose_name='Key Passphrase')),
                ('remote_directory', models.CharField(blank=True, default='/upload/trustpoint/', help_text='Remote directory (e.g. /backups/) where files should be uploaded. Trailing slash is optional.', max_length=512, verbose_name='Remote Directory')),
            ],
        ),
        migrations.CreateModel(
            name='TlsSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ipv4_address', models.GenericIPAddressField(blank=True, null=True, protocol='IPv4')),
            ],
        ),
        migrations.CreateModel(
            name='SecurityConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('security_mode', models.CharField(choices=[('0', 'Testing env'), ('1', 'Basic'), ('2', 'Medium'), ('3', 'High'), ('4', 'Highest')], default='1', max_length=6)),
                ('auto_gen_pki', models.BooleanField(default=False)),
                ('auto_gen_pki_key_algorithm', models.CharField(choices=[('RSA2048SHA256', 'RSA2048'), ('RSA4096SHA256', 'RSA4096'), ('SECP256R1SHA256', 'SECP256R1')], default='RSA2048SHA256', max_length=24)),
                ('notification_config', models.OneToOneField(help_text='Notification configuration associated with this security level.', null=True, on_delete=django.db.models.deletion.CASCADE, related_name='security_config', to='notifications.notificationconfig')),
            ],
        ),
    ]
