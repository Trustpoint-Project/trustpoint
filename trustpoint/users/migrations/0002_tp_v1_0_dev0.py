# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.core.validators
import django.db.models.deletion
import users.models
import util.encrypted_fields
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pki', '0003_tp_v1_0_dev0'),
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='apppermission',
            options={'default_permissions': (), 'managed': False, 'permissions': [('manage_users', 'Can manage users'), ('manage_roles', 'Can manage roles'), ('manage_organizations', 'Can manage organizations'), ('manage_service_accounts', 'Can manage service accounts'), ('use_rest_api', 'Can use the REST API'), ('manage_cas', 'Can manage certificate authorities'), ('manage_ras', 'Can manage registration authorities'), ('manage_domains', 'Can manage domains'), ('manage_truststores', 'Can manage trust stores'), ('manage_certificate_profiles', 'Can manage certificate profiles'), ('manage_crypto_backends', 'Can manage cryptographic backends'), ('issue_certificates', 'Can issue certificates'), ('revoke_certificates', 'Can revoke certificates'), ('download_credentials', 'Can download private credentials'), ('view_help_pages', 'Can view help pages'), ('manage_devices', 'Can manage devices'), ('manage_certificate_discovery', 'Can manage certificate discovery'), ('manage_signer', 'Can manage signer'), ('manage_workflows', 'Can manage workflows'), ('approve_workflows', 'Can approve workflows'), ('manage_system_configuration', 'Can manage system configuration'), ('manage_security_configuration', 'Can manage security configuration'), ('manage_backups', 'Can manage backups'), ('manage_notifications', 'Can manage notification settings'), ('manage_tls_webserver_configuration', 'Can manage TLS webserver configuration'), ('view_audit_log', 'Can view the audit log'), ('view_system_logs', 'Can view system logs'), ('view_metrics', 'Can view system metrics')]},
        ),
        migrations.AddField(
            model_name='groupprofile',
            name='is_builtin',
            field=models.BooleanField(default=False, help_text='Identifies a role provided by Trustpoint.', verbose_name='built-in role'),
        ),
        migrations.AddField(
            model_name='groupprofile',
            name='is_deletion_protected',
            field=models.BooleanField(default=False, help_text='Prevents the role from being deleted.', verbose_name='deletion-protected role'),
        ),
        migrations.AddField(
            model_name='groupprofile',
            name='is_modification_protected',
            field=models.BooleanField(default=False, help_text='Prevents the role from being modified.', verbose_name='modification-protected role'),
        ),
        migrations.AddField(
            model_name='trustpointuser',
            name='account_type',
            field=models.CharField(choices=[('HUMAN', 'Human'), ('SERVICE', 'Service')], default='HUMAN', help_text='Human accounts have interactive Web UI login; service accounts use API credentials or mTLS.', max_length=10, verbose_name='account type'),
        ),
        migrations.CreateModel(
            name='UserClientCertificate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('certificate', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='user_client_certificate', to='pki.certificatemodel', verbose_name='client certificate')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='client_certificates', to=settings.AUTH_USER_MODEL, verbose_name='user')),
            ],
            options={
                'verbose_name': 'user client certificate',
                'verbose_name_plural': 'user client certificates',
            },
        ),
        migrations.CreateModel(
            name='UserOTPDevice',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('throttling_failure_timestamp', models.DateTimeField(blank=True, default=None, help_text='A timestamp of the last failed verification attempt. Null if last attempt succeeded.', null=True)),
                ('throttling_failure_count', models.PositiveIntegerField(default=0, help_text='Number of successive failed attempts.')),
                ('created_at', models.DateTimeField(auto_now_add=True, help_text='The date and time when this device was initially created in the system.', null=True)),
                ('last_used_at', models.DateTimeField(blank=True, help_text='The most recent date and time this device was used.', null=True)),
                ('name', models.CharField(default='Authenticator', max_length=64)),
                ('key', util.encrypted_fields.EncryptedTextField(default=users.models.new_otp_key, editable=False, validators=[django.core.validators.RegexValidator('\\A[0-9a-f]{40}\\Z', 'Invalid OTP secret.')])),
                ('confirmed', models.BooleanField(default=False, editable=False)),
                ('last_t', models.BigIntegerField(default=-1, editable=False)),
                ('user', models.ForeignKey(limit_choices_to={'account_type': 'HUMAN'}, on_delete=django.db.models.deletion.CASCADE, related_name='otp_devices', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='UserOTPRecoveryCode',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code_hash', models.CharField(editable=False, max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('used_at', models.DateTimeField(blank=True, editable=False, null=True)),
                ('device', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='recovery_codes', to='users.userotpdevice')),
            ],
        ),
        migrations.CreateModel(
            name='ServiceAccountCredential',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('client_id', models.CharField(help_text='Unique identifier for API key authentication.', max_length=255, unique=True, verbose_name='client ID')),
                ('hashed_secret', models.CharField(help_text='Hashed API secret for API key authentication.', max_length=255, verbose_name='hashed secret')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='created at')),
                ('expires_at', models.DateTimeField(blank=True, help_text='Optional expiration date for the credential.', null=True, verbose_name='expires at')),
                ('last_used', models.DateTimeField(blank=True, null=True, verbose_name='last used')),
                ('usage_count', models.PositiveIntegerField(default=0, help_text='Number of times this credential has been used for authentication.', verbose_name='usage count')),
                ('is_active', models.BooleanField(default=True, help_text='Deactivate to revoke access without deleting the credential.', verbose_name='active')),
                ('description', models.TextField(blank=True, help_text='Optional description of this credential.', verbose_name='description')),
                ('service_account', models.ForeignKey(limit_choices_to={'account_type': 'SERVICE'}, on_delete=django.db.models.deletion.CASCADE, related_name='service_credentials', to=settings.AUTH_USER_MODEL, verbose_name='service account')),
            ],
            options={
                'verbose_name': 'service account credential',
                'verbose_name_plural': 'service account credentials',
                'indexes': [models.Index(fields=['client_id'], name='users_servi_client__3dcb30_idx'), models.Index(fields=['service_account', 'is_active'], name='users_servi_service_1c6986_idx')],
            },
        ),
        migrations.AddConstraint(
            model_name='userotpdevice',
            constraint=models.UniqueConstraint(fields=('user',), name='unique_user_otp_device'),
        ),
        migrations.AddConstraint(
            model_name='userotpdevice',
            constraint=models.CheckConstraint(condition=models.Q(('last_t__gte', -1)), name='user_otp_valid_last_t'),
        ),
        migrations.AddConstraint(
            model_name='userotpdevice',
            constraint=models.CheckConstraint(condition=models.Q(('confirmed', False), ('last_t__gte', 0), _connector='OR'), name='user_otp_confirmed_has_verified_token'),
        ),
        migrations.AddConstraint(
            model_name='userotprecoverycode',
            constraint=models.UniqueConstraint(fields=('device', 'code_hash'), name='unique_user_otp_recovery_code'),
        ),
    ]
