# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0002_tp_v1_0_dev0'),
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
            name='is_protected',
            field=models.BooleanField(default=False, help_text='Prevents the role from being modified or deleted.', verbose_name='protected role'),
        ),
    ]
