# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='apppermission',
            options={'default_permissions': (), 'permissions': (('manage_workflow', 'Can manage workflow'), ('onboard_device', 'Can onboard device'), ('manage_ca', 'Can manage CA'), ('manage_role', 'Can manage role'), ('use_rest_api', 'Can use REST API'))},
        ),
        migrations.AddField(
            model_name='trustpointuser',
            name='account_type',
            field=models.CharField(choices=[('HUMAN', 'Human'), ('SERVICE', 'Service')], default='HUMAN', help_text='Human accounts have interactive Web UI login; service accounts use API credentials or mTLS.', max_length=10, verbose_name='account type'),
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
    ]
