# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.core.validators
import django.db.models.deletion
import util.encrypted_fields
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):


    initial = True

    dependencies = [
        ('onboarding', '0001_initial'),
        ('pki', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='DeviceModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('common_name', models.CharField(default='', max_length=100, unique=True, verbose_name='Device')),
                ('serial_number', models.CharField(blank=True, default='', max_length=100, verbose_name='Serial-Number')),
                ('rfc_4122_uuid', models.UUIDField(default=uuid.uuid4, editable=False, help_text='RFC 4122 version 4 UUID uniquely identifying this device. Auto-generated on device creation and immutable thereafter.', unique=True, verbose_name='Device UUID')),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True, unpack_ipv4=True, verbose_name='IP Address')),
                ('device_type', models.IntegerField(choices=[(0, 'Generic Device'), (2, 'OPC UA GDS Push'), (3, 'Agent (1-to-1)')], default=0, verbose_name='Device Type')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created')),
                ('domain', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='devices', to='pki.domainmodel', verbose_name='Domain')),
                ('no_onboarding_config', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='device', to='onboarding.noonboardingconfigmodel', verbose_name='No Onboarding Config')),
                ('onboarding_config', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='device', to='onboarding.onboardingconfigmodel', verbose_name='Onboarding Config')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='OpcUaGdsPushConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('opc_server_port', models.PositiveIntegerField(default=4840, validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(65535)], verbose_name='OPC Server Port')),
                ('opc_user', models.CharField(blank=True, default='', max_length=128, verbose_name='OPC User')),
                ('opc_password', util.encrypted_fields.EncryptedCharField(blank=True, default='', max_length=128, verbose_name='OPC Password')),
                ('opc_gds_push_enable_periodic_update', models.BooleanField(blank=True, default=False, help_text='When enabled, the server certificate and trustlist will be automatically renewed at the specified interval.', verbose_name='Enable Periodic Certificate and Trustlist Update')),
                ('opc_gds_push_renewal_interval', models.PositiveIntegerField(blank=True, default=168, help_text='Number of hours between each automatic server certificate and trustlist renewal. Minimum 1 hour.', verbose_name='Renewal Interval (hours)')),
                ('opc_gds_push_last_update_scheduled_at', models.DateTimeField(blank=True, help_text='Timestamp of the most recent scheduled periodic server certificate and trustlist update.', null=True, verbose_name='Last Periodic Update Scheduled At')),
                ('opc_gds_push_enable_domain_credential_renewal', models.BooleanField(blank=True, default=False, help_text='Automatically replace the GDS Push domain credential and revoke its predecessor.', verbose_name='Enable Periodic Domain Credential Renewal')),
                ('opc_gds_push_domain_credential_renewal_interval', models.PositiveIntegerField(default=168, help_text='Number of hours between automatic domain credential renewals. Minimum 1 hour.', verbose_name='Domain Credential Renewal Interval (hours)')),
                ('opc_gds_push_domain_credential_next_renewal_at', models.DateTimeField(blank=True, null=True, verbose_name='Next Domain Credential Renewal')),
                ('device', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='opc_ua_gds_push_config', to='devices.devicemodel')),
                ('opc_trust_store', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='opc_ua_gds_push_configs', to='pki.truststoremodel', verbose_name='OPC Server Truststore')),
            ],
        ),
        migrations.CreateModel(
            name='RemoteDeviceCredentialDownloadModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('otp', models.CharField(default='', max_length=32, verbose_name='OTP')),
                ('attempts', models.IntegerField(default=0, verbose_name='Attempts')),
                ('download_token', models.CharField(default='', max_length=64, verbose_name='Download Token')),
                ('token_created_at', models.DateTimeField(null=True, verbose_name='Token Created')),
                ('device', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='devices.devicemodel')),
                ('issued_credential_model', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='pki.issuedcredentialmodel')),
            ],
        ),
    ]
