# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.core.validators
import django.db.models.deletion
import util.encrypted_fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0003_tp_v0_6_0'),
        ('pki', '0002_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='devicemodel',
            name='opc_gds_push_enable_periodic_update',
        ),
        migrations.RemoveField(
            model_name='devicemodel',
            name='opc_gds_push_last_update_scheduled_at',
        ),
        migrations.RemoveField(
            model_name='devicemodel',
            name='opc_gds_push_renewal_interval',
        ),
        migrations.RemoveField(
            model_name='devicemodel',
            name='opc_server_port',
        ),
        migrations.AlterField(
            model_name='devicemodel',
            name='device_type',
            field=models.IntegerField(choices=[(0, 'Generic Device'), (2, 'OPC UA GDS Push'), (3, 'Agent (1-to-1)')], default=0, verbose_name='Device Type'),
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
    ]
