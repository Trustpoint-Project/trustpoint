# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('devices', '0002_tp_v1_0_1'),
    ]

    operations = [
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_regenerate_server_key',
            field=models.BooleanField(
                default=False,
                help_text=(
                    'Generate a new private key on the server for each certificate renewal. '
                    'Disabled by default so secure elements and non-exportable keys are reused.'
                ),
                verbose_name='Generate New Server Key on Renewal',
            ),
        ),
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_max_trustlist_element_size',
            field=models.PositiveIntegerField(
                default=0,
                help_text='Maximum size of one DER-encoded certificate or CRL in a pushed trust list. 0 means no limit.',
                verbose_name='Maximum Trust-List Element Size (bytes)',
            ),
        ),
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_max_trustlist_entries',
            field=models.PositiveIntegerField(
                default=0,
                help_text='Maximum number of unique certificates and CRLs in a pushed trust list. 0 means no limit. Set this for devices with fixed trust-list capacity.',
                verbose_name='Maximum Trust-List Entries',
            ),
        ),
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_require_crls',
            field=models.BooleanField(
                default=True,
                help_text='Reject a trust-list update when a CA in the chain has no CRL.',
                verbose_name='Require CRLs in Pushed Trust Lists',
            ),
        ),
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_server_url',
            field=models.CharField(
                blank=True,
                default='',
                help_text='Optional full endpoint URL (opc.tcp://host:port/path). Overrides the IP address and port.',
                max_length=255,
                verbose_name='OPC Server URL',
            ),
        ),
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_renewal_threshold_days',
            field=models.PositiveIntegerField(
                default=30,
                help_text='Only replace the server certificate in the periodic task when it expires within this many days. The trust list is still refreshed each cycle.',
                verbose_name='Certificate Renewal Threshold (days)',
            ),
        ),
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_certificate_inventory',
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text='Certificate groups, trust lists and rejected certificates read from the device.',
                verbose_name='Last Certificate Inventory',
            ),
        ),
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_certificate_inventory_updated_at',
            field=models.DateTimeField(blank=True, null=True, verbose_name='Certificate Inventory Updated At'),
        ),
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_server_validation',
            field=models.CharField(
                choices=[
                    ('pinned', 'Pinned leaf certificate (truststore order 0)'),
                    ('ca', 'CA chain validation (truststore CA certificates)'),
                ],
                default='pinned',
                help_text='Pinned validation requires the exact server certificate at truststore order 0. CA validation reads the current server certificate and accepts it when it chains to a CA in the truststore, which allows certificate rotation.',
                max_length=16,
                verbose_name='Server Certificate Validation',
            ),
        ),
        migrations.CreateModel(
            name='GdsPushOperationLock',
            fields=[
                (
                    'device',
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        primary_key=True,
                        related_name='gds_push_operation_lock',
                        serialize=False,
                        to='devices.devicemodel',
                    ),
                ),
                ('acquired_at', models.DateTimeField()),
                ('expires_at', models.DateTimeField()),
            ],
        ),
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_trustlist_mode',
            field=models.CharField(
                choices=[
                    ('managed', 'Managed (preserve external entries)'),
                    ('authoritative', 'Authoritative (replace targeted lists)'),
                ],
                default='managed',
                help_text='Managed preserves entries Trustpoint does not own and prunes only its own obsolete entries. Authoritative replaces the targeted TrustLists with the configured desired state.',
                max_length=16,
                verbose_name='Trust-List Management Mode',
            ),
        ),
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_additional_trust_store',
            field=models.ForeignKey(
                blank=True,
                help_text='Optional certificates added to the desired TrustList in both management modes.',
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='opc_ua_gds_push_additional_configs',
                to='pki.truststoremodel',
                verbose_name='Additional Trust Material',
            ),
        ),
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_managed_trustlist_state',
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text='Per certificate group SHA-256 fingerprints of Trustpoint-managed certificates and CRLs that were successfully deployed.',
                verbose_name='Managed Trust-List State',
            ),
        ),
    ]
