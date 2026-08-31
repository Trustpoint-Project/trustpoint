# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.core.validators
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('devices', '0003_tp_v0_6_0'),
        ('pki', '0003_tp_v1_0_dev0'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='WebUiAutomationProfileDefinition',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text='Unique identifier for this automation workflow definition.', max_length=200, unique=True, verbose_name='Name')),
                ('profile', models.JSONField(help_text='JSON profile containing metadata, named paths, operations, steps, and postconditions.', verbose_name='Automation Profile')),
                ('checksum', models.CharField(blank=True, editable=False, max_length=64, verbose_name='Checksum')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated At')),
            ],
            options={
                'verbose_name': 'Web UI Automation Profile',
                'verbose_name_plural': 'Web UI Automation Profiles',
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='WebUiAutomationDevice',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('base_url', models.URLField(help_text='Base URL of the device management interface, e.g. https://192.168.1.10:8443.', verbose_name='Base URL')),
                ('authentication_type', models.CharField(choices=[('HTTP_BASIC', 'HTTP Basic Authentication'), ('FORM_LOGIN', 'Form-based Login')], max_length=30, verbose_name='Authentication Type')),
                ('encrypted_username', models.TextField(editable=False, verbose_name='Encrypted Username')),
                ('encrypted_password', models.TextField(editable=False, verbose_name='Encrypted Password')),
                ('encrypted_private_key_password', models.TextField(blank=True, default='', editable=False, verbose_name='Encrypted Private-Key Password')),
                ('credentials_updated_at', models.DateTimeField(blank=True, editable=False, null=True, verbose_name='Credentials Updated At')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated At')),
                ('device', models.OneToOneField(help_text='The Trustpoint device managed through Web UI automation.', on_delete=django.db.models.deletion.PROTECT, related_name='web_ui_automation', to='devices.devicemodel', verbose_name='Device')),
            ],
            options={
                'verbose_name': 'Web UI Automation Device',
                'verbose_name_plural': 'Web UI Automation Devices',
                'ordering': ['device__common_name'],
            },
        ),
        migrations.CreateModel(
            name='WebUiAutomationAssignedProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('onboarding_status', models.IntegerField(choices=[(1, 'Pending'), (2, 'Onboarded')], default=1, verbose_name='Onboarding Status')),
                ('enabled', models.BooleanField(default=True, help_text='Disabled assignments cannot be executed manually or automatically.', verbose_name='Enabled')),
                ('automatic_renewal_enabled', models.BooleanField(default=False, verbose_name='Automatic Renewal Enabled')),
                ('renewal_mode', models.CharField(choices=[('INTERVAL', 'Fixed Interval'), ('BEFORE_EXPIRY', 'Before Expiry')], default='BEFORE_EXPIRY', max_length=30, verbose_name='Renewal Mode')),
                ('renewal_days', models.PositiveIntegerField(default=30, help_text='For before-expiry mode, renew when this many days remain. For interval mode, renew this many days after the last successful update.', validators=[django.core.validators.MinValueValidator(1)], verbose_name='Renewal Days')),
                ('last_certificate_update', models.DateTimeField(blank=True, null=True, verbose_name='Last Certificate Update')),
                ('next_certificate_update_scheduled', models.DateTimeField(blank=True, help_text='Optional one-time scheduling override. This takes precedence over the calculated date.', null=True, verbose_name='Next Certificate Update')),
                ('confirmed_profile_checksum', models.CharField(blank=True, max_length=64, verbose_name='Confirmed Profile Checksum')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated At')),
                ('issued_credential', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='web_ui_automation_assignment', to='pki.issuedcredentialmodel', verbose_name='Issued Credential')),
                ('automation_device', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='assigned_profiles', to='web_ui_automation.webuiautomationdevice', verbose_name='Web UI Automation Device')),
                ('workflow_definition', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assigned_to', to='web_ui_automation.webuiautomationprofiledefinition', verbose_name='Automation Profile')),
            ],
            options={
                'verbose_name': 'Assigned Web UI Automation Profile',
                'verbose_name_plural': 'Assigned Web UI Automation Profiles',
                'ordering': ['automation_device__device__common_name', 'workflow_definition__name'],
            },
        ),
        migrations.CreateModel(
            name='WebUiAutomationJob',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('operation', models.CharField(choices=[('onboard', 'Onboard'), ('renew', 'Renew'), ('inventory', 'Inventory')], max_length=20, verbose_name='Operation')),
                ('status', models.CharField(choices=[('QUEUED', 'Queued'), ('RUNNING', 'Running'), ('AWAITING_CONFIRMATION', 'Awaiting Confirmation'), ('COMPLETED', 'Completed'), ('FAILED', 'Failed')], default='QUEUED', max_length=30, verbose_name='Status')),
                ('result', models.CharField(choices=[('NONE', 'No Result'), ('SUCCESSFUL', 'Successful'), ('PARTIALLY_SUCCESSFUL', 'Partially Successful'), ('FAILED', 'Failed')], default='NONE', max_length=30, verbose_name='Result')),
                ('verification_status', models.CharField(choices=[('NOT_CONFIGURED', 'Not Configured'), ('PASSED', 'Passed'), ('PARTIAL', 'Partially Passed'), ('FAILED', 'Failed')], default='NOT_CONFIGURED', max_length=30, verbose_name='Verification Status')),
                ('profile_snapshot', models.JSONField(verbose_name='Profile Snapshot')),
                ('profile_checksum', models.CharField(max_length=64, verbose_name='Profile Checksum')),
                ('is_automatic', models.BooleanField(default=False, verbose_name='Automatic Job')),
                ('failed_step_id', models.CharField(blank=True, max_length=120, verbose_name='Failed Step ID')),
                ('failure_category', models.CharField(blank=True, max_length=80, verbose_name='Failure Category')),
                ('error_message', models.TextField(blank=True, verbose_name='Error Message')),
                ('started_at', models.DateTimeField(blank=True, null=True, verbose_name='Started At')),
                ('finished_at', models.DateTimeField(blank=True, null=True, verbose_name='Finished At')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('assignment', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='jobs', to='web_ui_automation.webuiautomationassignedprofile', verbose_name='Assigned Profile')),
                ('candidate_certificate', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='web_ui_automation_jobs', to='pki.certificatemodel', verbose_name='Candidate Certificate')),
                ('initiated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='web_ui_automation_jobs', to=settings.AUTH_USER_MODEL, verbose_name='Initiated By')),
            ],
            options={
                'verbose_name': 'Web UI Automation Job',
                'verbose_name_plural': 'Web UI Automation Jobs',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='WebUiAutomationStepLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sequence', models.PositiveIntegerField(verbose_name='Sequence')),
                ('step_id', models.CharField(max_length=120, verbose_name='Step ID')),
                ('action', models.CharField(max_length=80, verbose_name='Action')),
                ('status', models.CharField(choices=[('RUNNING', 'Running'), ('SUCCESSFUL', 'Successful'), ('SKIPPED', 'Skipped'), ('FAILED', 'Failed')], default='RUNNING', max_length=20, verbose_name='Status')),
                ('message', models.TextField(blank=True, verbose_name='Message')),
                ('details', models.JSONField(blank=True, default=dict, verbose_name='Details')),
                ('started_at', models.DateTimeField(auto_now_add=True, verbose_name='Started At')),
                ('finished_at', models.DateTimeField(blank=True, null=True, verbose_name='Finished At')),
                ('job', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='step_logs', to='web_ui_automation.webuiautomationjob', verbose_name='Job')),
            ],
            options={
                'verbose_name': 'Web UI Automation Step Log',
                'verbose_name_plural': 'Web UI Automation Step Logs',
                'ordering': ['sequence'],
            },
        ),
        migrations.AddConstraint(
            model_name='webuiautomationassignedprofile',
            constraint=models.UniqueConstraint(fields=('automation_device', 'workflow_definition'), name='unique_webui_profile_per_device'),
        ),
        migrations.AddConstraint(
            model_name='webuiautomationsteplog',
            constraint=models.UniqueConstraint(fields=('job', 'sequence'), name='unique_webui_step_sequence'),
        ),
    ]
