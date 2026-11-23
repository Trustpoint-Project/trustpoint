# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import util.encrypted_fields
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('agents', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='agentassignedprofile',
            name='claim_token',
            field=models.UUIDField(
                blank=True,
                editable=False,
                help_text='Token the agent must return when acknowledging the claimed job.',
                null=True,
                verbose_name='Claim Token',
            ),
        ),
        migrations.AddField(
            model_name='agentassignedprofile',
            name='claimed_at',
            field=models.DateTimeField(
                blank=True,
                help_text='Set while an agent is executing this job. Expired claims are retried.',
                null=True,
                verbose_name='Claimed At',
            ),
        ),
        migrations.AddField(
            model_name='agentassignedprofile',
            name='failure_count',
            field=models.PositiveIntegerField(
                default=0,
                help_text='Consecutive failed attempts. Reset after a successful renewal.',
                verbose_name='Failure Count',
            ),
        ),
        migrations.AddField(
            model_name='agentassignedprofile',
            name='last_attempt_at',
            field=models.DateTimeField(
                blank=True,
                help_text='Timestamp of the most recent job execution attempt.',
                null=True,
                verbose_name='Last Attempt',
            ),
        ),
        migrations.AddField(
            model_name='agentassignedprofile',
            name='last_error',
            field=models.TextField(
                blank=True,
                default='',
                help_text='Most recent failure reported by the agent.',
                verbose_name='Last Error',
            ),
        ),
        migrations.AddField(
            model_name='agentprofiledefinition',
            name='secrets',
            field=util.encrypted_fields.EncryptedJSONField(
                blank=True,
                default=None,
                help_text='Optional JSON object of secret values, stored encrypted. Reference values from steps with {{ secret:name }}. Do not put passwords in the profile JSON.',
                null=True,
                verbose_name='Secret Values',
            ),
        ),
        migrations.AlterField(
            model_name='agentassignedprofile',
            name='next_certificate_update_scheduled',
            field=models.DateTimeField(
                blank=True,
                help_text='Manually scheduled next renewal trigger time. Set to a past datetime to force immediate renewal, or a future datetime to delay it. Replaced with the certificate-expiry-based schedule after the next successful update.',
                null=True,
                verbose_name='Next Certificate Update',
            ),
        ),
        migrations.AlterField(
            model_name='agentprofiledefinition',
            name='is_active',
            field=models.BooleanField(
                default=True,
                help_text='Inactive definitions are hidden from selection and skipped by renewal scheduling, but preserved for audit purposes.',
                verbose_name='Active',
            ),
        ),
    ]
