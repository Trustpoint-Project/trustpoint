import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('devices', '0003_tp_v0_5_0'),
    ]

    operations = [
        migrations.CreateModel(
            name='AgentWorkflowDefinition',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text='Unique identifier for this workflow definition.', max_length=200, unique=True, verbose_name='Name')),
                ('profile', models.JSONField(help_text='JSON object containing device metadata and automation steps. Metadata fields: vendor, device_family, firmware_hint, version, description. Steps array contains typed automation steps.', verbose_name='Workflow Profile')),
                ('is_active', models.BooleanField(default=True, help_text='Inactive definitions are hidden from selection but preserved for audit purposes.', verbose_name='Active')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Agent Workflow Definition',
                'verbose_name_plural': 'Agent Workflow Definitions',
            },
        ),
        migrations.CreateModel(
            name='TrustpointAgent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text="Human-readable name, e.g. 'Cell A Agent 1'.", max_length=120, unique=True, verbose_name='Name')),
                ('agent_id', models.CharField(help_text="Stable identifier sent by the agent in every API request. Must match AGENT_ID in the agent's runtime config.", max_length=120, unique=True, verbose_name='Agent ID')),
                ('certificate_fingerprint', models.CharField(help_text="SHA-256 fingerprint of the agent's mTLS client certificate. Revoke the cert to decommission the agent at the TLS layer.", max_length=64, unique=True, verbose_name='Certificate Fingerprint (SHA-256)')),
                ('capabilities', models.JSONField(default=list, help_text='List of job types this agent supports, e.g. ["wbm_cert_push"]. Used for display and validation; does not restrict API access at runtime.', verbose_name='Capabilities')),
                ('cell_location', models.CharField(blank=True, help_text="Free-text description of the production cell, e.g. 'Building 3 / Cell A'.", max_length=200, verbose_name='Cell Location')),
                ('is_active', models.BooleanField(default=True, help_text='Inactive agents are rejected by the API even if their certificate is still valid.', verbose_name='Active')),
                ('poll_interval_seconds', models.PositiveIntegerField(default=300, help_text='How often this agent should call the check-in endpoint. Returned in every check-in response so the agent self-configures. Lower values increase responsiveness; higher values reduce server load.', verbose_name='Poll Interval (seconds)')),
                ('last_seen_at', models.DateTimeField(blank=True, help_text='Updated on every authenticated API call. Use for liveness monitoring.', null=True, verbose_name='Last Seen')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('device', models.ForeignKey(blank=True, help_text='For 1-to-1 agents: the device that IS the agent (standalone). For 1-to-n agents: the agent-process device that holds only the domain credential. Application certificates are issued to separate managed-device records.', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='agents', to='devices.devicemodel', verbose_name='Device')),
            ],
            options={
                'verbose_name': 'Trustpoint Agent',
                'verbose_name_plural': 'Trustpoint Agents',
            },
        ),
        migrations.CreateModel(
            name='AgentAssignedProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('renewal_threshold_days', models.PositiveIntegerField(default=30, help_text='Trustpoint will trigger certificate renewal when the currently issued certificate expires within this many days.', verbose_name='Renewal Threshold (days)')),
                ('last_certificate_update', models.DateTimeField(blank=True, help_text='Timestamp of the most recent successful certificate issuance for this profile.', null=True, verbose_name='Last Certificate Update')),
                ('next_certificate_update_scheduled', models.DateTimeField(blank=True, help_text='Manually scheduled next renewal trigger time. Set to a past datetime to force immediate renewal, or a future datetime to delay it. Cleared automatically after the next successful certificate update.', null=True, verbose_name='Next Certificate Update')),
                ('enabled', models.BooleanField(default=True, help_text='Disabled assignments are skipped during renewal scheduling.', verbose_name='Enabled')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('workflow_definition', models.ForeignKey(help_text='The workflow / renewal profile applied to this agent.', on_delete=django.db.models.deletion.PROTECT, related_name='assigned_to', to='agents.agentworkflowdefinition', verbose_name='Agent Profile')),
                ('agent', models.ForeignKey(help_text='The 1-to-1 agent this profile is assigned to.', on_delete=django.db.models.deletion.CASCADE, related_name='assigned_profiles', to='agents.trustpointagent', verbose_name='Agent')),
            ],
            options={
                'verbose_name': 'Agent Assigned Profile',
                'verbose_name_plural': 'Agent Assigned Profiles',
                'unique_together': {('agent', 'workflow_definition')},
            },
        ),
    ]
