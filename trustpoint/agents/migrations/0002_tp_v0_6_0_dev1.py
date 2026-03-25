import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0001_tp_v0_5_0'),
    ]

    operations = [
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
                ('agent', models.ForeignKey(help_text='The 1-to-1 agent this profile is assigned to.', on_delete=django.db.models.deletion.CASCADE, related_name='assigned_profiles', to='agents.trustpointagent', verbose_name='Agent')),
                ('workflow_definition', models.ForeignKey(help_text='The workflow / renewal profile applied to this agent.', on_delete=django.db.models.deletion.PROTECT, related_name='assigned_to', to='agents.agentworkflowdefinition', verbose_name='Agent Profile')),
            ],
            options={
                'verbose_name': 'Agent Assigned Profile',
                'verbose_name_plural': 'Agent Assigned Profiles',
                'unique_together': {('agent', 'workflow_definition')},
            },
        ),
    ]
