import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('agents', '0001_initial'),
        ('devices', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='trustpointagent',
            name='device',
            field=models.ForeignKey(blank=True, help_text='For 1-to-1 agents: the device that IS the agent (standalone). For 1-to-n agents: the agent-process device that holds only the domain credential. Application certificates are issued to separate managed-device records.', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='agents', to='devices.devicemodel', verbose_name='Device'),
        ),
        migrations.AddField(
            model_name='agentassignedprofile',
            name='agent',
            field=models.ForeignKey(help_text='The 1-to-1 agent this profile is assigned to.', on_delete=django.db.models.deletion.CASCADE, related_name='assigned_profiles', to='agents.trustpointagent', verbose_name='Agent'),
        ),
        migrations.AlterUniqueTogether(
            name='agentassignedprofile',
            unique_together={('agent', 'workflow_definition')},
        ),
    ]
