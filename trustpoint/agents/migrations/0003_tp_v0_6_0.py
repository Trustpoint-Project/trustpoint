import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0002_initial'),
        ('devices', '0003_tp_v0_6_0'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='trustpointagent',
            name='capabilities',
        ),
        migrations.AlterField(
            model_name='trustpointagent',
            name='device',
            field=models.ForeignKey(blank=True, help_text='For 1-to-1 agents: the device that IS the agent (standalone). Application certificates are issued to separate managed-device records.', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='agents', to='devices.devicemodel', verbose_name='Device'),
        ),
    ]
