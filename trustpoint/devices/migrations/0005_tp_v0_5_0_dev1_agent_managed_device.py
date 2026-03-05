"""Add AGENT_MANAGED_DEVICE (5) to DeviceModel.DeviceType."""

from typing import ClassVar

from django.db import migrations, models


class Migration(migrations.Migration):
    """Add the Agent Managed Device choice to the device_type field."""

    dependencies: ClassVar = [
        ('devices', '0004_tp_v0_5_0_dev1'),
    ]

    operations: ClassVar = [
        migrations.AlterField(
            model_name='devicemodel',
            name='device_type',
            field=models.IntegerField(
                choices=[
                    (0, 'Generic Device'),
                    (1, 'OPC UA GDS'),
                    (2, 'OPC UA GDS Push'),
                    (3, 'Agent (1-to-1)'),
                    (4, 'Agent (1-to-n)'),
                    (5, 'Agent Managed Device'),
                ],
                default=0,
                verbose_name='Device Type',
            ),
        ),
    ]
