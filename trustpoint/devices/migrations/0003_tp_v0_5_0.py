from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0002_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='devicemodel',
            name='device_type',
            field=models.IntegerField(choices=[(0, 'Generic Device'), (1, 'OPC UA GDS'), (2, 'OPC UA GDS Push'), (3, 'Agent (1-to-1)'), (4, 'Agent (1-to-n)'), (5, 'Agent Managed Device')], default=0, verbose_name='Device Type'),
        ),
    ]
