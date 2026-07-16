import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('cmp', '0001_initial'),
        ('devices', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='cmptransactionmodel',
            name='device',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='cmp_transactions', to='devices.devicemodel', verbose_name='Device'),
        ),
    ]
