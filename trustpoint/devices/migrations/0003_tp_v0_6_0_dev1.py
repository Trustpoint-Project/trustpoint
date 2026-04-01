import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0002_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='devicemodel',
            name='rfc_4122_uuid',
            field=models.UUIDField(default=uuid.uuid4, editable=False, help_text='RFC 4122 version 4 UUID uniquely identifying this device. Auto-generated on device creation and immutable thereafter.', unique=True, verbose_name='Device UUID'),
        ),
    ]
