import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('management', '0006_preserve_self_signed_ca_creation_column'),
        ('pki', '0006_self_signed_ca_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='certificateauthenticationconfig',
            name='certificate_profile',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to='pki.certificateprofilemodel',
                verbose_name='Default user certificate profile',
            ),
        ),
    ]
