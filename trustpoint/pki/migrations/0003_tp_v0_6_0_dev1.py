import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('management', '0003_tp_v0_6_0_dev1'),
        ('pki', '0002_tp_v0_6_0_dev1'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='carollovermodel',
            name='initiated_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL, verbose_name='Initiated By'),
        ),
        migrations.AddField(
            model_name='carollovermodel',
            name='new_issuing_ca',
            field=models.ForeignKey(blank=True, help_text='The replacement Issuing CA. Null until the new CA is ready.', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='rollovers_as_new', to='pki.camodel', verbose_name='New Issuing CA'),
        ),
        migrations.AddField(
            model_name='carollovermodel',
            name='old_issuing_ca',
            field=models.ForeignKey(help_text='The Issuing CA being replaced.', on_delete=django.db.models.deletion.PROTECT, related_name='rollovers_as_old', to='pki.camodel', verbose_name='Old Issuing CA'),
        ),
        migrations.DeleteModel(
            name='PKCS11Key',
        ),
        migrations.AddConstraint(
            model_name='carollovermodel',
            constraint=models.UniqueConstraint(condition=models.Q(('state__in', ['planned', 'awaiting_new_ca', 'preparation', 'transition'])), fields=('old_issuing_ca',), name='unique_active_rollover_per_old_ca'),
        ),
    ]
