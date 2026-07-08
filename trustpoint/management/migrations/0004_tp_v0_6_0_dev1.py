import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        ('management', '0003_tp_v0_6_0_dev1'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='auditlog',
            name='actor',
            field=models.ForeignKey(blank=True, help_text='The user who triggered the action. Null for system-triggered actions.', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='audit_log_entries', to=settings.AUTH_USER_MODEL, verbose_name='Actor'),
        ),
        migrations.AddField(
            model_name='auditlog',
            name='target_content_type',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='contenttypes.contenttype', verbose_name='Target Content Type'),
        ),
        migrations.DeleteModel(
            name='KeyStorageConfig',
        ),
        migrations.DeleteModel(
            name='PKCS11Token',
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['target_content_type', 'target_object_id'], name='audit_log_target_idx'),
        ),
    ]
