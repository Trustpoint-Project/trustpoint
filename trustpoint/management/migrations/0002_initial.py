import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        ('devices', '0002_initial'),
        ('management', '0001_initial'),
        ('pki', '0002_initial'),
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
        migrations.AddField(
            model_name='notificationmodel',
            name='certificate',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='notifications', to='pki.certificatemodel'),
        ),
        migrations.AddField(
            model_name='notificationmodel',
            name='device',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='notifications', to='devices.devicemodel'),
        ),
        migrations.AddField(
            model_name='notificationmodel',
            name='domain',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='notifications', to='pki.domainmodel'),
        ),
        migrations.AddField(
            model_name='notificationmodel',
            name='issuing_ca',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='notifications', to='pki.camodel'),
        ),
        migrations.AddField(
            model_name='notificationmodel',
            name='message',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='notifications', to='management.notificationmessagemodel'),
        ),
        migrations.AddField(
            model_name='notificationmodel',
            name='statuses',
            field=models.ManyToManyField(related_name='notifications', to='management.notificationstatus'),
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['target_content_type', 'target_object_id'], name='audit_log_target_idx'),
        ),
    ]
