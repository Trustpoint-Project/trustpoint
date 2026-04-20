import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('devices', '0002_initial'),
        ('management', '0001_initial'),
        ('pki', '0001_initial'),
    ]

    operations = [
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
        migrations.AddField(
            model_name='pkcs11token',
            name='kek',
            field=models.ForeignKey(blank=True, help_text='Associated key encryption key stored in this token', null=True, on_delete=django.db.models.deletion.SET_NULL, to='pki.pkcs11key', verbose_name='Key Encryption Key (KEK)'),
        ),
        migrations.AddField(
            model_name='keystorageconfig',
            name='hsm_config',
            field=models.OneToOneField(blank=True, help_text='Associated HSM token configuration (SoftHSM or Physical HSM)', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='crypto_storage_config', to='management.pkcs11token', verbose_name='HSM Configuration'),
        ),
    ]