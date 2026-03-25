import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0002_tp_v0_6_0_dev1'),
        ('pki', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='agentjob',
            name='target',
        ),
        migrations.AddField(
            model_name='agentassignedprofile',
            name='certificate_profile',
            field=models.ForeignKey(blank=True, help_text='Certificate profile used when issuing the certificate for this assignment.', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='assigned_profiles', to='pki.certificateprofilemodel', verbose_name='Certificate Profile'),
        ),
        migrations.AddField(
            model_name='agentassignedprofile',
            name='push_requested',
            field=models.BooleanField(default=False, help_text="Set to True by the operator ('push now') to force a push on the next check-in, regardless of the certificate expiry window. Cleared automatically once the agent picks up the assignment.", verbose_name='Push Requested'),
        ),
        migrations.DeleteModel(
            name='AgentCertificateTarget',
        ),
        migrations.DeleteModel(
            name='AgentJob',
        ),
    ]
