import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('cmp', '0002_initial'),
        ('pki', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='cmptransactionmodel',
            name='domain',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='cmp_transactions', to='pki.domainmodel', verbose_name='Domain'),
        ),
        migrations.AddField(
            model_name='cmptransactionmodel',
            name='final_certificate',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='cmp_transaction_records', to='pki.certificatemodel', verbose_name='Final Certificate'),
        ),
        migrations.AddField(
            model_name='cmptransactionmodel',
            name='issuer_credential',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='cmp_transaction_issuer_records', to='pki.credentialmodel', verbose_name='Issuer Credential'),
        ),
        migrations.AddIndex(
            model_name='cmptransactionmodel',
            index=models.Index(fields=['status'], name='cmp_cmptran_status_bca250_idx'),
        ),
        migrations.AddIndex(
            model_name='cmptransactionmodel',
            index=models.Index(fields=['backend', 'backend_reference'], name='cmp_cmptran_backend_ba899c_idx'),
        ),
        migrations.AddIndex(
            model_name='cmptransactionmodel',
            index=models.Index(fields=['device', 'status'], name='cmp_cmptran_device__000381_idx'),
        ),
        migrations.AddIndex(
            model_name='cmptransactionmodel',
            index=models.Index(fields=['domain', 'status'], name='cmp_cmptran_domain__3132e9_idx'),
        ),
    ]
