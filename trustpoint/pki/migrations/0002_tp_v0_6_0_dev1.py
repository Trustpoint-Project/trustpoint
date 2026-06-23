import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pki', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='certificateprofilemodel',
            name='credential_type',
            field=models.CharField(choices=[('application', 'Application Credential'), ('domain', 'Domain Credential')], default='application', max_length=32),
        ),
        migrations.AddField(
            model_name='domainmodel',
            name='domain_credential_profile',
            field=models.ForeignKey(blank=True, help_text='Certificate profile used for issuing domain credentials. Defaults to "domain_credential".', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='domains_as_credential_profile', to='pki.certificateprofilemodel', verbose_name='Domain Credential Profile'),
        ),
        migrations.AddIndex(
            model_name='certificatemodel',
            index=models.Index(fields=['not_valid_after'], name='pki_cert_not_valid_after_idx'),
        ),
        migrations.AddIndex(
            model_name='certificatemodel',
            index=models.Index(fields=['not_valid_before'], name='pki_cert_not_valid_before_idx'),
        ),
        migrations.AddIndex(
            model_name='certificatemodel',
            index=models.Index(fields=['serial_number'], name='pki_cert_serial_num_idx'),
        ),
        migrations.AddIndex(
            model_name='certificatemodel',
            index=models.Index(fields=['subject_public_bytes'], name='pki_cert_subj_pub_bytes_idx'),
        ),
        migrations.AddIndex(
            model_name='certificatemodel',
            index=models.Index(fields=['issuer_public_bytes', 'issuer_id'], name='pki_cert_iss_pub_bytes_isid_idx'),
        ),
        migrations.AddIndex(
            model_name='revokedcertificatemodel',
            index=models.Index(fields=['ca', 'revoked_at'], name='pki_revoked_ca_revoked_at_idx'),
        ),
    ]
