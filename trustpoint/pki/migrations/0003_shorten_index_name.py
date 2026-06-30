from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pki', '0002_tp_v0_6_0_dev1'),
    ]

    operations = [
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
            index=models.Index(fields=['issuer_public_bytes', 'issuer_id'], name='pki_cert_iss_pub_bytes_idx'),
        ),
        migrations.AddIndex(
            model_name='revokedcertificatemodel',
            index=models.Index(fields=['ca', 'revoked_at'], name='pki_revoked_ca_revoked_at_idx'),
        ),
    ]
