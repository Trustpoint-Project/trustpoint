from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('management', '0002_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='securityconfig',
            name='not_permitted_mldsa_variant_oids',
            field=models.JSONField(blank=True, default=list, help_text='JSON list of ML-DSA variant OIDs (from trustpoint_core.oid.PublicKeyAlgorithmOid) not permitted at the current security level.'),
        ),
        migrations.AlterField(
            model_name='securityconfig',
            name='auto_gen_pki_key_algorithm',
            field=models.CharField(choices=[('RSA2048SHA256', 'RSA2048'), ('RSA4096SHA256', 'RSA4096'), ('SECP256R1SHA256', 'SECP256R1'), ('MLDSA44', 'ML-DSA-44'), ('MLDSA65', 'ML-DSA-65'), ('MLDSA87', 'ML-DSA-87')], default='RSA2048SHA256', max_length=24),
        ),
    ]
