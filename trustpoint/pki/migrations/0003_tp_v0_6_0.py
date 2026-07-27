from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pki', '0002_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='certificatemodel',
            name='signature_algorithm_oid',
            field=models.CharField(choices=[('1.2.840.113549.1.1.4', 'Rsa Md5'), ('1.2.840.113549.1.1.5', 'Rsa Sha1'), ('1.3.14.3.2.29', 'Rsa Sha1 Alt'), ('1.2.840.113549.1.1.14', 'Rsa Sha224'), ('1.2.840.113549.1.1.11', 'Rsa Sha256'), ('1.2.840.113549.1.1.12', 'Rsa Sha384'), ('1.2.840.113549.1.1.13', 'Rsa Sha512'), ('2.16.840.1.101.3.4.3.13', 'Rsa Sha3 224'), ('2.16.840.1.101.3.4.3.14', 'Rsa Sha3 256'), ('2.16.840.1.101.3.4.3.15', 'Rsa Sha3 384'), ('2.16.840.1.101.3.4.3.16', 'Rsa Sha3 512'), ('1.2.840.10045.4.1', 'Ecdsa Sha1'), ('1.2.840.10045.4.3.1', 'Ecdsa Sha224'), ('1.2.840.10045.4.3.2', 'Ecdsa Sha256'), ('1.2.840.10045.4.3.3', 'Ecdsa Sha384'), ('1.2.840.10045.4.3.4', 'Ecdsa Sha512'), ('2.16.840.1.101.3.4.3.9', 'Ecdsa Sha3 224'), ('2.16.840.1.101.3.4.3.10', 'Ecdsa Sha3 256'), ('2.16.840.1.101.3.4.3.11', 'Ecdsa Sha3 384'), ('2.16.840.1.101.3.4.3.12', 'Ecdsa Sha3 512'), ('1.2.840.113533.7.66.13', 'Password Based Mac'), ('2.16.840.1.101.3.4.3.17', 'Mldsa44'), ('2.16.840.1.101.3.4.3.18', 'Mldsa65'), ('2.16.840.1.101.3.4.3.19', 'Mldsa87')], editable=False, max_length=256, verbose_name='Signature Algorithm OID'),
        ),
        migrations.AlterField(
            model_name='certificatemodel',
            name='spki_algorithm_oid',
            field=models.CharField(choices=[('1.2.840.10045.2.1', 'Ecc'), ('1.2.840.113549.1.1.1', 'Rsa'), ('2.16.840.1.101.3.4.3.17', 'Mldsa44'), ('2.16.840.1.101.3.4.3.18', 'Mldsa65'), ('2.16.840.1.101.3.4.3.19', 'Mldsa87')], editable=False, max_length=256, verbose_name='Public Key Algorithm OID'),
        ),
    ]
