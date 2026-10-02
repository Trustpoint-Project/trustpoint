# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('onboarding', '0003_tp_v1_0_dev0'),
        ('pki', '0002_initial'),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name='camodel',
            name='ca_mode_constraint',
        ),
        migrations.AlterField(
            model_name='camodel',
            name='ca_type',
            field=models.IntegerField(blank=True, choices=[(-1, 'Keyless CA'), (0, 'Auto-Generated Root'), (1, 'Auto-Generated'), (2, 'Local-Legacy Software'), (3, 'Local-Managed Backend'), (4, 'Remote-EST-RA'), (5, 'Remote-CMP-RA'), (6, 'Remote-Issuing-EST'), (7, 'Remote-Issuing-CMP'), (8, 'Remote-Issuing-CSR')], help_text='Type of CA - KEYLESS for keyless CAs', null=True, verbose_name='CA Type'),
        ),
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
        migrations.AddConstraint(
            model_name='camodel',
            constraint=models.CheckConstraint(condition=models.Q(models.Q(('ca_type', -1), ('certificate__isnull', False), ('credential__isnull', True)), models.Q(('ca_type__in', [4, 5]), ('credential__isnull', True)), models.Q(('ca_type__in', [0, 1, 2, 3, 6, 7, 8]), ('certificate__isnull', True), ('credential__isnull', False)), _connector='OR'), name='ca_mode_constraint', violation_error_message='Invalid CA configuration'),
        ),
    ]
