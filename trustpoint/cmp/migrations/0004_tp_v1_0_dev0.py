# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cmp', '0003_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='cmptransactionmodel',
            name='last_client_nonce',
            field=models.BinaryField(blank=True, help_text='Most recently authenticated CMP senderNonce for this transaction.', null=True, verbose_name='Last Client Nonce'),
        ),
        migrations.AddField(
            model_name='cmptransactionmodel',
            name='last_server_nonce',
            field=models.BinaryField(blank=True, help_text='Most recently emitted CMP senderNonce for this transaction.', null=True, verbose_name='Last Server Nonce'),
        ),
    ]
