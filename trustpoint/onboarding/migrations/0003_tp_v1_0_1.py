# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Encrypt existing reusable enrollment credentials without replacing key material."""

from django.core.validators import MaxLengthValidator
from django.db import migrations, models

from util.encrypted_fields import EncryptedTextField


def rewrite_credentials(apps, schema_editor, *, decrypt=False):
    """Use plain historical fields so ciphertext is neither decoded nor encrypted twice."""
    from appsecrets.service import get_app_secret_service

    config = apps.get_model('onboarding', 'NoOnboardingConfigModel')
    rows = config.objects.using(schema_editor.connection.alias)
    service = None
    for pk, password, secret in rows.values_list('pk', 'est_password', 'cmp_shared_secret').iterator(chunk_size=500):
        values = {name: value for name, value in (('est_password', password), ('cmp_shared_secret', secret)) if value}
        if not values:
            continue
        if service is None:
            service = get_app_secret_service()
        transform = service.decrypt_text if decrypt else service.encrypt_text
        rows.filter(pk=pk).update(**{name: transform(value) for name, value in values.items()})


def encrypt_credentials(apps, schema_editor):
    rewrite_credentials(apps, schema_editor)


def decrypt_credentials(apps, schema_editor):
    rewrite_credentials(apps, schema_editor, decrypt=True)


class Migration(migrations.Migration):
    dependencies = [
        ('onboarding', '0002_initial'),
        ('appsecrets', '0001_initial'),
    ]

    operations = [
        # Text storage fits expanded UTF-8 ciphertext; historical fields stay plain during conversion.
        migrations.AlterField(
            model_name='noonboardingconfigmodel',
            name='est_password',
            field=models.TextField(verbose_name='EST Password', max_length=128, blank=True, default=''),
        ),
        migrations.AlterField(
            model_name='noonboardingconfigmodel',
            name='cmp_shared_secret',
            field=models.TextField(verbose_name='CMP Shared Secret', max_length=128, blank=True, default=''),
        ),
        migrations.RunPython(encrypt_credentials, decrypt_credentials),
        migrations.AlterField(
            model_name='noonboardingconfigmodel',
            name='est_password',
            field=EncryptedTextField(
                verbose_name='EST Password',
                max_length=128,
                blank=True,
                default='',
                validators=[MaxLengthValidator(128)],
            ),
        ),
        migrations.AlterField(
            model_name='noonboardingconfigmodel',
            name='cmp_shared_secret',
            field=EncryptedTextField(
                verbose_name='CMP Shared Secret',
                max_length=128,
                blank=True,
                default='',
                validators=[MaxLengthValidator(128)],
            ),
        ),
    ]
