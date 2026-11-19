# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models
from django.utils import timezone


def stamp_existing_otps(apps, _schema_editor):
    """Give OTPs issued before this migration a start time so they expire normally."""
    download_model = apps.get_model('devices', 'RemoteDeviceCredentialDownloadModel')
    download_model.objects.filter(otp_created_at__isnull=True).exclude(otp='').update(otp_created_at=timezone.now())


class Migration(migrations.Migration):
    dependencies = [
        ('devices', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='remotedevicecredentialdownloadmodel',
            name='otp_created_at',
            field=models.DateTimeField(null=True, verbose_name='OTP Created'),
        ),
        migrations.RunPython(stamp_existing_otps, migrations.RunPython.noop),
    ]
