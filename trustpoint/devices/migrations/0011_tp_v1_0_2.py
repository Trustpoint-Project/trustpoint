# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations

SHA1_OID = '1.3.14.3.2.26'


def migrate_device_security_policy(apps, schema_editor):
    """Fold stricter per-device GDS limits into the central SecurityConfig before removing them."""
    SecurityConfig = apps.get_model('management', 'SecurityConfig')
    GdsConfig = apps.get_model('devices', 'OpcUaGdsPushConfig')
    security = SecurityConfig.objects.order_by('pk').first()
    if security is None:
        return

    rows = list(GdsConfig.objects.values_list('opc_gds_push_minimum_key_size', 'opc_gds_push_reject_sha1'))
    strictest_key_size = max((minimum or 0 for minimum, _reject in rows), default=0)
    reject_sha1 = any(reject for _minimum, reject in rows)

    update_fields = []
    if strictest_key_size and security.rsa_minimum_key_size is not None:
        if security.rsa_minimum_key_size < strictest_key_size:
            security.rsa_minimum_key_size = strictest_key_size
            update_fields.append('rsa_minimum_key_size')
    if reject_sha1:
        blocked = list(security.not_permitted_signature_algorithm_oids or [])
        if SHA1_OID not in blocked:
            blocked.append(SHA1_OID)
            security.not_permitted_signature_algorithm_oids = blocked
            update_fields.append('not_permitted_signature_algorithm_oids')
    if update_fields:
        security.save(update_fields=update_fields)


class Migration(migrations.Migration):
    dependencies = [
        ('devices', '0010_tp_v1_0_2'),
        ('management', '0007_tp_v1_0_2'),
    ]

    operations = [
        migrations.RunPython(migrate_device_security_policy, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_minimum_key_size',
        ),
        migrations.RemoveField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_reject_sha1',
        ),
    ]
