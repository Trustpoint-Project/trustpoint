# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import management.models.security
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('management', '0006_tp_v1_0_2'),
    ]

    operations = [
        migrations.AddField(
            model_name='securityconfig',
            name='permitted_opc_ua_security_policies',
            field=models.JSONField(blank=True, default=management.models.security.default_opc_ua_security_policies, help_text='OPC UA SecurityPolicies the GDS Push client may negotiate. Certificate-management operations always require SignAndEncrypt. Legacy Basic256/Basic128Rsa15 policies must be selected explicitly and are never used as a silent fallback.', verbose_name='Permitted OPC UA security policies'),
        ),
    ]
