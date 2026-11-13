# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Keep the renamed CA creation policy readable by the previous release."""

import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

from management.models import SecurityConfig

pytestmark = pytest.mark.django_db(transaction=True)


@pytest.mark.parametrize('start', ['0004_tp_v1_0_1_dev0', '0005_rename_allow_self_signed_ca_creation'])
def test_ca_creation_policy_preserves_values_and_legacy_column(start: str) -> None:
    """Upgrade from either field name without breaking old or new ORM readers."""
    executor = MigrationExecutor(connection)
    latest = executor.loader.graph.leaf_nodes()
    legacy_target = [('management', '0004_tp_v1_0_1_dev0')]
    target = [('management', start)]
    try:
        executor.migrate(target)
        historical = executor.loader.project_state(target).apps.get_model('management', 'SecurityConfig')
        field = 'allow_auto_gen_pki' if target == legacy_target else 'allow_self_signed_ca_creation'
        rows = [(historical.objects.create(**{field: allowed}).pk, allowed) for allowed in (False, True)]

        executor = MigrationExecutor(connection)
        executor.migrate(latest)
        legacy = executor.loader.project_state(legacy_target).apps.get_model('management', 'SecurityConfig')
        for pk, allowed in rows:
            assert SecurityConfig.objects.get(pk=pk).allow_self_signed_ca_creation is allowed
            assert legacy.objects.get(pk=pk).allow_auto_gen_pki is allowed

        table_name = SecurityConfig._meta.db_table  # noqa: SLF001
        with connection.cursor() as cursor:
            columns = {column.name for column in connection.introspection.get_table_description(cursor, table_name)}
        assert 'allow_auto_gen_pki' in columns
        assert 'allow_self_signed_ca_creation' not in columns
    finally:
        MigrationExecutor(connection).migrate(latest)
