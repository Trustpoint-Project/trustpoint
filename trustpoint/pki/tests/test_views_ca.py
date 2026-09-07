# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for CA table and bulk-delete view behavior."""

from __future__ import annotations

from http import HTTPStatus
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from django.test import RequestFactory

from pki.views.ca import CaBulkDeleteConfirmView, CaTableView


def test_ca_table_hierarchical_sort_orders_roots_and_children() -> None:
    """CA rows are ordered by root hierarchy and then name."""
    root = SimpleNamespace(id=1, unique_name='root', parent_ca=None)
    child_b = SimpleNamespace(id=3, unique_name='child-b', parent_ca=root)
    child_a = SimpleNamespace(id=2, unique_name='child-a', parent_ca=root)
    second_root = SimpleNamespace(id=4, unique_name='second-root', parent_ca=None)

    view = CaTableView()
    result = CaTableView.__dict__['_hierarchical_sort'](view, [child_b, second_root, root, child_a])

    assert [ca.unique_name for ca in result] == ['root', 'child-a', 'child-b', 'second-root']


def test_ca_table_hierarchical_sort_ignores_orphaned_rows() -> None:
    """Rows whose parent is absent are not silently promoted to roots."""
    missing_parent = SimpleNamespace(id=99, unique_name='missing', parent_ca=None)
    orphan = SimpleNamespace(id=2, unique_name='orphan', parent_ca=missing_parent)

    view = CaTableView()
    assert CaTableView.__dict__['_hierarchical_sort'](view, [orphan]) == []


def test_ca_table_export_config_contains_security_relevant_columns() -> None:
    """CA exports include hierarchy, status, domains, signature, and expiry data."""
    config = CaTableView().get_export_config()

    assert config.filename == 'certificate_authorities'
    keys = [column.key for column in config.columns]
    assert {'unique_name', 'parent_ca', 'is_active', 'domains', 'signature_suite', 'not_valid_after'} <= set(keys)


def test_bulk_delete_removes_children_before_parents() -> None:
    """Hierarchical deletion invokes child deletion before parent deletion."""
    deletion_order: list[str] = []
    parent = Mock(id=1, parent_ca=None)
    child = Mock(id=2, parent_ca=parent)
    parent.unique_name = 'parent'
    child.unique_name = 'child'
    parent.delete.side_effect = lambda: deletion_order.append('parent')
    child.delete.side_effect = lambda: deletion_order.append('child')

    view = CaBulkDeleteConfirmView()
    CaBulkDeleteConfirmView.__dict__['_delete_cas_hierarchically'](view, [parent, child])

    assert child.delete.call_count == 1
    assert parent.delete.call_count == 1
    assert deletion_order == ['child', 'parent']


@pytest.mark.django_db
def test_bulk_delete_get_redirects_when_no_cas_selected() -> None:
    """The confirmation view redirects and reports an empty selection."""
    request = RequestFactory().get('/cas/delete/')
    request.user = SimpleNamespace(is_authenticated=False)
    view = CaBulkDeleteConfirmView()
    view.request = request
    view.get_queryset = Mock(return_value=Mock(exists=Mock(return_value=False)))

    with patch('pki.views.ca.messages.error') as error:
        response = view.get(request)

    assert response.status_code == HTTPStatus.FOUND
    error.assert_called_once()
