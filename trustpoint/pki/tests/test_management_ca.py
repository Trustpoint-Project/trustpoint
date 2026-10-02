# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for management-CA lifecycle operations used by certificate authentication."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from django.core.exceptions import ValidationError
from django.test import TestCase

from pki.services.management_ca import ManagementCAService


class ManagementCAServiceTest(TestCase):
    """Validate action guards before management-CA hierarchy changes are applied."""

    @staticmethod
    def ca(pk: int, *, parent_ca_id: int | None, credential_id: int | None = 1) -> Mock:
        ca = Mock()
        ca.pk = pk
        ca.parent_ca_id = parent_ca_id
        ca.credential_id = credential_id
        return ca

    def test_is_complete_accepts_expected_hierarchy(self) -> None:
        root = self.ca(1, parent_ca_id=None)
        issuing = self.ca(2, parent_ca_id=1)

        assert ManagementCAService.is_complete(root, issuing)

    def test_is_complete_rejects_incomplete_or_inconsistent_hierarchy(self) -> None:
        hierarchies = [
            (None, None),
            (Mock(pk=1, parent_ca_id=None, credential_id=1), None),
            (None, Mock(pk=2, parent_ca_id=None, credential_id=1)),
            (Mock(pk=1, parent_ca_id=9, credential_id=1), Mock(pk=2, parent_ca_id=1, credential_id=1)),
            (Mock(pk=1, parent_ca_id=None, credential_id=None), Mock(pk=2, parent_ca_id=1, credential_id=1)),
            (Mock(pk=1, parent_ca_id=None, credential_id=1), Mock(pk=2, parent_ca_id=9, credential_id=1)),
        ]
        for root, issuing in hierarchies:
            with self.subTest(root=root, issuing=issuing):
                assert not ManagementCAService.is_complete(root, issuing)

    def test_apply_rejects_unknown_action(self) -> None:
        with pytest.raises(ValidationError, match='valid management CA action'):
            ManagementCAService.apply('invalid', root_ca_id=None, issuing_ca_id=None)

    @patch('pki.services.management_ca.call_command')
    @patch.object(ManagementCAService, 'get_hierarchy', return_value=(None, None))
    def test_generate_creates_hierarchy_when_none_exists(self, get_hierarchy: Mock, call_command: Mock) -> None:
        ManagementCAService.apply('generate', root_ca_id=None, issuing_ca_id=None)

        get_hierarchy.assert_called_once_with(lock=True)
        call_command.assert_called_once()
        assert call_command.call_args.args[0] == 'create_management_ca'

    @patch.object(ManagementCAService, 'get_hierarchy')
    def test_apply_rejects_stale_ca_ids(self, get_hierarchy: Mock) -> None:
        root = self.ca(10, parent_ca_id=None)
        issuing = self.ca(11, parent_ca_id=10)
        get_hierarchy.return_value = (root, issuing)

        with pytest.raises(ValidationError, match='has changed'):
            ManagementCAService.apply('delete', root_ca_id=1, issuing_ca_id=2)

    @patch.object(ManagementCAService, 'get_hierarchy')
    def test_generate_rejects_existing_management_ca(self, get_hierarchy: Mock) -> None:
        get_hierarchy.return_value = (self.ca(1, parent_ca_id=None), None)

        with pytest.raises(ValidationError, match='already exists'):
            ManagementCAService.apply('generate', root_ca_id=1, issuing_ca_id=None)

    @patch.object(ManagementCAService, 'get_hierarchy', return_value=(None, None))
    def test_delete_rejects_missing_management_ca(self, _get_hierarchy: Mock) -> None:
        with pytest.raises(ValidationError, match='no management CA'):
            ManagementCAService.apply('delete', root_ca_id=None, issuing_ca_id=None)

    @patch.object(ManagementCAService, '_delete_hierarchy')
    @patch.object(ManagementCAService, 'get_hierarchy')
    def test_replace_requires_complete_hierarchy(self, get_hierarchy: Mock, delete_hierarchy: Mock) -> None:
        root = self.ca(1, parent_ca_id=None)
        issuing = self.ca(2, parent_ca_id=99)
        get_hierarchy.return_value = (root, issuing)

        with pytest.raises(ValidationError, match='incomplete'):
            ManagementCAService.apply('replace', root_ca_id=1, issuing_ca_id=2)

        delete_hierarchy.assert_not_called()

    @patch('pki.services.management_ca.call_command')
    @patch.object(ManagementCAService, '_delete_hierarchy')
    @patch.object(ManagementCAService, 'get_hierarchy')
    def test_replace_deletes_old_hierarchy_then_generates_new_one(
        self,
        get_hierarchy: Mock,
        delete_hierarchy: Mock,
        call_command: Mock,
    ) -> None:
        root = self.ca(1, parent_ca_id=None)
        issuing = self.ca(2, parent_ca_id=1)
        get_hierarchy.return_value = (root, issuing)

        ManagementCAService.apply('replace', root_ca_id=1, issuing_ca_id=2)

        delete_hierarchy.assert_called_once_with(root, issuing)
        call_command.assert_called_once()
        assert call_command.call_args.args[0] == 'create_management_ca'

    @patch('pki.services.management_ca.call_command')
    @patch.object(ManagementCAService, '_delete_hierarchy')
    @patch.object(ManagementCAService, 'get_hierarchy')
    def test_delete_removes_hierarchy_without_regenerating(
        self,
        get_hierarchy: Mock,
        delete_hierarchy: Mock,
        call_command: Mock,
    ) -> None:
        root = self.ca(1, parent_ca_id=None)
        issuing = self.ca(2, parent_ca_id=1)
        get_hierarchy.return_value = (root, issuing)

        ManagementCAService.apply('delete', root_ca_id=1, issuing_ca_id=2)

        delete_hierarchy.assert_called_once_with(root, issuing)
        call_command.assert_not_called()

    def test_delete_hierarchy_rejects_inconsistent_parent_relationship(self) -> None:
        root = self.ca(1, parent_ca_id=None)
        issuing = self.ca(2, parent_ca_id=99)

        with pytest.raises(ValidationError, match='inconsistent'):
            ManagementCAService._delete_hierarchy(root, issuing)  # noqa: SLF001

    def test_delete_hierarchy_deletes_child_before_root_and_cleans_related_objects(self) -> None:
        calls: list[str] = []
        root = self.ca(1, parent_ca_id=None)
        issuing = self.ca(2, parent_ca_id=1)
        root_certificate = Mock()
        issuing_certificate = Mock()
        root_chain = Mock()
        issuing_chain = Mock()
        root.credential.certificates.all.return_value = [root_certificate]
        issuing.credential.certificates.all.return_value = [issuing_certificate]
        root.chain_truststore = root_chain
        issuing.chain_truststore = issuing_chain
        issuing.delete.side_effect = lambda: calls.append('issuing')
        root.delete.side_effect = lambda: calls.append('root')

        ManagementCAService._delete_hierarchy(root, issuing)  # noqa: SLF001

        assert calls == ['issuing', 'root']
        issuing_chain.delete.assert_called_once_with()
        root_chain.delete.assert_called_once_with()
        issuing_certificate.delete.assert_called_once_with()
        root_certificate.delete.assert_called_once_with()
