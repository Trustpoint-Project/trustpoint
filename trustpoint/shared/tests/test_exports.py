# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for streaming CSV exports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from shared.exports import ExportColumn, generate_csv_response

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass
class _Row:
    name: str


class _Rows:
    """Minimal queryset stand-in exposing the iterator used by the export."""

    def __init__(self, rows: list[_Row]) -> None:
        self._rows = rows

    def iterator(self) -> Iterator[_Row]:
        """Yield the supplied rows."""
        yield from self._rows


def test_generate_csv_response_streams_rows() -> None:
    rows = _Rows([_Row('alpha'), _Row('beta')])
    response = generate_csv_response(rows, [ExportColumn(key='name', label='Name')], 'devices')

    body = b''.join(response.streaming_content).decode('utf-8')

    assert response['Content-Type'] == 'text/csv; charset=utf-8'
    assert response['Content-Disposition'].startswith('attachment; filename="tp_devices_')
    assert body == '\ufeffName\r\nalpha\r\nbeta\r\n'


def test_generate_csv_response_neutralizes_formulas() -> None:
    rows = _Rows([_Row('=HYPERLINK("http://attacker/")'), _Row('-1+1')])
    response = generate_csv_response(rows, [ExportColumn(key='name', label='Name')], 'devices')

    body = b''.join(response.streaming_content).decode('utf-8')

    assert "'=HYPERLINK" in body
    assert "'-1+1" in body
