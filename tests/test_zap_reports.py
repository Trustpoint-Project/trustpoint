# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for scan failures masquerading as clean ZAP results."""

# ruff: noqa: INP001

import json
import runpy
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

SCAN_ERROR = 2

check_reports = runpy.run_path(str(Path(__file__).resolve().parents[1] / '.github/check_zap_reports.py'))[
    'check_reports'
]


def write_report(directory: Path, protocol: str, risks: Sequence[int] = (), status: int = 0) -> None:
    """Write synthetic ZAP reports with explicit completed-scan status."""
    (directory / f'{protocol}.exit').write_text(str(status))
    data = {'site': [{'@name': f'{protocol}://localhost', 'alerts': [{'riskcode': str(risk)} for risk in risks]}]}
    (directory / f'{protocol}.json').write_text(json.dumps(data))
    (directory / f'{protocol}.md').write_text('Synthetic Markdown report')
    (directory / f'{protocol}.html').write_text('<html>Synthetic HTML report</html>')


@pytest.fixture
def reports(tmp_path: Path) -> Path:
    """Provide successful empty reports for both scan protocols."""
    write_report(tmp_path, 'http')
    write_report(tmp_path, 'https')
    return tmp_path


@pytest.mark.parametrize(
    ('status', 'risks', 'expected'),
    [
        (0, [], 0),
        (2, [0, 1], 0),
        (2, [2], 1),
        (2, [3], 1),
        (0, [3], 1),
        (1, [1], 1),
        (3, [], 2),
        (125, [], 2),
        (124, [], 2),
        (2, [], 2),
    ],
)
def test_exit_status_and_risk_policy(
    reports: Path, status: int, risks: list[int], expected: int, capsys: pytest.CaptureFixture[str]
) -> None:
    """Keep scanner errors distinct from accepted alerts and blocking findings."""
    write_report(reports, 'http', risks, status)
    assert check_reports(reports) == expected
    output = capsys.readouterr().out
    assert 'HTTPS: scan completed' in output
    if expected == SCAN_ERROR:
        assert 'invalid scan evidence' in output
    elif expected == 1:
        assert 'Blocking ZAP findings' in output


@pytest.mark.parametrize('protocol', ['http', 'https'])
@pytest.mark.parametrize('extension', ['exit', 'json', 'md', 'html'])
def test_missing_or_empty_required_evidence_fails(reports: Path, protocol: str, extension: str) -> None:
    """Require all reports and statuses, even when the other scan completed."""
    report = reports / f'{protocol}.{extension}'
    report.unlink()
    assert check_reports(reports) == SCAN_ERROR
    report.write_text('')
    assert check_reports(reports) == SCAN_ERROR


@pytest.mark.parametrize(
    'data',
    [
        'not JSON',
        {},
        {'site': []},
        {'site': [{'@name': 'https://unexpected.invalid', 'alerts': []}]},
        {'site': [{'@name': 'http://localhost:8080', 'alerts': []}]},
        {'site': [{'@name': 'https://localhost'}]},
        {'site': [{'@name': 'https://localhost', 'alerts': 'not a list'}]},
        {'site': [{'@name': 'https://localhost', 'alerts': [{}]}]},
        {'site': [{'@name': 'https://localhost', 'alerts': [{'riskcode': 'unknown'}]}]},
    ],
)
def test_malformed_report_cannot_be_treated_as_zero_findings(reports: Path, data: dict[str, Any] | str) -> None:
    """Malformed JSON, targets and alert schemas must fail closed."""
    (reports / 'https.json').write_text(data if isinstance(data, str) else json.dumps(data))
    assert check_reports(reports) == SCAN_ERROR
