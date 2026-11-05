# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Fail closed on missing ZAP evidence; distinguish scan errors from findings."""

# ruff: noqa: INP001, T201

import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

BLOCKING_RISK = 2
TARGET_ORIGINS = {('http', None), ('http', 80), ('https', None), ('https', 443)}


def _report_risks(data: dict[str, Any]) -> list[int]:
    """Validate the report target and each alert before trusting risk counts."""
    sites = data['site']
    if not isinstance(sites, list) or not sites:
        message = 'report contains no scanned sites'
        raise ValueError(message)
    targets = [urlsplit(site['@name']) for site in sites if isinstance(site['@name'], str)]
    if len(targets) != len(sites) or not any(
        url.hostname == 'localhost' and (url.scheme, url.port) in TARGET_ORIGINS for url in targets
    ):
        message = 'report does not include the intended localhost target'
        raise ValueError(message)
    risks = []
    for site in sites:
        alerts = site['alerts']
        if not isinstance(alerts, list):
            message = 'invalid alerts list'
            raise TypeError(message)
        for alert in alerts:
            risk = str(alert['riskcode'])
            if risk not in ('0', '1', '2', '3'):
                message = 'invalid riskcode'
                raise ValueError(message)
            risks.append(int(risk))
    return risks


def _read_scan(directory: Path, protocol: str) -> tuple[int, list[int]]:
    """Require completed scans and all three nonempty report formats."""
    status = int((directory / f'{protocol}.exit').read_text().strip())
    if status not in (0, 1, 2):
        message = f'scanner exited with code {status}'
        raise ValueError(message)
    for extension in ('json', 'md', 'html'):
        report = directory / f'{protocol}.{extension}'
        if not report.is_file() or report.stat().st_size == 0:
            message = f'missing or empty report: {report.name}'
            raise ValueError(message)
    risks = _report_risks(json.loads((directory / f'{protocol}.json').read_text()))
    if status in (1, 2) and not risks:
        message = 'scanner reported findings but the report contains none'
        raise ValueError(message)
    return status, risks


def check_reports(directory: Path) -> int:
    """Return 2 for scan/evidence errors, 1 for blocking findings, otherwise 0."""
    errors = []
    blocked = 0
    accepted = 0
    for protocol in ('http', 'https'):
        try:
            status, risks = _read_scan(directory, protocol)
            # A configured ZAP FAIL must never be downgraded by risk level.
            blocked += max(sum(risk >= BLOCKING_RISK for risk in risks), int(status == 1))
            accepted += sum(risk < BLOCKING_RISK for risk in risks) if status != 1 else 0
            print(f'{protocol.upper()}: scan completed; {len(risks)} alerts')
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(f'{protocol.upper()}: invalid scan evidence: {exc}')

    for error in errors:
        print(f'::error::{error}')
    if blocked:
        print(f'::error::Blocking ZAP findings: {blocked} (medium/high alerts or scanner FAIL)')
    if accepted:
        print(f'::warning::Informational/low ZAP alerts accepted by baseline policy: {accepted}; review artifacts')
    print('Scope: unauthenticated operational baseline; authenticated coverage requires separate release evidence.')
    return 2 if errors else int(blocked > 0)


if __name__ == '__main__':
    sys.exit(check_reports(Path(sys.argv[1])))
