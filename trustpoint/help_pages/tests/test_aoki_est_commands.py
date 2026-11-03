# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""The AOKI enrollment example must use the initialization response and IDevID."""

import json
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from django.urls import resolve

from help_pages.commands import AokiEstIDevIDCommandBuilder
from help_pages.devices_help_views import AokiEstIDevIDStrategy
from help_pages.tests.test_command_escaping import shell_arguments
from help_pages.tests.test_devices_help_views import _device, _domain, _help_context


@pytest.mark.parametrize('absolute_url', [False, True])
def test_aoki_est_enrollment_uses_initialization_response(tmp_path: Path, absolute_url: bool) -> None:
    domain = _domain()
    context = _help_context(_device(domain), domain)
    context_host = context.host_base
    path = '/.well-known/est/discovered-domain/domain_credential/'
    response = {
        'aoki-init': {
            'tls-truststore': 'TLS CERTIFICATE\n',
            'enrollment-info': {
                'protocols': [{'protocol': 'EST', 'url': context_host + path if absolute_url else path}]
            },
        },
    }
    (tmp_path / 'aoki_init_response.json').write_text(json.dumps(response))
    sections, _ = AokiEstIDevIDStrategy().build_sections(context)
    arguments = shell_arguments(sections[-1].rows[-1].value, tmp_path)

    assert arguments[arguments.index('--cert') + 1] == 'idevid.pem'
    assert arguments[arguments.index('--key') + 1] == 'idevid_pk.pem'
    assert arguments[arguments.index('--cacert') + 1] == 'trust_store.pem'
    assert arguments[-1] == context_host + path + 'simpleenroll'
    assert resolve(urlsplit(arguments[-1]).path).kwargs['domain'] == 'discovered-domain'
    assert (tmp_path / 'trust_store.pem').read_text() == 'TLS CERTIFICATE\n'


@pytest.mark.parametrize(
    'response',
    [
        'not JSON',
        '{"aoki-init": {}}',
        '{"aoki-init": {"enrollment-info": {"protocols": []}}}',
    ],
)
def test_invalid_aoki_response_stops_before_enrollment(tmp_path: Path, response: str) -> None:
    (tmp_path / 'aoki_init_response.json').write_text(response)
    command = AokiEstIDevIDCommandBuilder.get_curl_enroll_command('https://example.test')
    result = subprocess.run(
        ['bash', '-c', 'curl() { touch enrollment-attempted; };\n' + command],
        cwd=tmp_path,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert not (tmp_path / 'enrollment-attempted').exists()
