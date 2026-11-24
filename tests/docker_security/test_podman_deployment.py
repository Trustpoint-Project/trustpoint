# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Keep the deployment check from mistaking a failed form for successful setup."""

import io
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.error import HTTPError
from urllib.parse import parse_qs

import podman_deployment as deployment
import pytest


@pytest.mark.parametrize('status,location', [(200, ''), (403, ''), (302, '/users/login/')])
def test_failed_form_is_rejected_and_saved(tmp_path, monkeypatch, status, location):
    monkeypatch.chdir(tmp_path)
    page = io.BytesIO(b'<input value="masked-token" name="csrfmiddlewaretoken" type="hidden">')
    page.status = 200
    result = io.BytesIO(b'Form error details')
    result.status = status
    result.headers = {'Location': location}
    client = SimpleNamespace(open=Mock(side_effect=[page, result]))

    with pytest.raises(AssertionError, match='expected redirect') as error:
        deployment.submit_form(client, 'https://192.0.2.1:8443', '/admin/', {'password': 'synthetic'}, '/database/')

    assert (tmp_path / 'reports/podman/failed-form.html').read_text() == 'Form error details'
    assert f'Location {location!r}' in str(error.value)


@pytest.mark.parametrize('next_path', ['/database/', '/home/'])
def test_successful_form_keeps_csrf_headers_and_requires_expected_redirect(tmp_path, monkeypatch, next_path):
    monkeypatch.chdir(tmp_path)
    page = io.BytesIO(b'<input name="csrfmiddlewaretoken" value="masked-token">')
    page.status = 200
    redirect = HTTPError('/admin/', 302, 'Found', {'Location': next_path}, io.BytesIO(b''))
    client = SimpleNamespace(open=Mock(side_effect=[page, redirect]))

    deployment.submit_form(client, 'https://192.0.2.1:8443', '/admin/', {'username': 'ci'}, next_path)

    request = client.open.call_args_list[1].args[0]
    assert parse_qs(request.data.decode()) == {'username': ['ci'], 'csrfmiddlewaretoken': ['masked-token']}
    assert request.get_header('Origin') == 'https://192.0.2.1:8443'
    assert request.get_header('Referer') == 'https://192.0.2.1:8443/admin/'
    assert not (tmp_path / 'reports/podman/failed-form.html').exists()
