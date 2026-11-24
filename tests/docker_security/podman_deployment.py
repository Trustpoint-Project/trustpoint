# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Exercise the real software-backend setup wizard in the disposable rootless CI deployment."""

# ruff: noqa: INP001, T201 - standalone integration assertions, synthetic CI data only.

import ipaddress
import json
import os
import re
import ssl
import subprocess
from html.parser import HTMLParser
from http import HTTPStatus
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPCookieProcessor, HTTPSHandler, OpenerDirector, ProxyHandler, Request, build_opener

from check_response_headers import NoRedirect

COMPOSE = ['podman', 'compose']
ADMIN_USER = 'podman-admin'
WIZARD = '/setup-wizard/fresh-install/'


def call(arguments: list[str]) -> str:
    """Run only local CI commands and retain their failure diagnostics."""
    return subprocess.run(arguments, check=True, stdout=subprocess.PIPE, text=True, timeout=330).stdout  # noqa: S603


class CsrfToken(HTMLParser):
    """Read Django's hidden form token without depending on attribute order."""

    token = ''

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Capture the CSRF input value."""
        attributes = dict(attrs)
        if tag == 'input' and attributes.get('name') == 'csrfmiddlewaretoken':
            self.token = attributes.get('value') or ''


def browser() -> OpenerDirector:
    """Keep browser cookies and inspect redirects through disposable self-signed TLS."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()), HTTPSHandler(context=context), NoRedirect())


def submit_form(client: OpenerDirector, origin: str, path: str, fields: dict[str, str], next_path: str) -> None:
    """Require successful CSRF-protected submission, not just a rendered error page."""
    with client.open(origin + path, timeout=30) as response:
        assert response.status == HTTPStatus.OK, (path, response.status)
        token = CsrfToken()
        token.feed(response.read().decode())
        assert token.token, f'No CSRF token on {path}'
    request = Request(  # noqa: S310 - main validates the disposable CI origin as an IPv4 address.
        origin + path,
        data=urlencode({**fields, 'csrfmiddlewaretoken': token.token}).encode(),
        headers={'Origin': origin, 'Referer': origin + path},
    )
    try:
        response = client.open(request, timeout=300)
    except HTTPError as error:
        response = error
    with response:
        body = response.read().decode()
        location = response.headers.get('Location', '')
        if response.status != HTTPStatus.FOUND or urlsplit(location).path != next_path:
            Path('reports/podman').mkdir(parents=True, exist_ok=True)
            Path('reports/podman/failed-form.html').write_text(body)
            message = f'{path}: expected redirect to {next_path}, received {response.status} with Location {location!r}'
            raise AssertionError(message)
    print(f'PASS: {path} submitted with browser cookies and CSRF headers.')


def login(origin: str, username: str, password: str, next_path: str) -> OpenerDirector:
    """Prove that the bootstrap or operational account can log in over the published IP."""
    client = browser()
    submit_form(client, origin, '/users/login/', {'username': username, 'password': password}, next_path)
    return client


def operational_state() -> dict[str, str]:
    """Read the actual PostgreSQL role and persist an encrypted value across restart."""
    probe = """
import hashlib, json, os, sys
from pathlib import Path
sys.path.insert(0, '/var/www/html/trustpoint/trustpoint')
os.environ['DJANGO_SETTINGS_MODULE'] = 'trustpoint.settings'
import django
django.setup()
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import connection
from appsecrets.service import get_app_secret_service
from setup_wizard.models import SetupWizardCompletedModel
assert os.geteuid() == 33
assert 'NoNewPrivs:\\t1' in Path('/proc/self/status').read_text()
assert SetupWizardCompletedModel.setup_wizard_completed()
assert get_user_model().objects.get(username='podman-admin').is_superuser
with connection.cursor() as cursor:
    cursor.execute('SELECT current_user')
    assert cursor.fetchone()[0] == 'podman_ci'
service = get_app_secret_service()
payload = Path(settings.MEDIA_ROOT) / 'podman-ci-encrypted.txt'
if not payload.exists():
    payload.write_text(service.encrypt_text('persisted Podman CI value'))
assert service.decrypt_text(payload.read_text()) == 'persisted Podman CI value'
print(json.dumps({'signing_key': hashlib.sha256(settings.SECRET_KEY.encode()).hexdigest(),
                 'dek': hashlib.sha256(service.require_dek()).hexdigest(),
                 'payload': hashlib.sha256(payload.read_bytes()).hexdigest()}))
"""
    return json.loads(call([*COMPOSE, 'exec', '-T', '--user', '33:33', 'trustpoint', '.venv/bin/python', '-c', probe]))


def main() -> None:
    """Verify the four reported Podman problems against a real fresh installation."""
    assert os.geteuid() != 0
    assert os.environ['COMPOSE_PROJECT_NAME'] == 'trustpoint-podman-ci', 'Use only the disposable CI deployment.'
    assert call(['podman', 'info', '--format', '{{.Host.Security.Rootless}}']).strip() == 'true'
    host = str(ipaddress.IPv4Address(os.environ['PODMAN_TEST_HOST']))
    origin = f'https://{host}:8443'
    try:
        response = browser().open(f'http://{host}:8080/', timeout=30)
    except HTTPError as error:
        response = error
    with response:
        assert response.status == HTTPStatus.MOVED_PERMANENTLY
        assert response.headers['Location'] == origin + '/'
    logs = call([*COMPOSE, 'logs', '--no-color', 'trustpoint'])
    bootstrap_password = re.findall(r'Trustpoint bootstrap password: (\S+)', logs)[-1]
    client = login(origin, 'admin', bootstrap_password, '/setup-wizard/')
    password = os.environ['PODMAN_TEST_ADMIN_PASSWORD']
    steps = [
        (
            'admin-user',
            {
                'operational_admin_username': ADMIN_USER,
                'operational_admin_email': 'ci@example.invalid',
                'password1': password,
                'password2': password,
            },
            'database',
        ),
        (
            'database',
            {
                'operational_db_host': 'postgres',
                'operational_db_port': '5432',
                'operational_db_name': 'podman_ci',
                'operational_db_user': 'podman_ci',
                'operational_db_password': os.environ['DATABASE_PASSWORD'],
            },
            'crypto-storage',
        ),
        ('crypto-storage', {'crypto_storage': '0'}, 'backend-config'),
        ('backend-config', {}, 'demo-data'),
        ('demo-data', {'inject_demo_data': 'False'}, 'tls-config'),
        ('tls-config', {'tls_mode': 'generate', 'ipv4_addresses': host, 'domain_names': 'localhost'}, 'summary'),
    ]
    for step, fields, next_step in steps:
        submit_form(client, origin, WIZARD + step + '/', fields, WIZARD + next_step + '/')
    submit_form(client, origin, WIZARD + 'summary/', {}, '/users/login/')
    for service in ('trustpoint', 'postgres'):
        status = call([*COMPOSE, 'exec', '-T', service, 'cat', '/proc/1/status'])
        assert 'NoNewPrivs:\t1' in status, service
    before = operational_state()
    login(origin, ADMIN_USER, password, '/home/')
    call([*COMPOSE, 'restart'])
    call([*COMPOSE, 'up', '-d', '--no-build', '--wait', '--wait-timeout', '300'])
    login(origin, ADMIN_USER, password, '/home/')
    assert operational_state() == before, 'Restart changed persisted keys or encrypted data.'
    database_logs = call([*COMPOSE, 'logs', '--no-color', 'postgres'])
    assert not re.search(r'role "[^"]+" does not exist', database_logs), database_logs
    print(
        'PASS: rootless deployment, NoNewPrivileges, IP setup, custom database role and encrypted state after restart.'
    )


if __name__ == '__main__':
    main()
