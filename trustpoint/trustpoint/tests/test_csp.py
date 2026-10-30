# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Exercise CSP through the real middleware chain and trusted UI templates."""

import re
from html.parser import HTMLParser
from http import HTTPStatus
from pathlib import Path
from typing import NoReturn
from unittest.mock import patch

import pytest
from django.conf import settings as django_settings
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponse, HttpResponseBase
from django.template.loader import render_to_string
from django.test import Client
from django.urls import include, path
from pytest_django.fixtures import Settings

from trustpoint.urls import urlpatterns as operational_urls
from workflows2.forms import Workflow2DefinitionForm


def forbidden(_request: HttpRequest) -> NoReturn:
    """Trigger Django's real production 403 handler."""
    raise PermissionDenied


def broken(_request: HttpRequest) -> NoReturn:
    """Trigger Django's real production 500 handler."""
    message = 'Synthetic failure'
    raise RuntimeError(message)


def rendered(request: HttpRequest) -> HttpResponse:
    """Render trusted inline code with the request nonce."""
    return HttpResponse(render_to_string('management/includes/metrics.html', request=request))


urlpatterns = [
    path('api/csp-forbidden/', forbidden),
    path('api/csp-broken/', broken),
    path('api/csp-rendered/', rendered),
    path('setup-wizard/', include('setup_wizard.urls')),
    *operational_urls,
]


class ActiveContent(HTMLParser):
    """Collect executable elements and forbidden inline attributes."""

    def __init__(self) -> None:
        """Initialize captured content."""
        super().__init__()
        self.inline_nonces: list[str | None] = []
        self.forbidden_attributes: list[str] = []

    def handle_starttag(self, tag: str, attributes: list[tuple[str, str | None]]) -> None:
        """Inspect an opening element."""
        attrs = dict(attributes)
        if tag == 'style' or (tag == 'script' and 'src' not in attrs and attrs.get('type') != 'application/json'):
            self.inline_nonces.append(attrs.get('nonce'))
        self.forbidden_attributes.extend(name for name in attrs if name.startswith('on') or name == 'style')


def assert_headers(response: HttpResponseBase) -> str:
    """Require enforced restrictions, along with Django's supporting headers."""
    policy = response['Content-Security-Policy']
    for directive in [
        "default-src 'none'",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "script-src-attr 'none'",
        "style-src-attr 'none'",
    ]:
        assert directive in policy
    assert 'unsafe-inline' not in policy
    assert 'unsafe-eval' not in policy
    assert 'Content-Security-Policy-Report-Only' not in response
    assert response['X-Frame-Options'] == 'DENY'
    assert response['X-Content-Type-Options'] == 'nosniff'
    assert response['Referrer-Policy'] == 'same-origin'
    return policy


@pytest.fixture(autouse=True)
def production_response_settings(settings: Settings) -> None:
    """Keep auth, CSRF and security middleware active in production rendering mode."""
    settings.DEBUG = False
    settings.ROOT_URLCONF = __name__
    settings.TRUSTPOINT_IS_OPERATIONAL = True
    settings.TRUSTPOINT_IS_BOOTSTRAP = False
    settings.ALLOWED_HOSTS = ['testserver']


@pytest.mark.django_db
@pytest.mark.parametrize('secure', [False, True])
def test_login_and_auth_redirect_headers(client: Client, *, secure: bool) -> None:
    """Both transports and authentication short circuits receive CSP."""
    response = client.get('/users/login/', secure=secure)
    assert response.status_code == HTTPStatus.OK
    assert_headers(response)
    response = client.get('/home/dashboard/', secure=secure)
    assert response.status_code == HTTPStatus.FOUND
    assert response['Location'] == '/users/login/'
    assert_headers(response)


@pytest.mark.django_db
@pytest.mark.parametrize(
    ('url', 'status'), [('/api/csp-forbidden/', 403), ('/api/csp-broken/', 500), ('/api/csp-missing/', 404)]
)
def test_production_error_headers(url: str, status: int) -> None:
    """Unhandled errors and missing pages retain the enforced policy."""
    response = Client(raise_request_exception=False).get(url)
    assert response.status_code == status
    assert_headers(response)
    assert b'nonce="None"' not in response.content


@pytest.mark.django_db
def test_csrf_rejection_headers() -> None:
    """The CSRF middleware's rejection also receives the security headers."""
    response = Client(enforce_csrf_checks=True).post('/users/login/', {'username': 'nobody'})
    assert response.status_code == HTTPStatus.FORBIDDEN
    assert_headers(response)


@pytest.mark.django_db
def test_nonce_matches_rendered_script_and_style_and_changes_per_response(client: Client) -> None:
    """Trusted inline code is authorized with a fresh nonce on each response."""
    nonces = []
    expected_inline_elements = 2
    for _ in range(2):
        response = client.get('/api/csp-rendered/')
        policy = assert_headers(response)
        parser = ActiveContent()
        parser.feed(response.content.decode())
        assert len(parser.inline_nonces) == expected_inline_elements
        assert not parser.forbidden_attributes
        nonce = parser.inline_nonces[0]
        assert nonce
        assert all(value == nonce for value in parser.inline_nonces)
        assert f"'nonce-{nonce}'" in policy
        nonces.append(nonce)
    assert nonces[0] != nonces[1]


@pytest.mark.django_db
def test_bootstrap_index_uses_policy(client: Client, settings: Settings) -> None:
    """The real setup index is covered even before any account exists."""
    settings.TRUSTPOINT_IS_BOOTSTRAP = True
    settings.TRUSTPOINT_IS_OPERATIONAL = False
    with patch('setup_wizard.models.SetupWizardCompletedModel.setup_wizard_completed', return_value=False):
        response = client.get('/setup-wizard/')
    assert response.status_code == HTTPStatus.OK
    assert_headers(response)


@pytest.mark.django_db
def test_login_post_still_authenticates(client: Client) -> None:
    """Adding CSP preserves the existing login/session flow."""
    password = 'csp-test-password-321'  # noqa: S105 - synthetic test account
    user = get_user_model().objects.create_user(username='csp-user', password=password)
    response = client.post('/users/login/', {'username': user.username, 'password': password})
    assert response.status_code == HTTPStatus.FOUND
    assert client.session['_auth_user_id'] == str(user.pk)
    assert_headers(response)


@pytest.mark.django_db
def test_django_https_redirect_keeps_csp(client: Client, settings: Settings) -> None:
    """CSP runs outside SecurityMiddleware, including deployment-enabled redirects."""
    settings.SECURE_SSL_REDIRECT = True
    response = client.get('/users/login/')
    assert response.status_code == HTTPStatus.MOVED_PERMANENTLY
    assert response['Location'] == 'https://testserver/users/login/'
    assert_headers(response)


def test_templates_do_not_reintroduce_inline_attributes() -> None:
    """Guard the full template tree, including pages not reached by anonymous ZAP."""
    for template in (Path(django_settings.BASE_DIR) / 'templates').rglob('*.html'):
        source = template.read_text()
        assert not re.search(r'\son[a-z]+\s*=|\sstyle\s*=|javascript:', source, re.IGNORECASE), template
        assert not re.search(r'<(?:script(?![^>]*\bsrc=)|style)(?![^>]*\bnonce=)[\s>]', source), template


@pytest.mark.django_db
def test_api_documentation_policy_is_scoped(client: Client) -> None:
    """ReDoc can use local search and fixed styles without broadening other pages."""
    user = get_user_model().objects.create_superuser(username='docs-user', password=None)
    client.force_login(user)
    redoc = client.get('/redoc/')
    assert redoc.status_code == HTTPStatus.OK
    policy = assert_headers(redoc)
    assert "worker-src 'self' blob:" in policy
    assert b'fonts.googleapis.com' not in redoc.content
    assert b'/static/js/redoc-csp.min.js' in redoc.content
    swagger = client.get('/swagger/')
    assert swagger.status_code == HTTPStatus.OK
    assert '/static/drf-yasg/swagger-ui-dist' in swagger.content.decode()
    assert 'blob:' not in assert_headers(swagger)
    assert 'blob:' not in assert_headers(client.get('/users/login/'))


def test_workflow_fallback_widget_has_no_inline_style() -> None:
    """Keep the fallback textarea usable before the nonce-aware editor loads."""
    assert 'style=' not in str(Workflow2DefinitionForm()['yaml_text'])


@pytest.mark.django_db
def test_login_reflected_values_remain_escaped(client: Client) -> None:
    """A nonced page must still escape user-controlled markup in form values."""
    payload = '"><img src=x onerror=alert(1)>'
    response = client.post('/users/login/', {'username': payload, 'password': 'invalid'})
    assert response.status_code == HTTPStatus.OK
    assert b'<img src=x onerror=' not in response.content
    assert b'&lt;img' in response.content
    assert_headers(response)
