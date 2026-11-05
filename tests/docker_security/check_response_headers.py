# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Check headers on the deployed Django/Nginx boundary, including edge responses."""

# ruff: noqa: INP001, T201

import argparse
import ssl
from http.client import HTTPMessage
from http.cookies import SimpleCookie
from typing import IO
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    """Inspect the HTTP edge redirect rather than silently following it."""

    def redirect_request(
        self,
        _req: Request,
        _fp: IO[bytes],
        _code: int,
        _msg: str,
        _headers: HTTPMessage,
        _newurl: str,
    ) -> None:
        """Return the original redirect response to the caller."""


def check_headers(http_origin: str, https_origin: str, *, insecure: bool = False) -> None:
    """Fail on missing, duplicated or weakened deployed security headers."""
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    opener = build_opener(NoRedirect(), HTTPSHandler(context=context))
    cases = [
        (http_origin, '/users/login/', 'GET', 301),
        (https_origin, '/users/login/', 'GET', 200),
        (https_origin, '/users/login/', 'HEAD', 405),
        (https_origin, '/static/css/trustpoint.css', 'GET', 200),
        (https_origin, '/static/does-not-exist.css', 'GET', 404),
        # These paths must reach Django over HTTP, even when no enrollment exists.
        (http_origin, '/crl/0/', 'GET', 404),
        (http_origin, '/.well-known/cmp/does-not-exist/', 'GET', 405),
        (http_origin, '/.well-known/scep/does-not-exist/', 'GET', 404),
    ]
    for origin, path, method, expected in cases:
        request = Request(urljoin(origin, path), method=method)  # noqa: S310 - explicit operator-provided origins
        try:
            response = opener.open(request, timeout=15)
        except HTTPError as error:
            response = error
        with response:
            assert response.code == expected, (path, response.code, expected)
            policies = response.headers.get_all('Content-Security-Policy', [])
            assert len(policies) == 1, (path, policies)
            policy = policies[0]
            for directive in (
                "default-src 'none'",
                "base-uri 'none'",
                "object-src 'none'",
                "frame-ancestors 'none'",
                "form-action 'self'",
            ):
                assert directive in policy, (path, directive)
            assert 'unsafe-inline' not in policy, path
            assert 'unsafe-eval' not in policy, path
            for name, value in [
                ('X-Frame-Options', 'DENY'),
                ('X-Content-Type-Options', 'nosniff'),
                ('Referrer-Policy', 'same-origin'),
            ]:
                assert response.headers.get_all(name) == [value], (path, name)
            if origin == https_origin and path == '/users/login/' and method == 'GET':
                cookies = SimpleCookie()
                for value in response.headers.get_all('Set-Cookie', []):
                    cookies.load(value)
                assert cookies['csrftoken']['secure'], 'Docker CSRF cookie must require HTTPS'
            if origin == http_origin and path == '/users/login/':
                target = urlsplit(response.headers['Location'])
                assert target.scheme == 'https'
                assert target.path == path
            print(f'{method} {origin}{path}: {response.code}, security headers OK')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--http', default='http://localhost')
    parser.add_argument('--https', default='https://localhost')
    parser.add_argument('--insecure', action='store_true', help='Allow disposable self-signed test TLS only')
    arguments = parser.parse_args()
    check_headers(arguments.http, arguments.https, insecure=arguments.insecure)
