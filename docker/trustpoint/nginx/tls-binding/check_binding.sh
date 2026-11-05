#!/usr/bin/env bash
# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT
#
# Live checks for a built nginx channel-binding module. For example:
# NGINX_BINARY=/path/to/nginx NGINX_MODULE=/path/to/module.so bash check_binding.sh
# TLS_CERT/TLS_KEY may override the repository's public HTTPS test fixtures.
# Requires Python 3, OpenSSL with -no_ems, and permission to bind loopback ports.
set -euo pipefail

if [[ -z "${NGINX_BINARY:-}" || -z "${NGINX_MODULE:-}" ]]; then
    echo 'SKIP: set NGINX_BINARY and NGINX_MODULE to run live nginx TLS checks.'
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export NGINX_BINARY NGINX_MODULE
export TLS_CERT="${TLS_CERT:-${SCRIPT_DIR}/../../../../tests/data/x509/https_server.crt}"
export TLS_KEY="${TLS_KEY:-${SCRIPT_DIR}/../../../../tests/data/x509/https_server.pem}"

python3 - <<'PYTHON'
import base64
import pathlib
import os
import socket
import ssl
import subprocess
import tempfile
import time

nginx_binary = pathlib.Path(os.environ['NGINX_BINARY']).resolve()
nginx_module = pathlib.Path(os.environ['NGINX_MODULE']).resolve()
cert = pathlib.Path(os.environ['TLS_CERT']).resolve()
key = pathlib.Path(os.environ['TLS_KEY']).resolve()
with tempfile.TemporaryDirectory(prefix='trustpoint-binding-nginx-') as work:
    work = pathlib.Path(work)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    (work / 'logs').mkdir()
    (work / 'index.txt').write_text('OK')
    config = work / 'nginx.conf'
    config.write_text(f'''
load_module {nginx_module};
daemon off;
master_process off;
error_log {work}/error.log;
pid {work}/nginx.pid;
events {{}}
http {{
    access_log off;
    server {{
        listen 127.0.0.1:{port} ssl;
        ssl_certificate {cert};
        ssl_certificate_key {key};
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_cache shared:Binding:1m;
        ssl_session_tickets off;
        location / {{ root {work}; index index.txt; add_header X-Test-Binding "$trustpoint_tls_unique_supported|$trustpoint_tls_unique|$ssl_protocol" always; }}
    }}
}}
''')
    process = subprocess.Popen([str(nginx_binary), '-p', str(work), '-c', str(config)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError(process.communicate()[1].decode())
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1):
                    break
            except OSError:
                time.sleep(.05)
        def exchange(context, session=None):
            with socket.create_connection(('127.0.0.1', port)) as tcp:
                with context.wrap_socket(tcp, server_hostname='127.0.0.1', session=session) as tls:
                    binding = tls.get_channel_binding('tls-unique')
                    reused = tls.session_reused
                    negotiated_session = tls.session
                    tls.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                    response = bytearray()
                    while chunk := tls.recv(8192):
                        response.extend(chunk)
                    body = next(line.split(b': ', 1)[1].decode() for line in bytes(response).split(b'\r\n') if line.startswith(b'X-Test-Binding: '))
                    return binding, reused, negotiated_session, body
        ctx12 = ssl.create_default_context(cafile=str(cert))
        ctx12.minimum_version = ctx12.maximum_version = ssl.TLSVersion.TLSv1_2
        binding, reused, session, body = exchange(ctx12)
        assert not reused
        assert body == '1|' + base64.b64encode(binding).decode() + '|TLSv1.2', body
        print('PASS: nginx TLS 1.2 full handshake equals client tls-unique')
        binding, reused, _, body = exchange(ctx12, session)
        assert reused, 'TLS 1.2 session was not resumed'
        assert body == '1|' + base64.b64encode(binding).decode() + '|TLSv1.2', body
        print('PASS: nginx TLS 1.2 resumed handshake equals client tls-unique')
        ctx13 = ssl.create_default_context(cafile=str(cert))
        ctx13.minimum_version = ctx13.maximum_version = ssl.TLSVersion.TLSv1_3
        _, _, _, body = exchange(ctx13)
        assert body == '0||TLSv1.3', body
        print('PASS: nginx TLS 1.3 does not expose invalid tls-unique')
        noems = subprocess.run(['openssl', 's_client', '-tls1_2', '-no_ems', '-quiet', '-connect', f'127.0.0.1:{port}', '-CAfile', str(cert), '-verify_return_error'], input=b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n', capture_output=True, timeout=10)
        assert b'X-Test-Binding: 0||TLSv1.2\r\n' in noems.stdout, noems.stdout
        print('PASS: nginx refuses tls-unique without extended master secret')
    finally:
        process.terminate()
        process.wait(timeout=5)
PYTHON
