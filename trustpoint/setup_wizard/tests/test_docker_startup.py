# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Run container shell failure paths with disposable files and stub services."""

import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from threading import Thread

import pytest

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize('failure', ['validation', 'reload', None])
@pytest.mark.parametrize('helper', ['update_tls.sh', 'update_tls_nginx.sh'])
def test_tls_entry_points_preserve_previous_files_on_failure(tmp_path, failure, helper):
    installed, staging, binaries = (tmp_path / name for name in ('installed', 'staging', 'bin'))
    for directory in (installed, staging, binaries):
        directory.mkdir()
    names = ('nginx-tls-server-key.key', 'nginx-tls-server-cert.pem', 'nginx-tls-server-cert-chain.pem')
    for name in names:
        (installed / name).write_text('previous')
        (staging / name).write_text('candidate')
    nginx = binaries / 'nginx'
    nginx.write_text(
        '#!/bin/sh\n'
        + (
            'exit 1\n'
            if failure == 'validation'
            else 'if [ "$1" = "-s" ]; then exit 1; fi\nexit 0\n'
            if failure == 'reload'
            else 'exit 0\n'
        )
    )
    nginx.chmod(0o755)
    pid = tmp_path / 'nginx.pid'
    pid.write_text(str(os.getpid()))
    internal = ROOT / 'docker/trustpoint/wizard/internal'
    source = (internal / 'update_tls.sh').read_text()
    source = source.replace('/etc/trustpoint/tls/', str(installed))
    source = source.replace('/var/www/html/trustpoint/docker/trustpoint/nginx/tls', str(staging))
    source = source.replace('/run/nginx.pid', str(pid)).replace('DELAY=2', 'DELAY=0')
    installer = tmp_path / 'update_tls.sh'
    installer.write_text(source)
    if helper == 'update_tls_nginx.sh':
        source = (
            (internal / helper).read_text().replace('/etc/trustpoint/wizard/internal/update_tls.sh', str(installer))
        )
    result = subprocess.run(
        ['bash', '-c', source, 'tls-test', 'no_hsm'],
        env={**os.environ, 'PATH': f'{binaries}:{os.environ["PATH"]}'},
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert (result.returncode != 0) == (failure is not None), result.stdout + result.stderr
    assert all((installed / name).read_text() == ('previous' if failure else 'candidate') for name in names)
    assert all((staging / name).read_text() == 'candidate' for name in names)


@pytest.mark.parametrize('mode', ['bootstrap', 'operational', 'handoff', 'shutdown'])
def test_web_supervisor_detects_service_exit_and_stops_children(tmp_path, mode):
    source = (ROOT / 'docker/trustpoint/entrypoint.sh').read_text()
    source = source[source.index('service_alive()') : source.index('# ---------------- WORKER ROLE')]
    source = source.replace('/run/trustpoint-operational', str(tmp_path / 'operational'))
    binaries = tmp_path / 'bin'
    binaries.mkdir()
    nginx = binaries / 'nginx'
    nginx.write_text(f"""#!{sys.executable}
import os, sys, time
from pathlib import Path
(Path(os.environ['TEST_DIR']) / (sys.argv[1] + '.ready')).touch()
time.sleep(30)
""")
    nginx.chmod(0o755)
    setup = """
nginx gunicorn &
GUNICORN_PID=$!
echo "$GUNICORN_PID" > "$TEST_DIR/gunicorn.pid"
"""
    if mode == 'handoff':
        setup += """
until [ -f "$TEST_DIR/gunicorn.ready" ]; do sleep 0.01; done
kill "$GUNICORN_PID"
wait "$GUNICORN_PID" || true
nginx operational-gunicorn &
echo "$!" > "$TEST_DIR/operational-gunicorn.pid"
nginx operational-qcluster &
echo "$!" > "$TEST_DIR/operational-qcluster.pid"
touch "$TEST_DIR/operational.ready"
"""
    elif mode in {'operational', 'shutdown'}:
        setup += 'nginx qcluster &\nQCLUSTER_PID=$!\necho "$QCLUSTER_PID" > "$TEST_DIR/qcluster.pid"\n'
    source += '\ntrap stop_web_services EXIT\ntrap "exit 0" TERM INT\n' + setup
    source += 'echo READY\nstart_nginx_foreground\n'
    process = subprocess.Popen(
        ['bash', '-c', source],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, 'TEST_DIR': str(tmp_path), 'PATH': f'{binaries}:{os.environ["PATH"]}'},
        start_new_session=True,
    )
    try:
        assert process.stdout.readline().strip() == 'READY'
        services = ['operational-gunicorn', 'operational-qcluster'] if mode == 'handoff' else ['gunicorn']
        if mode in {'operational', 'shutdown'}:
            services.append('qcluster')
        services.append('-g')  # The supervisor starts nginx with -g as its first argument.
        deadline = time.monotonic() + 5
        # Bash can publish READY before its background children finish starting.
        while not all((tmp_path / f'{service}.ready').exists() for service in services):
            assert process.poll() is None, process.communicate()
            assert time.monotonic() < deadline, 'Supervisor services did not start'
            time.sleep(0.01)
        if mode == 'shutdown':
            process.send_signal(signal.SIGTERM)
        else:
            filename = {
                'bootstrap': 'gunicorn.pid',
                'operational': 'qcluster.pid',
                'handoff': 'operational-qcluster.pid',
            }[mode]
            os.kill(int((tmp_path / filename).read_text()), signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == (0 if mode == 'shutdown' else 1), stdout + stderr
        if mode != 'shutdown':
            assert 'Required service' in stdout
        for path in tmp_path.glob('*.pid'):
            with pytest.raises(ProcessLookupError):
                os.kill(int(path.read_text()), 0)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()


@pytest.fixture
def socket_directory():
    # Unix socket paths have a small platform limit; pytest's macOS paths exceed it.
    with tempfile.TemporaryDirectory(prefix='tp-mdns-', dir='/tmp') as directory:
        yield Path(directory)


@pytest.mark.parametrize('ignore_termination', [False, True])
def test_shutdown_waits_for_handoff_service_outside_shell_job_table(tmp_path, ignore_termination):
    source = (ROOT / 'docker/trustpoint/entrypoint.sh').read_text()
    source = source[source.index('service_alive()') : source.index('# ---------------- WORKER ROLE')]
    source = source.replace('/run/trustpoint-operational', str(tmp_path / 'operational'))
    if ignore_termination:
        source = source.replace('SECONDS + 8', 'SECONDS + 1')
    finished = tmp_path / 'finished'
    program = """
import signal, sys, time
from pathlib import Path
def stop(*_):
    time.sleep(0.3)
    Path(sys.argv[1]).touch()
    sys.exit(0)
signal.signal(signal.SIGTERM, signal.SIG_IGN if sys.argv[2] == 'True' else stop)
print('READY', flush=True)
while True:
    time.sleep(1)
"""
    # This service and the cleanup shell are siblings, as after a sudo handoff.
    service = subprocess.Popen(
        [sys.executable, '-c', program, str(finished), str(ignore_termination)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert service.stdout.readline().strip() == 'READY'
        # Reap the sibling as its launcher would; macOS has no /proc zombie check.
        reaper = Thread(target=service.wait, daemon=True)
        reaper.start()
        (tmp_path / 'operational-qcluster.pid').write_text(str(service.pid))
        result = subprocess.run(
            ['bash', '-c', source + '\nstop_web_services\n'],
            capture_output=True,
            text=True,
            timeout=4,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        if ignore_termination:
            assert 'exceeded the shutdown deadline' in result.stdout
            assert service.wait(timeout=1) == -signal.SIGKILL
            assert not finished.exists()
        else:
            assert finished.exists(), 'Cleanup returned before the handoff service finished shutdown'
            assert service.wait(timeout=1) == 0
    finally:
        if service.poll() is None:
            service.kill()
        service.communicate(timeout=2)


@pytest.mark.parametrize('stale_sockets', [False, True])
def test_mdns_runs_without_host_sockets_and_detects_daemon_exit(tmp_path, socket_directory, stale_sockets):
    binaries = tmp_path / 'bin'
    binaries.mkdir()
    sockets = socket_directory
    if stale_sockets:
        for name in ('dbus.sock', 'avahi.sock'):
            with socket.socket(socket.AF_UNIX) as stale:
                stale.bind(str(sockets / name))
        (tmp_path / 'old-avahi.pid').write_text('12345')
    for name, body in {
        'uname': 'echo Linux',
        'getent': 'exit 1',
        'ip': 'echo "1.1.1.1 via 192.0.2.1 dev eth0 src 192.0.2.10"',
        'dbus-uuidgen': 'exit 0',
    }.items():
        executable = binaries / name
        executable.write_text('#!/bin/sh\n' + body + '\n')
        executable.chmod(0o755)
    for name, socket_name in [('dbus-daemon', 'dbus.sock'), ('avahi-daemon', 'avahi.sock')]:
        executable = binaries / name
        executable.write_text(f"""#!{sys.executable}
import os, socket, time
from pathlib import Path
root = Path(os.environ['TEST_DIR'])
time.sleep(0.2)
server = socket.socket(socket.AF_UNIX)
server.bind(str(Path(os.environ['TEST_SOCKET_DIR']) / {socket_name!r}))
(root / {name + '.pid'!r}).write_text(str(os.getpid()))
time.sleep(0.2)
(root / {name + '.ready'!r}).touch()
time.sleep(30)
""")
        executable.chmod(0o755)
    bus_query = binaries / 'dbus-send'
    bus_query.write_text(f"""#!{sys.executable}
import os, sys
from pathlib import Path
daemon = 'avahi-daemon' if sys.argv[-1] == 'string:org.freedesktop.Avahi' else 'dbus-daemon'
ready = (Path(os.environ['TEST_DIR']) / (daemon + '.ready')).exists()
print('boolean ' + str(ready).lower())
""")
    bus_query.chmod(0o755)
    publisher = binaries / 'avahi-publish'
    publisher.write_text(f"""#!{sys.executable}
import os, sys, time
from pathlib import Path
for daemon in ('dbus-daemon', 'avahi-daemon'):
    assert (Path(os.environ['TEST_DIR']) / (daemon + '.ready')).exists()
with (Path(os.environ['TEST_DIR']) / 'publications').open('a') as stream:
    stream.write(' '.join(sys.argv[1:]) + '\\n')
time.sleep(30)
""")
    publisher.chmod(0o755)
    source = (ROOT / 'docker/mdns/entrypoint.sh').read_text()
    source = source.replace('/var/run/dbus/system_bus_socket', str(sockets / 'dbus.sock'))
    source = source.replace('/var/run/avahi-daemon/socket', str(sockets / 'avahi.sock'))
    source = source.replace('/var/run/avahi-daemon/pid', str(tmp_path / 'old-avahi.pid'))
    source = source.replace('/var/run/dbus/pid', str(tmp_path / 'old-dbus.pid'))
    source = source.replace('/run/dbus/dbus.pid', str(tmp_path / 'old-dbus2.pid'))
    process = subprocess.Popen(
        ['bash', '-c', source],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={
            **os.environ,
            'TEST_DIR': str(tmp_path),
            'TEST_SOCKET_DIR': str(sockets),
            'PATH': f'{binaries}:{os.environ["PATH"]}',
        },
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 5
        publications = tmp_path / 'publications'
        while not publications.exists() or len(publications.read_text().splitlines()) != 4:
            assert process.poll() is None, process.communicate()
            assert time.monotonic() < deadline, 'Discovery services did not publish'
            time.sleep(0.05)
        assert process.poll() is None
        os.kill(int((tmp_path / 'avahi-daemon.pid').read_text()), signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 1, stdout + stderr
        assert 'Advertising service' in stderr
        for path in tmp_path.glob('*-daemon.pid'):
            with pytest.raises(ProcessLookupError):
                os.kill(int(path.read_text()), 0)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
