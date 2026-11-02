# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Generated commands must pass untrusted values as literal shell arguments."""

import subprocess
from functools import partial
from pathlib import Path
from shutil import which

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from help_pages.cert_parameters import CertParameterTemplate
from help_pages.commands import (
    CmpClientCertificateCommandBuilder,
    CmpSharedSecretCommandBuilder,
    EstUsernamePasswordCommandBuilder,
    RestClientCertificateCommandBuilder,
    RestUsernamePasswordCommandBuilder,
)
from pki.util.cert_profile import JSONProfileVerifier


def shell_arguments(command: str, directory: Path) -> list[str]:
    """Capture arguments without running enrollment clients or contacting a server."""
    result = subprocess.run(
        ['bash', '-c', 'openssl() { printf "%s\\0" "$@"; }; '
         'curl() { printf "%s\\0" "$@"; }; jq() { :; };\n' + command],
        cwd=directory, capture_output=True, check=True,
    )
    assert result.stderr == b''
    assert not (directory / 'injected').exists()
    return result.stdout.decode().rstrip('\0').split('\0')


@pytest.mark.parametrize('secret', ['two words', 'a"b\'c\\d', '$HOME', '$(touch injected)', '`touch injected`', 'a!b;c&d'])
@pytest.mark.parametrize('protocol', ['cmp', 'est', 'rest'])
@pytest.mark.parametrize('domain_credential', [False, True])
def test_secrets_reach_clients_unchanged(tmp_path: Path, secret: str, protocol: str, domain_credential: bool) -> None:
    """Spaces, quoting characters, and substitutions must remain part of the credential."""
    host = 'https://example.test/enroll?x=$HOME&y=$(touch injected)'
    if protocol == 'cmp':
        if domain_credential:
            command = CmpSharedSecretCommandBuilder.get_domain_credential_profile_command(host, 1, secret)
        else:
            command = CmpSharedSecretCommandBuilder.get_dynamic_cert_profile_command(
                host, 1, secret, 1, {'subject': {'CN': 'device'}, 'validity': {'days': 1}},
            )
        option, expected = '-secret', f'pass:{secret}'
    else:
        builder = EstUsernamePasswordCommandBuilder if protocol == 'est' else RestUsernamePasswordCommandBuilder
        username = 'device"$HOME'
        if domain_credential:
            command = builder.get_curl_enroll_domain_credential_command(username, secret, host)
        else:
            command = builder.get_curl_enroll_command(username, secret, host, 1)
        (tmp_path / 'csr-1.pem').write_text('CSR')
        (tmp_path / 'csr-domain-credential.pem').write_text('CSR')
        option, expected = '--user', f'{username}:{secret}'
    arguments = shell_arguments(command, tmp_path)
    assert arguments[arguments.index(option) + 1] == expected
    assert host in arguments


PROFILE_BUILDERS = [
    partial(CmpSharedSecretCommandBuilder.get_dynamic_cert_profile_command,
            host='https://tp/cmp', pk=1, shared_secret='secret', cred_number=1),
    partial(CmpClientCertificateCommandBuilder.get_dynamic_cert_profile_command, host='https://tp/cmp', cred_number=1),
    partial(EstUsernamePasswordCommandBuilder.get_dynamic_cert_profile_command, cred_number=1),
    partial(RestUsernamePasswordCommandBuilder.get_dynamic_cert_profile_command, cred_number=1),
    partial(RestClientCertificateCommandBuilder.get_dynamic_cert_profile_command, cred_number=1),
]


@pytest.mark.parametrize('builder', PROFILE_BUILDERS)
@pytest.mark.parametrize('editable', [False, True])
def test_fixed_and_editable_profile_values_are_literal(tmp_path: Path, builder, editable: bool) -> None:
    """Fixed values and template substitutions need the same shell and subject escaping."""
    common_name = 'a/b+c\\d "quoted" \'single\' $HOME $(touch injected) `touch injected` !'
    uri = 'urn:device:$HOME:$(touch${IFS}injected):`touch${IFS}injected`:"quoted"'
    profile = {
        'type': 'cert_profile', 'validity': {'days': 1},
        'subj': {'common_name': {'default': common_name} if editable else common_name},
        'ext': {'subject_alternative_name': {'uris': {'default': [uri]} if editable else [uri]}},
    }
    verifier = JSONProfileVerifier(profile)
    template = CertParameterTemplate.build(
        verifier.get_sample_request(), verifier.get_editable_fields(),
        lambda request: builder(sample_request=request),
    )
    arguments = shell_arguments(template.initial_command, tmp_path)
    subject_option = '-subject' if '-subject' in arguments else '-subj'
    subject = arguments[arguments.index(subject_option) + 1]
    expected = common_name.replace('\\', '\\\\').replace('/', '\\/').replace('+', '\\+')
    assert subject == f'/commonName={expected}'
    san_option = '-sans' if '-sans' in arguments else '-addext'
    expected_san = uri if san_option == '-sans' else f'subjectAltName = URI:{uri}'
    assert arguments[arguments.index(san_option) + 1] == expected_san


@pytest.mark.skipif(which('openssl') is None, reason='OpenSSL is required to inspect the generated CSR')
def test_openssl_preserves_subject_delimiters(tmp_path: Path) -> None:
    """Escaping must preserve the certificate name, not introduce extra subject attributes."""
    common_name = 'a/b+c\\d "q" \'s\' $HOME $(touch injected) `touch injected` !'
    key = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / 'key-1.pem').write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))
    command = EstUsernamePasswordCommandBuilder.get_dynamic_cert_profile_command(
        1, {'subject': {'common_name': common_name}},
    )
    result = subprocess.run(['bash', '-c', command], cwd=tmp_path, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr.decode()

    csr = x509.load_der_x509_csr((tmp_path / 'csr-1.der').read_bytes())
    assert len(csr.subject) == 1
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == common_name
    assert not (tmp_path / 'injected').exists()
