import os
from abc import ABC, abstractmethod
from typing import Any


class CMPCommandComponent(ABC):
    """Abstract base class for CMP command components."""

    @abstractmethod
    def build_args(self, context: dict[str, Any]) -> list[str]:
        """Build command arguments for this component."""

    @abstractmethod
    def prepare_files(self, temp_dir: str, context: dict[str, Any]) -> list[str]:
        """Prepare any files needed for this component. Returns list of created files."""

    @abstractmethod
    def get_description(self) -> str:
        """Get human-readable description of this component."""


class BasicCMPArgs(CMPCommandComponent):
    """Basic CMP command arguments."""

    def __init__(self, cmd: str = 'cr', implicit_confirm: bool = True):
        self.cmd = cmd
        self.implicit_confirm = implicit_confirm

    def build_args(self, context: dict[str, Any]) -> list[str]:
        args = ['openssl', 'cmp', '-cmd', self.cmd]
        if self.implicit_confirm:
            args.append('-implicit_confirm')
        return args

    def prepare_files(self, temp_dir: str, context: dict[str, Any]) -> list[str]:
        return []

    def get_description(self) -> str:
        return f'Basic CMP {self.cmd} command'


class ServerConfig(CMPCommandComponent):
    """Server configuration component."""

    def __init__(self, server_url: str, tls_used: bool = False):
        self.server_url = server_url
        self.tls_used = tls_used

    def build_args(self, context: dict[str, Any]) -> list[str]:
        args = ['-server', self.server_url]
        if self.tls_used:
            args.append('-tls_used')
        return args

    def prepare_files(self, temp_dir: str, context: dict[str, Any]) -> list[str]:
        return []

    def get_description(self) -> str:
        protocol = 'HTTPS' if self.tls_used else 'HTTP'
        return f'{protocol} server at {self.server_url}'


class SharedSecretAuth(CMPCommandComponent):
    """Shared secret authentication component."""

    def __init__(self, ref: str, secret: str):
        self.ref = ref
        self.secret = secret

    def build_args(self, context: dict[str, Any]) -> list[str]:
        return ['-ref', self.ref, '-secret', self.secret]

    def prepare_files(self, temp_dir: str, context: dict[str, Any]) -> list[str]:
        return []

    def get_description(self) -> str:
        return f'Shared secret authentication (ref: {self.ref})'


class CertificateAuth(CMPCommandComponent):
    """Certificate authentication component."""

    def __init__(self, cert_content: str = None, key_content: str = None,
                 cert_file: str = None, key_file: str = None):
        self.cert_content = cert_content or '-----BEGIN CERTIFICATE-----\nMOCK_CERTIFICATE_DATA\n-----END CERTIFICATE-----\n'
        self.key_content = key_content or '-----BEGIN PRIVATE KEY-----\nMOCK_KEY_DATA\n-----END PRIVATE KEY-----\n'
        self.cert_file = cert_file or '/tmp/domain_credential_cert.pem'
        self.key_file = key_file or '/tmp/domain_credential_key.pem'

    def build_args(self, context: dict[str, Any]) -> list[str]:
        cert_file = context.get('cert_file', self.cert_file)
        key_file = context.get('key_file', self.key_file)
        return ['-cert', cert_file, '-key', key_file]

    def prepare_files(self, temp_dir: str, context: dict[str, Any]) -> list[str]:
        cert_file = os.path.join(temp_dir, self.cert_file)
        key_file = os.path.join(temp_dir, self.key_file)

        with open(cert_file, 'w') as f:
            f.write(self.cert_content)
        with open(key_file, 'w') as f:
            f.write(self.key_content)

        context['cert_file'] = cert_file
        context['key_file'] = key_file

        return [cert_file, key_file]

    def get_description(self) -> str:
        return 'Certificate-based authentication'


class CertificateRequest(CMPCommandComponent):
    """Certificate request parameters component."""

    def __init__(self, subject: str, days: int = 10, sans: str = None,
                 policy_oids: str = None, key_file: str = None, cert_out_file: str = None):
        self.subject = subject
        self.days = days
        self.sans = sans
        self.policy_oids = policy_oids
        self.key_file = key_file or '/tmp/key.pem'
        self.cert_out_file = cert_out_file or '/tmp/cert.pem'

    def build_args(self, context: dict[str, Any]) -> list[str]:
        key_file = context.get('key_file', self.key_file)
        cert_out_file = context.get('cert_out_file', self.cert_out_file)

        args = [
            '-subject', self.subject,
            '-days', str(self.days),
            '-newkey', key_file,
            '-certout', cert_out_file
        ]
        if self.sans:
            args.extend(['-sans', self.sans])
        if self.policy_oids:
            args.extend(['-policy_oids', self.policy_oids])
        return args

    def prepare_files(self, temp_dir: str, context: dict[str, Any]) -> list[str]:
        cert_out_file = os.path.join(temp_dir, 'cert.pem')
        context['cert_out_file'] = cert_out_file
        return []

    def get_description(self) -> str:
        desc = f'Certificate request for {self.subject} ({self.days} days)'
        if self.sans:
            desc += f' with SAN: {self.sans}'
        if self.policy_oids:
            desc += f' with policy OIDs: {self.policy_oids}'

        return desc


class ServerCertificate(CMPCommandComponent):
    """Server certificate component."""

    def __init__(self, cert_content: str = None, srvcert_file: str = None):
        self.cert_content = cert_content or '-----BEGIN CERTIFICATE-----\nMOCK_SRVCERT_DATA\n-----END CERTIFICATE-----\n'
        self.srvcert_file = srvcert_file or '/tmp/issuing_ca_cert.pem'

    def build_args(self, context: dict[str, Any]) -> list[str]:
        srvcert_file = context.get('srvcert_file', self.srvcert_file)
        return ['-srvcert', srvcert_file]

    def prepare_files(self, temp_dir: str, context: dict[str, Any]) -> list[str]:
        srvcert_file = os.path.join(temp_dir, 'issuing_ca_cert.pem')

        with open(srvcert_file, 'w') as f:
            f.write(self.cert_content)

        context['srvcert_file'] = srvcert_file
        return [srvcert_file]

    def get_description(self) -> str:
        return 'Server certificate validation'



class CertificateOutput(CMPCommandComponent):
    """Certificate output options component."""

    def __init__(self, chain_out: bool = False, extra_certs_out: bool = False,
                 chain_out_file: str = None, extra_certs_out_file: str = None):
        self.chain_out = chain_out
        self.extra_certs_out = extra_certs_out
        self.chain_out_file = chain_out_file or '/tmp/chain_without_root.pem'
        self.extra_certs_out_file = extra_certs_out_file or '/tmp/full_chain.pem'

    def build_args(self, context: dict[str, Any]) -> list[str]:
        args = []
        if self.chain_out:
            chain_out_file = context.get('chain_out_file', self.chain_out_file)
            args.extend(['-chainout', chain_out_file])
        if self.extra_certs_out:
            extra_certs_out_file = context.get('extra_certs_out_file', self.extra_certs_out_file)
            args.extend(['-extracertsout', extra_certs_out_file])
        return args

    def prepare_files(self, temp_dir: str, context: dict[str, Any]) -> list[str]:
        files = []
        if self.chain_out:
            chain_out_file = os.path.join(temp_dir, 'chain_without_root.pem')
            context['chain_out_file'] = chain_out_file
            files.append(chain_out_file)
        if self.extra_certs_out:
            extra_certs_out_file = os.path.join(temp_dir, 'full_chain.pem')
            context['extra_certs_out_file'] = extra_certs_out_file
            files.append(extra_certs_out_file)
        return []  # Output files will be created by OpenSSL

    def get_description(self) -> str:
        outputs = []
        if self.chain_out:
            outputs.append('chain output')
        if self.extra_certs_out:
            outputs.append('full chain output')
        return f"Certificate outputs: {', '.join(outputs)}" if outputs else 'Basic certificate output'



class CompositeCMPCommand(CMPCommandComponent):
    """Composite CMP command that combines multiple components."""

    def __init__(self, name: str, description: str = None):
        self.name = name
        self.description = description or name
        self.components: list[CMPCommandComponent] = []

    def add_component(self, component: CMPCommandComponent) -> 'CompositeCMPCommand':
        """Add a component to this composite command."""
        self.components.append(component)
        return self

    def build_args(self, context: dict[str, Any] = None) -> list[str]:
        """Build complete command arguments from all components."""
        if context is None:
            context = {}

        args = []
        for component in self.components:
            args.extend(component.build_args(context))
        return args

    def prepare_files(self, temp_dir: str, context: dict[str, Any]) -> list[str]:
        """Prepare all files needed by all components."""
        all_files = []
        for component in self.components:
            files = component.prepare_files(temp_dir, context)
            all_files.extend(files)
        return all_files

    def get_description(self) -> str:
        """Get complete description of this composite command."""
        component_descriptions = [comp.get_description() for comp in self.components]
        return f"{self.description}: {'; '.join(component_descriptions)}"

    def __str__(self) -> str:
        """String representation of the composite command."""
        return self.get_description()

    def __repr__(self) -> str:
        """Detailed representation of the composite command."""
        return f"CompositeCMPCommand(name='{self.name}', components={len(self.components)})"


if __name__ == '__main__':
    command = (CompositeCMPCommand('tls_cert_auth', 'TLS CMP with certificate authentication')
               .add_component(BasicCMPArgs(cmd='cr'))
               .add_component(ServerConfig('https://127.0.0.1:443/.well-known/cmp/certification/schmalz/tls-server/',
                                           tls_used=True))
               .add_component(CertificateAuth())
               .add_component(CertificateRequest('/CN=Trustpoint-TlsServer-Credential-1',
                                                 10,
                                                 'critical 127.0.0.1 ::1 localhost'))
               .add_component(ServerCertificate())
               .add_component(CertificateOutput(chain_out=True, extra_certs_out=True)))

    cmd_args = command.build_args()
    print(' '.join(cmd_args))


