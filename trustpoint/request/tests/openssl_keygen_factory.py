from abc import ABC, abstractmethod
from typing import Any


class KeyGenerationComponent(ABC):
    """Abstract base class for key generation components."""

    @abstractmethod
    def build_args(self, context: dict[str, Any]) -> list[str]:
        """Build command arguments for this component."""

    @abstractmethod
    def get_description(self) -> str:
        """Get human-readable description of this component."""


class RSAKeyGenerator(KeyGenerationComponent):
    """RSA key generation using OpenSSL genrsa command."""

    def __init__(self, key_size: int = 2048):
        if key_size not in [2048, 3072, 4096]:
            raise ValueError('RSA key size should be one of: 2048, 3072, 4096')
        self.key_size = key_size

    def build_args(self, context: dict[str, Any]) -> list[str]:
        """Build OpenSSL genrsa command arguments."""
        return ['openssl', 'genrsa']

    def get_key_size_args(self) -> list[str]:
        """Get the key size argument that should come at the end."""
        return [str(self.key_size)]

    def get_description(self) -> str:
        return f'RSA {self.key_size}-bit key generation'

    def get_priority(self) -> int:
        """RSA generator should come first."""
        return 10


class ECKeyGenerator(KeyGenerationComponent):
    """ECC key generation using OpenSSL ecparam command."""

    def __init__(self, curve_name: str = 'secp256r1'):
        valid_curves = ['secp256r1', 'sect283r1', 'sect571r1', 'secp384r1', 'secp521r1']
        if curve_name not in valid_curves:
            raise ValueError(f'Curve must be one of: {valid_curves}')
        self.curve_name = curve_name

    def build_args(self, context: dict[str, Any]) -> list[str]:
        """Build OpenSSL ecparam command arguments."""
        return ['openssl', 'ecparam', '-name', self.curve_name, '-genkey']

    def get_description(self) -> str:
        curve_display_names = {
            'secp256r1': 'ECC SECP256R1 (P-256)',
            'sect283r1': 'ECC SECT283R1',
            'sect571r1': 'ECC SECT571R1',
            'secp384r1': 'ECC SECP384R1 (P-384)',
            'secp521r1': 'ECC SECP521R1 (P-521)',
        }
        return curve_display_names.get(self.curve_name, f'ECC {self.curve_name.upper()}')

    def get_priority(self) -> int:
        """EC generator should come first."""
        return 10


class KeyFileOutput(KeyGenerationComponent):
    """Component for specifying the output file (-out argument)."""

    def __init__(self, file_path: str | None = None, auto_generate_path: bool = True):
        self.file_path = file_path or '/tmp/key.pem'
        self.auto_generate_path = auto_generate_path

    def build_args(self, context: dict[str, Any]) -> list[str]:
        """Build -out argument with file path."""
        return ['-out', self.file_path]

    def get_description(self) -> str:
        if self.file_path:
            return f'Output to {self.file_path}'
        return 'Output file specification'

    def get_priority(self) -> int:
        """Output should come before the key size."""
        return 30


class CompositeKeyGenerator:
    """Composite key generator that combines multiple components."""

    def __init__(self, name: str, description: str = None):
        self.name = name
        self.description = description or name
        self.components: list[KeyGenerationComponent] = []

    def add_component(self, component: KeyGenerationComponent) -> 'CompositeKeyGenerator':
        """Add a component to this composite generator."""
        self.components.append(component)
        return self

    def build_command(self, context: dict[str, Any] = None) -> list[str]:
        """Build the complete OpenSSL command from all components."""
        if context is None:
            context = {}

        self._set_key_type_in_context(context)

        sorted_components = sorted(self.components, key=lambda c: c.get_priority())

        args = []
        rsa_generator = None

        for component in sorted_components:
            if isinstance(component, RSAKeyGenerator):
                rsa_generator = component
                args.extend(component.build_args(context))
            else:
                args.extend(component.build_args(context))

        if rsa_generator:
            args.extend(rsa_generator.get_key_size_args())

        return args

    def _set_key_type_in_context(self, context: dict[str, Any]) -> None:
        """Set the key type in context based on the generator component."""
        if 'key_type' not in context:
            for component in self.components:
                if isinstance(component, RSAKeyGenerator):
                    context['key_type'] = f'rsa-{component.key_size}'
                    break
                if isinstance(component, ECKeyGenerator):
                    context['key_type'] = f'ecc-{component.curve_name}'
                    break

    def get_description(self) -> str:
        """Get complete description of this composite generator."""
        component_descriptions = [comp.get_description() for comp in self.components]
        return f'{self.description}: {"; ".join(component_descriptions)}'

    def __str__(self) -> str:
        """String representation."""
        return self.get_description()

    def __repr__(self) -> str:
        """Detailed representation."""
        return f"CompositeKeyGenerator(name='{self.name}', components={len(self.components)})"
