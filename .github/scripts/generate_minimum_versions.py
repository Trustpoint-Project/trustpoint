"""Generate minimum version constraints from pyproject.toml."""

import re
import sys
from pathlib import Path


def parse_version_spec(spec: str) -> str | None:
    """Parse a PEP 440 version specifier and extract the minimum version."""
    spec = spec.strip()

    if match := re.match(r'^==\s*(.+)$', spec):
        return match.group(1)

    if match := re.match(r'^>=\s*(.+)$', spec):
        return match.group(1)

    if match := re.match(r'^~=\s*(.+)$', spec):
        version = match.group(1)
        if version.count('.') == 1:
            return f'{version}.0'
        return version

    if spec.startswith('>') and not spec.startswith('>='):
        return None

    return None


def extract_dependency_name(dep: str) -> str:
    """Extract package name from dependency string."""
    dep = re.sub(r'\[.*?\]', '', dep)
    return re.split(r'[><=!~]', dep)[0].strip()


def parse_pyproject_dependencies() -> dict[str, str]:
    """Parse pyproject.toml and extract minimum versions for all dependencies."""
    pyproject_path = Path('pyproject.toml')
    if not pyproject_path.exists():
        print('Error: pyproject.toml not found', file=sys.stderr)
        sys.exit(1)

    content = pyproject_path.read_text()
    constraints = {}

    in_dependencies = False
    in_dev_dependencies = False

    for line in content.split('\n'):
        line = line.strip()

        if line == 'dependencies = [':
            in_dependencies = True
            in_dev_dependencies = False
            continue
        if 'dev = [' in line:
            in_dev_dependencies = True
            in_dependencies = False
            continue
        if line.startswith('[') and line.endswith(']') and '=' in line:
            in_dependencies = False
            in_dev_dependencies = False
            continue

        if (in_dependencies or in_dev_dependencies) and line.startswith('"'):
            match = re.match(r'"([^"]+)"', line)
            if not match:
                continue

            dep_spec = match.group(1)
            pkg_name = extract_dependency_name(dep_spec)

            version_part = re.sub(r'^[a-zA-Z0-9_-]+(\[.*?\])?', '', dep_spec).strip()

            specs = [s.strip() for s in version_part.split(',') if s.strip()]

            min_version = None
            for spec in specs:
                version = parse_version_spec(spec)
                if version:
                    min_version = version
                    break  # Use first minimum we find

            if min_version:
                constraints[pkg_name] = f'{pkg_name}=={min_version}'

    return constraints


def main() -> None:
    """Generate and print minimum version constraints."""
    constraints = parse_pyproject_dependencies()

    if not constraints:
        print('Error: No dependencies found in pyproject.toml', file=sys.stderr)
        sys.exit(1)

    for pkg in sorted(constraints.keys()):
        print(constraints[pkg])


if __name__ == '__main__':
    main()
