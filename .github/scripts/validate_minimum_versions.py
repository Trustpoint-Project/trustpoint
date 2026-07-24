#!/usr/bin/env python3
"""Validate that installed packages match the minimum versions specified in pyproject.toml.

This script compares the versions of installed packages against the minimum versions
specified in pyproject.toml and reports any discrepancies. This helps identify when
dependency conflicts prevent installation of the absolute minimum versions.
"""

import re
import subprocess
import sys
from pathlib import Path

from packaging.version import parse as parse_version


def normalize_version(version: str) -> str:
    """Normalize a version string using packaging.version."""
    try:
        return str(parse_version(version))
    except Exception:  # noqa: BLE001
        return version


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

    return None


def extract_dependency_name(dep: str) -> str:
    """Extract package name from dependency string."""
    dep = re.sub(r'\[.*?\]', '', dep)
    return re.split(r'[><=!~]', dep)[0].strip()


def normalize_package_name(name: str) -> str:
    """Normalize package name according to PEP 503."""
    return re.sub(r'[-_.]+', '-', name).lower()


def get_installed_version(package_name: str) -> str | None:
    """Get the installed version of a package using uv pip show."""
    try:
        result = subprocess.run(
            ['uv', 'pip', 'show', package_name],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.startswith('Version:'):
                    return line.split(':', 1)[1].strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return None


def parse_pyproject_minimums() -> dict[str, str]:
    """Parse pyproject.toml and extract minimum versions for all dependencies."""
    pyproject_path = Path('pyproject.toml')
    if not pyproject_path.exists():
        return {}

    content = pyproject_path.read_text()
    minimums = {}

    in_dependencies = False
    in_dev_dependencies = False

    for raw_line in content.split('\n'):
        line = raw_line.strip()

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
            normalized_name = normalize_package_name(pkg_name)

            version_part = re.sub(r'^[a-zA-Z0-9_-]+(\[.*?\])?', '', dep_spec).strip()
            specs = [s.strip() for s in version_part.split(',') if s.strip()]

            for spec in specs:
                version = parse_version_spec(spec)
                if version:
                    minimums[normalized_name] = version
                    break

    return minimums


def validate_versions() -> tuple[list[tuple[str, str, str]], list[str]]:
    """Compare installed versions against minimum versions.
    
    Returns:
        Tuple of (mismatches, missing) where:
        - mismatches: List of (package, expected_min, actual) tuples
        - missing: List of package names that couldn't be checked
    """
    minimums = parse_pyproject_minimums()
    mismatches = []
    missing = []

    for pkg_name, min_version in minimums.items():
        installed_version = get_installed_version(pkg_name)
        
        if installed_version is None:
            missing.append(pkg_name)
            continue
        
        # Normalize both versions for comparison
        norm_installed = normalize_version(installed_version)
        norm_minimum = normalize_version(min_version)
            
        if norm_installed != norm_minimum:
            mismatches.append((pkg_name, min_version, installed_version))

    return mismatches, missing


def main() -> None:
    """Run validation and report results."""
    mismatches, missing = validate_versions()
    
    if not mismatches and not missing:
        print('✅ All packages are installed at their minimum specified versions!')
        sys.exit(0)
    
    exit_code = 0
    
    if mismatches:
        print('⚠️  The following packages are NOT at their minimum versions:')
        print()
        print('| Package | Minimum | Installed | Status |')
        print('|---------|---------|-----------|--------|')
        for pkg, min_ver, actual_ver in sorted(mismatches):
            # Compare versions to determine if installed is higher or lower
            status = '⬆️  Higher' if actual_ver > min_ver else '⬇️  Lower'
            print(f'| {pkg} | {min_ver} | {actual_ver} | {status} |')
        print()
        print(f'Total: {len(mismatches)} package(s) differ from minimum versions')
        print()
        print('ℹ️  This usually indicates dependency conflicts where installing the')
        print('   absolute minimum version would break compatibility with other packages.')
        print()
        # Don't fail - this is informational
    
    if missing:
        print('⚠️  Could not verify the following packages (not installed or not found):')
        for pkg in sorted(missing):
            print(f'  - {pkg}')
        print()
        exit_code = 1
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
