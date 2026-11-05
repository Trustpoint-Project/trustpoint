# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Run the fixed privileged helpers allowed by the deployment sudo policy."""

import subprocess
from pathlib import Path


def execute_shell_script(script: Path, *args: str) -> None:
    """Validate the helper and retain its diagnostics if sudo or the script fails."""
    script_path = Path(script).resolve()
    if not script_path.exists():
        msg = f'Script not found: {script_path}'
        raise FileNotFoundError(msg)
    if not script_path.is_file():
        msg = f'The script path {script_path} is not a valid file.'
        raise ValueError(msg)
    subprocess.run(  # noqa: S603 - fixed deployment helpers are constrained by sudoers.
        ['sudo', str(script_path), *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    )
