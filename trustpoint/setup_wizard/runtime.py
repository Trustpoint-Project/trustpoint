# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Run fixed helpers through the container's privileged control socket."""

import subprocess
from pathlib import Path


def execute_shell_script(script: Path, *args: str) -> None:
    """Validate the helper and retain its diagnostics if the operation fails."""
    script_path = Path(script).resolve()
    if not script_path.exists():
        msg = f'Script not found: {script_path}'
        raise FileNotFoundError(msg)
    if not script_path.is_file():
        msg = f'The script path {script_path} is not a valid file.'
        raise ValueError(msg)
    subprocess.run(  # noqa: S603 - fixed deployment helpers use the authenticated control socket.
        [str(script_path), *args],
        capture_output=True,
        text=True,
        check=True,
    )
