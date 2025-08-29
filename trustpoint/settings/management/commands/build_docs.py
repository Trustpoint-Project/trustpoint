from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Sequence, Tuple, Optional

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


def run(cmd: Sequence[str], cwd: Optional[Path] = None) -> Tuple[int, str]:
    """Run a command and capture output; return (code, combined_output)."""
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    out, _ = proc.communicate()
    return proc.returncode, out or ""


class Command(BaseCommand):
    help = (
        "Build Sphinx documentation (integrated with uv). "
        "Supports dependency sync, clean builds, static copy, and robust fallbacks."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--sync-deps",
            action="store_true",
            help="Run `uv sync --group docs` before building (installs/updates docs deps).",
        )
        parser.add_argument(
            "--clean",
            action="store_true",
            help="Clean build directory before building (remove build dirs or run `make clean`).",
        )
        parser.add_argument(
            "--force-env",
            action="store_true",
            help=(
                "Force building via `uv run -m sphinx.cmd.build -M html source build` "
                "to avoid import/env issues."
            ),
        )
        parser.add_argument(
            "--docs-dir",
            default=None,
            help="Path to docs root (default: <BASE_DIR>/docs).",
        )
        parser.add_argument(
            "--static-dest",
            default=None,
            help=(
                "Copy built HTML to this static directory (e.g., trustpoint/static/docs). "
                "If omitted, no copy is performed."
            ),
        )
        parser.add_argument(
            "--sphinx-args",
            nargs="*",
            default=None,
            help="Extra args passed to sphinx (e.g. -W -n). Only used in direct sphinx build.",
        )

    def handle(self, *args, **opts):
        base_dir = Path(settings.BASE_DIR)
        docs_dir = Path(opts["docs_dir"]) if opts["docs_dir"] else base_dir / "docs"
        source_dir = docs_dir / "source"

        # Prefer docs/_build/html; also accept docs/build/html then normalize.
        build_dir_primary = docs_dir / "_build" / "html"
        build_dir_alt = docs_dir / "build" / "html"

        static_dest = Path(opts["static_dest"]) if opts.get("static_dest") else None
        sync_deps = bool(opts["sync_deps"])
        do_clean = bool(opts["clean"])
        force_env = bool(opts["force_env"])
        sphinx_args = opts.get("sphinx_args") or []

        # --- sanity checks
        if not docs_dir.exists():
            raise CommandError(f"Docs directory not found: {docs_dir}")
        if not source_dir.exists():
            raise CommandError(f"Sphinx source dir not found: {source_dir} (expected docs/source)")

        # 1) Sync docs deps (uv group 'docs' → fallback uv pip install)
        if sync_deps:
            self.stdout.write(self.style.NOTICE("Syncing docs dependencies via uv…"))
            code, out = run(["uv", "sync", "--group", "docs", "--frozen"], cwd=base_dir)
            if code != 0:
                self.stderr.write(out)
                self.stdout.write(
                    self.style.WARNING(
                        "uv sync failed; falling back to explicit package install (sphinx, rtd theme, myst-parser)…"
                    )
                )
                code, out = run(
                    ["uv", "pip", "install", "sphinx", "sphinx-rtd-theme", "myst-parser"], cwd=base_dir
                )
                if code != 0:
                    self.stderr.write(out)
                    raise CommandError("Failed to install docs dependencies via uv.")
            else:
                self.stdout.write(self.style.SUCCESS("Docs deps are in sync."))

        # 2) Clean (optional)
        if do_clean:
            self.stdout.write(self.style.NOTICE("Cleaning existing build directories…"))
            for p in (build_dir_primary.parent, build_dir_alt.parent):
                try:
                    if p.exists():
                        shutil.rmtree(p)
                except Exception as e:
                    raise CommandError(f"Failed to clean build directory {p}: {e}")

        # 3) Build: prefer Makefile if present AND `make` is available, unless --force-env
        makefile = docs_dir / "Makefile"
        make_available = shutil.which("make") is not None

        if makefile.exists() and make_available and not force_env:
            self.stdout.write(self.style.NOTICE("Building docs via `make -C docs html`…"))
            make_cmd = ["make", "-C", str(docs_dir)]
            make_cmd += ["clean", "html"] if do_clean else ["html"]
            code, out = run(make_cmd, cwd=base_dir)
            if code != 0:
                self.stderr.write(out)
                self.stdout.write(self.style.WARNING("`make` failed; falling back to sphinx-build via uv…"))
                code, out = self._run_sphinx_build_via_uv(source_dir, build_dir_alt, sphinx_args)
                if code != 0:
                    self.stderr.write(out)
                    raise CommandError("Sphinx build failed (make + fallback).")
        else:
            if force_env:
                self.stdout.write(self.style.NOTICE(
                    "Building docs via `uv run -m sphinx.cmd.build -M html source build` (force-env)…"
                ))
                code, out = self._run_sphinx_build_matrix(source_dir, docs_dir)
            else:
                reason = []
                if not makefile.exists():
                    reason.append("no Makefile")
                if not make_available:
                    reason.append("`make` not available")
                note = f" ({', '.join(reason)})" if reason else ""
                self.stdout.write(self.style.NOTICE(
                    f"Building docs via `uv run -m sphinx.cmd.build -b html`{note}…"
                ))
                code, out = self._run_sphinx_build_via_uv(source_dir, build_dir_alt, sphinx_args)

            if code != 0:
                self.stderr.write(out)
                raise CommandError("Sphinx build failed.")

        # 4) Normalize output to docs/_build/html
        final_index = self._normalize_output(build_dir_primary, build_dir_alt)

        # 5) Optional: copy to static destination (idempotent)
        if static_dest:
            self.stdout.write(self.style.NOTICE(f"Copying HTML → {static_dest} …"))
            try:
                static_dest.mkdir(parents=True, exist_ok=True)
                # Remove dest content to prevent stale files
                for child in static_dest.iterdir():
                    if child.is_dir():
                        shutil.rmtree(child)
                    else:
                        child.unlink()
                for item in build_dir_primary.iterdir():
                    dest = static_dest / item.name
                    if item.is_dir():
                        shutil.copytree(item, dest)
                    else:
                        shutil.copy2(item, dest)
                self.stdout.write(self.style.SUCCESS(f"Static docs available at: {static_dest}"))
            except Exception as e:
                raise CommandError(f"Failed to copy HTML to static destination: {e}")

        self.stdout.write(self.style.SUCCESS(f"Docs built successfully: {final_index}"))

    # --- helpers -------------------------------------------------------------

    def _run_sphinx_build_via_uv(
        self, source_dir: Path, build_dir: Path, extra_args: Sequence[str]
    ) -> Tuple[int, str]:
        build_dir.mkdir(parents=True, exist_ok=True)
        cmd = ["uv", "run", "-m", "sphinx.cmd.build", "-b", "html"]
        if extra_args:
            cmd += list(extra_args)
        cmd += [str(source_dir), str(build_dir)]
        # cwd = project root (BASE_DIR)
        return run(cmd, cwd=source_dir.parent.parent)

    def _run_sphinx_build_matrix(self, source_dir: Path, docs_dir: Path) -> Tuple[int, str]:
        """
        Use the '-M html' target to let Sphinx manage build dirs (writes to docs/build/html).
        Often helps with env/import nuances because it passes through Sphinx's app-level target.
        """
        cmd = ["uv", "run", "-m", "sphinx.cmd.build", "-M", "html", "source", "build"]
        return run(cmd, cwd=docs_dir)

    def _normalize_output(self, primary: Path, alt: Path) -> Path:
        """
        Ensure final HTML lives under docs/_build/html, copying from docs/build/html if needed.
        """
        if primary.exists():
            final_index = primary / "index.html"
        elif alt.exists():
            self.stdout.write(self.style.NOTICE("Normalizing output: build/html → _build/html …"))
            primary.parent.mkdir(parents=True, exist_ok=True)
            if primary.exists():
                shutil.rmtree(primary)
            shutil.copytree(alt, primary)
            final_index = primary / "index.html"
        else:
            raise CommandError(f"Build succeeded but no HTML dir at {primary} or {alt}")
        if not final_index.exists():
            raise CommandError(f"index.html not found at expected location: {final_index}")
        return final_index
