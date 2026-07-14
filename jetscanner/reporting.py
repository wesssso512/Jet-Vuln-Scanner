"""Report building and cross-platform file opening.

Fixes vs V1:
  * Reports are written into a ``reports/`` folder (created on demand) instead
    of the current working directory.
  * Opening the report / its folder works on Windows, macOS and Linux, and
    never shells out with an interpolated string.
"""
from __future__ import annotations

import datetime
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

from .models import ModuleResult

Advice = Tuple[str, str]

_SEP = "=" * 60


def build_report(
    target: str,
    started_at: str,
    modules: Sequence[ModuleResult],
    advice: Iterable[Advice] = (),
) -> str:
    """Render the full text report from structured results."""
    lines: List[str] = [
        _SEP,
        " Jet Vulnerability Scanner — Report",
        _SEP,
        f" Target : {target}",
        f" Started: {started_at}",
        _SEP,
        "",
    ]
    for module in modules:
        lines.append(f"[ {module.module} ]")
        lines.append(module.text if module.lines else "(no output)")
        lines.append("")

    advice = list(advice)
    if advice:
        lines += ["", _SEP, " Security Advisor", _SEP, ""]
        for title, body in advice:
            lines.append(title)
            lines.append(body)
            lines.append("-" * 40)
            lines.append("")

    return "\n".join(lines)


def save_report(content: str, reports_dir: str = "reports") -> Path:
    """Write ``content`` to a timestamped file inside ``reports_dir``."""
    directory = Path(reports_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = directory / f"Report_{stamp}.txt"
    path.write_text(content, encoding="utf-8")
    return path


def open_file(path: os.PathLike) -> None:
    """Open ``path`` with the OS default handler (cross-platform)."""
    path = str(path)
    if sys.platform.startswith("win"):
        os.startfile(path)  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.run(["open", path], check=False)
    else:
        subprocess.run(["xdg-open", path], check=False)


def reveal_in_folder(path: os.PathLike) -> None:
    """Reveal ``path`` in the system file browser, selecting it if possible."""
    path = os.path.abspath(str(path))
    if sys.platform.startswith("win"):
        subprocess.run(["explorer", "/select,", path], check=False)
    elif sys.platform == "darwin":
        subprocess.run(["open", "-R", path], check=False)
    else:
        # Most Linux file managers can't reliably select; open the parent dir.
        subprocess.run(["xdg-open", os.path.dirname(path)], check=False)
