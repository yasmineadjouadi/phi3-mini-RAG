"""Mise à jour de clés dans le fichier .env à la racine du projet."""
from __future__ import annotations

import os
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def update_dotenv_value(key: str, value: str) -> Path:
    """
    Remplace ou ajoute KEY=value dans .env (racine projet).
    Met aussi à jour os.environ.
    """
    env_path = _project_root() / ".env"
    value_escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    line_out = f'{key}="{value_escaped}"\n'

    lines: list[str] = []
    if env_path.exists():
        with open(env_path, encoding="utf-8") as f:
            lines = f.readlines()

    out: list[str] = []
    found = False
    prefix = f"{key}="
    prefix_spaced = f"{key} ="
    for line in lines:
        s = line.strip()
        if s.startswith(prefix) or s.startswith(prefix_spaced):
            out.append(line_out)
            found = True
        else:
            out.append(line)

    if not found:
        if out and not out[-1].endswith("\n"):
            out[-1] = out[-1] + "\n"
        out.append(line_out)

    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(out)

    os.environ[key] = value
    return env_path
