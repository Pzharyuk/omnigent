"""Write a grok CLI session file into a managed sandbox HOME."""

from __future__ import annotations

import os
from pathlib import Path


def write_grok_auth_json_from_env() -> None:
    """Materialize ``$HOME/.grok/auth.json`` from ``GROK_AUTH_JSON`` when set.

    The per-launch token Secret carries the owner's Grok session as
    ``GROK_AUTH_JSON``. The init container shares HOME with the host, so
    writing the file here is what ``grok agent stdio`` reads — env alone
    is not enough (OAuth session beats ``XAI_API_KEY`` only when
    ``auth.json`` exists).
    """
    raw = os.environ.get("GROK_AUTH_JSON", "").strip()
    if not raw:
        return
    home = os.environ.get("HOME") or "/home/omnigent"
    dest = Path(home) / ".grok" / "auth.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(raw)
    dest.chmod(0o600)
