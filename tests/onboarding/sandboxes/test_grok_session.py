"""Init-container helper that materializes a grok CLI session file."""

from __future__ import annotations

from omnigent.onboarding.sandboxes.grok_session import write_grok_auth_json_from_env


def test_write_skips_when_unset(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("GROK_AUTH_JSON", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    write_grok_auth_json_from_env()
    assert not (tmp_path / ".grok" / "auth.json").exists()


def test_write_auth_json(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("GROK_AUTH_JSON", '{"k":1}')
    write_grok_auth_json_from_env()
    dest = tmp_path / ".grok" / "auth.json"
    assert dest.read_text() == '{"k":1}'
    assert dest.stat().st_mode & 0o777 == 0o600
