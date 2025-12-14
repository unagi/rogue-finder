from __future__ import annotations

from nmap_gui.i18n import translate_grouped_key


def _translator_factory(values: dict[str, str]):
    def _translator(key: str) -> str:
        return values.get(key, key)

    return _translator


def test_translate_grouped_key_returns_exact_match():
    translator = _translator_factory({"diagnostics_status/running": "Running"})

    result = translate_grouped_key("diagnostics_status", "running", translator)

    assert result == "Running"


def test_translate_grouped_key_uses_default_subkey_when_missing():
    translator = _translator_factory({"diagnostics_status/not_started": "Idle"})

    result = translate_grouped_key(
        "diagnostics_status",
        "missing",
        translator,
        default_subkey="not_started",
    )

    assert result == "Idle"


def test_translate_grouped_key_returns_literal_when_default_missing():
    translator = _translator_factory({})

    result = translate_grouped_key("diagnostics_status", "unknown", translator)

    assert result == "diagnostics_status/unknown"
