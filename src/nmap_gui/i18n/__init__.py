"""Minimal translation helpers for GUI text."""
from __future__ import annotations

from collections.abc import Callable, Iterable

from PySide6.QtCore import QLocale

try:  # pragma: no cover - direct script execution fallback
    from ..models import ErrorRecord
except ImportError:  # pragma: no cover - PyInstaller bootstrap fallback
    from nmap_gui.models import ErrorRecord

from .en import TRANSLATIONS as EN_TRANSLATIONS
from .ja import TRANSLATIONS as JA_TRANSLATIONS

Translations = dict[str, str]
TranslatorFunc = Callable[[str], str]

# NOTE: Translation tables intentionally reuse identical strings across keys;
# Sonar duplicate-literal warnings (e.g., S1192) should be marked as reviewed
# rather than deduplicated to keep future localization flexible. The full
# catalogs live in en.py and ja.py to keep this module small.
_TRANSLATIONS: dict[str, Translations] = {
    "en": EN_TRANSLATIONS,
    "ja": JA_TRANSLATIONS,
}

DEFAULT_LANGUAGE = "en"


def detect_language() -> str:
    """Return the UI language code based on OS locale."""

    if QLocale.system().language() == QLocale.Language.Japanese:
        return "ja"
    return DEFAULT_LANGUAGE


def translate(key: str, lang: str | None = None) -> str:
    """Simple dictionary lookup with English fallback."""

    language = lang or detect_language()
    catalog = _TRANSLATIONS.get(language, _TRANSLATIONS[DEFAULT_LANGUAGE])
    if key in catalog:
        return catalog[key]
    return _TRANSLATIONS[DEFAULT_LANGUAGE].get(key, key)


def _format_template(template: str, context: dict[str, str]) -> str:
    try:
        return template.format(**context)
    except KeyError:
        return template


def format_error_record(record: ErrorRecord, lang: str | None = None) -> str:
    """Return a localized string combining code, message, and action."""

    language = lang or detect_language()
    message = _format_template(translate(record.message_key, language), record.context)
    action = _format_template(translate(record.action_key, language), record.context)
    action_label = translate("error_action_label", language)
    return f"[{record.code}] {message} ({action_label}: {action})"


def format_error_list(records: Iterable[ErrorRecord], lang: str | None = None) -> list[str]:
    return [format_error_record(record, lang) for record in records]


def translate_grouped_key(
    category: str,
    subkey: str,
    translator: TranslatorFunc,
    *,
    default_subkey: str | None = None,
) -> str:
    """Translate grouped keys (category/subkey) with optional default."""

    key = f"{category}/{subkey}"
    value = translator(key)
    if value != key:
        return value
    if default_subkey is None:
        return value
    fallback_key = f"{category}/{default_subkey}"
    fallback_value = translator(fallback_key)
    return fallback_value
