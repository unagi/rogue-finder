
"""Regression tests for translation catalog integrity."""
from __future__ import annotations

import ast
from collections.abc import Iterable
from importlib import import_module
from pathlib import Path

I18N_DIR = Path("src/nmap_gui/i18n")
CATALOG_FILES = {"en.py", "ja.py"}
MIN_GROUPED_ARGS = 2
LITERAL_PATTERNS = (
    "self._t",
    "self._translator",
    "self._set_summary_state",
    "translator",
    "translate",
    "_label",
    "translate_grouped_key",
)

TRANSLATION_HELPER_NAMES = set(LITERAL_PATTERNS)
TRANSLATION_HELPER_NAMES.add("self._label")


def _load_catalog_keys() -> tuple[set[str], set[str]]:
    en_catalog = import_module("nmap_gui.i18n.en")
    ja_catalog = import_module("nmap_gui.i18n.ja")
    return set(en_catalog.TRANSLATIONS), set(ja_catalog.TRANSLATIONS)


def _iter_sources() -> Iterable[Path]:
    for root in (Path("src"), Path("tests")):
        for path in root.rglob("*.py"):
            if path.parent == I18N_DIR and path.name in CATALOG_FILES:
                continue
            yield path


def _collect_literal_usage(catalog_keys: set[str]) -> set[str]:
    keys: set[str] = set()
    for _source_path, tree in _iter_source_trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = _call_name(node.func)
                if func_name == "translate_grouped_key":
                    keys.update(_collect_grouped_keys(node, catalog_keys))
                elif func_name in TRANSLATION_HELPER_NAMES:
                    key = _string_arg(node)
                    if key:
                        keys.add(key)
                keys.update(_collect_error_keys(node))
    return keys


def _iter_source_trees() -> Iterable[tuple[Path, ast.AST]]:
    for source_path in _iter_sources():
        yield source_path, ast.parse(
            source_path.read_text(encoding="utf-8"), filename=str(source_path)
        )


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _string_arg(call: ast.Call) -> str | None:
    if call.args:
        first = call.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
    return None


def _collect_grouped_keys(node: ast.Call, catalog_keys: set[str]) -> set[str]:
    keys: set[str] = set()
    category_value = None
    if node.args:
        category = node.args[0]
        if isinstance(category, ast.Constant) and isinstance(category.value, str):
            category_value = category.value
    if category_value is None:
        return keys
    if len(node.args) >= MIN_GROUPED_ARGS:
        subkey = node.args[1]
        if isinstance(subkey, ast.Constant) and isinstance(subkey.value, str):
            keys.add(f"{category_value}/{subkey.value}")
    for keyword in node.keywords or []:
        if keyword.arg == "default_subkey" and isinstance(keyword.value, ast.Constant):
            keys.add(f"{category_value}/{keyword.value.value}")
    prefix = f"{category_value}/"
    keys.update(key for key in catalog_keys if key.startswith(prefix))
    return keys


def _collect_error_keys(node: ast.Call) -> set[str]:
    keys: set[str] = set()
    for keyword in node.keywords or []:
        if (
            keyword.arg in {"message_key", "action_key"}
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
        ):
            keys.add(keyword.value.value)
    return keys


def _collect_group_categories_in_use() -> set[str]:
    categories: set[str] = set()
    for _path, tree in _iter_source_trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _call_name(node.func) == "translate_grouped_key":
                category = _string_arg(node)
                if category:
                    categories.add(category)
    return categories


def test_catalogs_stay_in_sync() -> None:
    en_keys, ja_keys = _load_catalog_keys()
    missing_in_ja = sorted(en_keys - ja_keys)
    missing_in_en = sorted(ja_keys - en_keys)
    assert not missing_in_ja and not missing_in_en, (
        f"Keys missing in ja: {missing_in_ja} | Keys missing in en: {missing_in_en}"
    )


def test_english_keys_are_used() -> None:
    en_keys, _ = _load_catalog_keys()
    used_keys = _collect_literal_usage(en_keys)
    unused = sorted(key for key in en_keys if key not in used_keys)
    assert not unused, f"Unused translation keys detected: {unused}"


def test_grouped_keys_have_translate_calls() -> None:
    en_keys, _ = _load_catalog_keys()
    grouped_categories = {key.split("/", 1)[0] for key in en_keys if "/" in key}
    helper_categories = _collect_group_categories_in_use()
    missing = sorted(grouped_categories - helper_categories)
    assert not missing, (
        "Grouped translation categories missing translate_grouped_key usage: " f"{missing}"
    )


def test_catalog_keys_use_single_group_separator() -> None:
    en_keys, ja_keys = _load_catalog_keys()
    invalid = sorted(
        key
        for key in en_keys | ja_keys
        if key.count("/") > 1
    )
    assert not invalid, f"Invalid grouped key format (multiple '/'): {invalid}"
