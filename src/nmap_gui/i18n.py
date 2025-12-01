"""Minimal translation helpers for GUI text."""
from __future__ import annotations

from typing import Dict, Iterable, List

from PySide6.QtCore import QLocale

from .models import ErrorRecord

Translations = Dict[str, str]


_TRANSLATIONS: Dict[str, Translations] = {
    "en": {
        "error_action_label": "Action",
        "window_title": "Nmap Discovery & Rating",
        "scan_settings": "Scan Settings",
        "targets_label": "Targets (IP / CIDR / hostname)",
        "targets_placeholder": "192.168.0.0/24\n10.0.0.5\nserver.local",
        "start": "Start",
        "stop": "Stop",
        "label_icmp": "ICMP",
        "label_ports": "Ports",
        "label_os": "OS",
        "export_csv": "Export CSV",
        "export_json": "Export JSON",
        "export_csv_dialog": "Export CSV",
        "export_json_dialog": "Export JSON",
        "export_csv_filter": "CSV Files (*.csv)",
        "export_json_filter": "JSON Files (*.json)",
        "export_csv_done": "CSV exported: {path}",
        "export_json_done": "JSON exported: {path}",
        "ready": "Ready",
        "scanning": "Scanning...",
        "scan_stopped": "Scan stopped",
        "scan_finished": "Scan finished",
        "missing_targets_title": "Missing targets",
        "missing_targets_body": "Please enter at least one target",
        "missing_modes_title": "Missing scan modes",
        "missing_modes_body": "Select at least one scan mode",
        "no_results_title": "No results",
        "no_results_body": "Scan results are empty",
        "summary_title": "Scan Summary",
        "summary_template": (
            "Targets: {targets} | Addresses queued: {requested} | "
            "Hosts found: {discovered} | Alive: {alive} | Status: {status}"
        ),
        "summary_status_idle": "Idle",
        "summary_status_no_hosts": "No hosts responded",
        "table_target": "Target",
        "table_alive": "Alive",
        "table_ports": "Ports",
        "table_os": "OS",
        "table_score": "Score",
        "table_priority": "Priority",
        "table_errors": "Errors",
        "alive_yes": "Yes",
        "alive_no": "No",
        "scan_error_title": "Scan error",
        "priority_high": "High",
        "priority_medium": "Medium",
        "priority_low": "Low",
        "error.scan_aborted.message": "Scan was aborted before completion.",
        "error.scan_aborted.action": "Start the scan again when you are ready.",
        "error.nmap_not_found.message": "Nmap executable was not found on PATH.",
        "error.nmap_not_found.action": "Install Nmap and ensure the nmap command is available.",
        "error.nmap_timeout.message": "Nmap did not finish within {timeout} seconds.",
        "error.nmap_timeout.action": "Reduce the target scope or increase the timeout, then retry.",
        "error.nmap_failed.message": "Nmap reported an execution error: {detail}.",
        "error.nmap_failed.action": "Inspect the error details, adjust options, and rerun.",
        "error.worker_pool_failed.message": "Worker processes stopped unexpectedly.",
        "error.worker_pool_failed.action": "Retry with fewer targets or restart the application.",
        "error.scan_crashed.message": "Scan execution crashed: {detail}.",
        "error.scan_crashed.action": "Review the log/targets, then run the scan again.",
        "privileged_os_required_title": "Administrator privileges required",
        "privileged_os_required_body": (
            "OS fingerprinting requires elevated privileges on this platform.\n"
            "Close the app and re-launch it from Terminal with:\n{command}\n\n"
            "Or uncheck the OS scan mode to continue without OS detection."
        ),
    },
    "ja": {
        "error_action_label": "対応",
        "window_title": "Nmap 解析・評価",
        "scan_settings": "スキャン設定",
        "targets_label": "ターゲット (IP / CIDR / ホスト名)",
        "targets_placeholder": "192.168.0.0/24\n10.0.0.5\nserver.local",
        "start": "開始",
        "stop": "停止",
        "label_icmp": "ICMP",
        "label_ports": "ポート",
        "label_os": "OS",
        "export_csv": "CSV出力",
        "export_json": "JSON出力",
        "export_csv_dialog": "CSV出力",
        "export_json_dialog": "JSON出力",
        "export_csv_filter": "CSVファイル (*.csv)",
        "export_json_filter": "JSONファイル (*.json)",
        "export_csv_done": "CSVを書き出しました: {path}",
        "export_json_done": "JSONを書き出しました: {path}",
        "ready": "待機中",
        "scanning": "スキャン中...",
        "scan_stopped": "スキャンを停止しました",
        "scan_finished": "スキャンが完了しました",
        "missing_targets_title": "ターゲット未入力",
        "missing_targets_body": "少なくとも1つのターゲットを入力してください",
        "missing_modes_title": "スキャンモード未選択",
        "missing_modes_body": "少なくとも1つのスキャンモードを選択してください",
        "no_results_title": "結果なし",
        "no_results_body": "スキャン結果がありません",
        "summary_title": "結果サマリ",
        "summary_template": (
            "ターゲット: {targets} | 想定ノード数: {requested} | "
            "検出ノード: {discovered} | 生存: {alive} | 状態: {status}"
        ),
        "summary_status_idle": "未実行",
        "summary_status_no_hosts": "ホストは検出されませんでした",
        "table_target": "ターゲット",
        "table_alive": "生存",
        "table_ports": "ポート",
        "table_os": "OS",
        "table_score": "スコア",
        "table_priority": "優先度",
        "table_errors": "エラー",
        "alive_yes": "はい",
        "alive_no": "いいえ",
        "scan_error_title": "スキャンエラー",
        "priority_high": "高",
        "priority_medium": "中",
        "priority_low": "低",
        "error.scan_aborted.message": "スキャンが完了する前に中断されました。",
        "error.scan_aborted.action": "準備ができたら再度スキャンを開始してください。",
        "error.nmap_not_found.message": "PATH 上に nmap 実行ファイルが見つかりません。",
        "error.nmap_not_found.action": "Nmap をインストールし、コマンドが利用できる状態にしてください。",
        "error.nmap_timeout.message": "Nmap が {timeout} 秒以内に完了しませんでした。",
        "error.nmap_timeout.action": "ターゲット数を減らすかタイムアウト値を延長して再実行してください。",
        "error.nmap_failed.message": "Nmap の実行でエラーが発生しました: {detail}。",
        "error.nmap_failed.action": "エラー内容を確認し、設定を調整して再実行してください。",
        "error.worker_pool_failed.message": "ワーカープロセスが予期せず停止しました。",
        "error.worker_pool_failed.action": "ターゲットを減らして再試行するか、アプリを再起動してください。",
        "error.scan_crashed.message": "スキャン実行で障害が発生しました: {detail}。",
        "error.scan_crashed.action": "ログとターゲットを確認し、再度スキャンしてください。",
        "privileged_os_required_title": "管理者権限が必要です",
        "privileged_os_required_body": (
            "この環境で OS 指紋検出を行うには管理者権限が必要です。\n"
            "アプリを終了し、ターミナルから次のコマンドで再起動してください:\n{command}\n\n"
            "OS 判定を行わない場合は、OS モードのチェックを外して再実行してください。"
        ),
    },
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


def _format_template(template: str, context: Dict[str, str]) -> str:
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


def format_error_list(records: Iterable[ErrorRecord], lang: str | None = None) -> List[str]:
    return [format_error_record(record, lang) for record in records]
