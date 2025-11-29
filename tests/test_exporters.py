import csv
import json

from nmap_gui.error_codes import ERROR_SCAN_ABORTED, build_error
from nmap_gui.exporters import export_csv, export_json
from nmap_gui.i18n import format_error_record
from nmap_gui.models import HostScanResult


def _sample_result() -> HostScanResult:
    return HostScanResult(
        target="10.0.0.5",
        is_alive=True,
        open_ports=[22, 80],
        os_guess="Windows 10",
        os_accuracy=98,
        high_ports=[50000],
        score_breakdown={"icmp": 2, "port 22": 2},
        score=7,
        priority="Medium",
        errors=[build_error(ERROR_SCAN_ABORTED)],
    )


def test_export_csv_round_trip(tmp_path):
    result = _sample_result()
    csv_path = tmp_path / "results.csv"
    export_csv(csv_path, [result], language="en")
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["target"] == "10.0.0.5"
    assert rows[0]["open_ports"] == "22,80"
    assert rows[0]["score"] == "7"
    expected_error = format_error_record(result.errors[0], "en")
    assert rows[0]["errors"] == expected_error


def test_export_json_serializes_full_object(tmp_path):
    result = _sample_result()
    json_path = tmp_path / "results.json"
    export_json(json_path, [result], language="en")
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data[0]["target"] == "10.0.0.5"
    assert data[0]["priority"] == "Medium"
    assert data[0]["score_breakdown"]["icmp"] == 2
    assert data[0]["errors"][0]["code"] == "RF001"
    expected_error = format_error_record(result.errors[0], "en")
    assert data[0]["errors_text"][0] == expected_error
