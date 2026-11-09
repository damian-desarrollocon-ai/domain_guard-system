import json
from datetime import datetime

from domainguard.core.report_generator import default_report_path, to_json, write_json
from domainguard.core.scanner import Scanner

from .helpers import FakeResolver, ok

D = "example.com"


def make_result():
    answers = {
        (D, "A"): ok(D, "A", "93.184.216.34"),
        (D, "NS"): ok(D, "NS", "ns1.x.net.", "ns2.x.net."),
    }
    return Scanner(resolver_factory=lambda: FakeResolver(answers)).scan(D)


def test_json_is_valid_and_has_expected_structure():
    data = json.loads(to_json(make_result()))
    for key in ("tool_version", "domain", "started_at", "finished_at", "modules", "findings",
                "risk", "limitations", "authorization_notice", "dns_records", "assessed"):
        assert key in data
    assert data["domain"] == D
    assert isinstance(data["risk"]["score"], int)
    assert data["risk"]["method"] and data["risk"]["lines"]
    assert [m["name"] for m in data["modules"]][0] == "dns_analysis"


def test_findings_serialize_with_all_required_fields():
    data = json.loads(to_json(make_result()))
    required = {"id", "module", "title", "description", "evidence", "severity", "category",
                "technical_explanation", "business_impact", "remediation", "confidence",
                "validation_limitations"}
    assert data["findings"]
    for finding in data["findings"]:
        assert required <= set(finding)
        assert isinstance(finding["severity"], str)


def test_timestamps_are_iso_8601():
    data = json.loads(to_json(make_result()))
    parsed = datetime.fromisoformat(data["started_at"].replace("Z", "+00:00"))
    assert parsed.tzinfo is not None


def test_accents_are_preserved_not_escaped():
    text = to_json(make_result())
    assert "\\u00" not in text
    assert "evaluación" in text or "Evaluación" in text or "autorización" in text


def test_write_json_creates_folders_and_roundtrips(tmp_path):
    result = make_result()
    target = write_json(result, tmp_path / "nested" / "dir" / "out.json")
    assert target.exists()
    assert json.loads(target.read_text(encoding="utf-8"))["domain"] == D


def test_default_report_path_is_safe_and_timestamped():
    result = make_result()
    path = default_report_path(result, "json")
    assert path.parent.name == "reports_output"
    assert path.name.startswith("example.com_") and path.name.endswith(".json")
    stamp = result.started_at.strftime("%Y%m%d_%H%M%S")
    assert stamp in path.name
    html = default_report_path(result, ".html", "out")
    assert html.parent.name == "out" and html.suffix == ".html"