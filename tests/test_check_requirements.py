"""Tests for the INCOSE regex gate. Run: uv run --with pytest pytest tests/test_check_requirements.py"""

import importlib.util
import json
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "agents/shared/requirements_gate.py"
spec = importlib.util.spec_from_file_location("requirements_gate", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def make(**overrides):
    req = {
        "id": "REQ-001",
        "component": "File Importer",
        "statement": "When the File Importer reads a file header, the File Importer "
        "shall reject any filename field longer than 255 bytes.",
        "rationale": "Unbounded filename allows out-of-bounds write.",
        "sources": {"cves": ["CVE-2023-12345"], "cwes": ["CWE-787"]},
        "verification": {"method": "Test", "criterion": "256-byte name is rejected."},
        "assumptions": [],
    }
    req.update(overrides)
    return req


def rules(result, kind="errors"):
    return {i["rule"] for i in result[kind]}


def check(req, seen=None):
    return gate.check_requirement(req, seen or set())


def test_good_requirement_passes():
    result = check(make())
    assert result["errors"] == []


def test_missing_shall_and_forbidden_verb():
    result = check(make(statement="The File Importer should reject long names."))
    assert {"missing_shall", "forbidden_verb"} <= rules(result)


def test_and_or_tbd_vague_and_escape():
    result = check(make(statement="The Importer shall reject and/or log robust TBD input where possible."))
    assert {"and_or", "tbd", "vague_term", "escape_clause"} <= rules(result)


def test_compound_is_warning_not_error():
    result = check(make(statement="The Importer shall reject and log invalid files."))
    assert result["errors"] == []
    assert "possible_compound" in rules(result, "warnings")


def test_missing_fields_and_bad_method():
    result = check(make(rationale="", verification={"method": "Vibes", "criterion": "x"}))
    assert {"missing_field", "bad_verification_method"} <= rules(result)


def test_verification_must_be_an_object():
    assert "bad_verification" in rules(check(make(verification="Test it")))


def test_bad_ids_and_duplicates():
    assert "bad_id" in rules(check(make(id="R1")))
    assert "duplicate_id" in rules(check(make(), seen={"REQ-001"}))
    assert "bad_cve_id" in rules(check(make(sources={"cves": ["CVE-1"], "cwes": []})))


def test_check_all_tracks_duplicates_within_batch_and_existing():
    report = gate.check_all([make(), make()], existing=None)
    assert report["passed"] is False
    assert "duplicate_id" in rules(report["results"][1])
    report = gate.check_all([make()], existing=[make()])
    assert report["passed"] is False


def test_cli_exit_codes(tmp_path):
    good, bad = tmp_path / "good.json", tmp_path / "bad.json"
    good.write_text(json.dumps([make()]), encoding="utf-8")
    bad.write_text(json.dumps([make(statement="It should work.")]), encoding="utf-8")
    assert gate.main([str(good)]) == 0
    assert gate.main([str(bad)]) == 1


def test_loads_file_with_utf8_bom(tmp_path):
    f = tmp_path / "bom.json"
    f.write_text(json.dumps([make()]), encoding="utf-8-sig")
    assert gate.main([str(f)]) == 0
