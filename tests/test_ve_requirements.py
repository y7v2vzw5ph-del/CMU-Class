"""Tests for the Vulnerability Expert's requirements writing (vulnerability_expert/requirements.py)."""

import json

import pytest

from tests.requirements_fakes import BAD_PHRASE, ScriptedModel
from vulnerability_expert.requirements import (
    MAX_ATTEMPTS,
    next_number,
    normalize,
    parse_requirements,
    prepare_cve,
    revise_component_requirements,
    write_component_requirements,
)

GOOD_STATEMENT = (
    "When the File Importer reads a file header, the File Importer shall reject "
    "each filename field longer than 255 bytes."
)


def requirement(**overrides):
    req = {
        "id": "REQ-999",  # the model's number: code replaces it
        "component": "ignored",
        "statement": GOOD_STATEMENT,
        "rationale": "An unbounded filename allows out-of-bounds writes.",
        "sources": {"cves": ["CVE-0000-0000"], "cwes": ["CWE-787"]},  # wrong CVE on purpose
        "verification": {"method": "Test", "criterion": "A 256-byte filename is rejected."},
        "assumptions": [],
        "gate_status": "passed",
    }
    req.update(overrides)
    return req


def cve(cve_id="CVE-2023-12345", system="ExampleApp 2.1"):
    return {"cve_id": cve_id, "system": system, "description": "Buffer overflow.", "cvss": 9.8}


class FakeModel:
    """Returns the scripted replies in order (the last one repeats) and remembers every call."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = []

    def __call__(self, messages, tools, **kwargs):
        self.calls.append([dict(m) for m in messages])
        return self.replies[min(len(self.calls), len(self.replies)) - 1]


def as_reply(*reqs):
    return json.dumps(list(reqs))


# ---- Reading the reply ------------------------------------------------------------

def test_parse_accepts_fences_intro_text_and_a_single_object():
    assert parse_requirements("```json\n" + as_reply(requirement()) + "\n```")[0]["statement"] == GOOD_STATEMENT
    assert len(parse_requirements("Here you go: " + as_reply(requirement(), requirement()))) == 2
    assert len(parse_requirements(json.dumps(requirement()))) == 1


@pytest.mark.parametrize("text", ["", "no json here", "[]", "[1, 2]", '{"a": '])
def test_parse_rejects_unusable_replies(text):
    with pytest.raises(ValueError):
        parse_requirements(text)


def test_code_sets_ids_component_and_the_cve_not_the_model():
    items = [requirement(), requirement()]
    result = normalize(items, prepare_cve(cve()), "ExampleApp 2.1", first_number=5)
    assert [r["id"] for r in result] == ["REQ-005", "REQ-006"]
    assert {r["component"] for r in result} == {"ExampleApp 2.1"}
    assert result[0]["sources"]["cves"] == ["CVE-2023-12345"]
    assert items[0]["id"] == "REQ-999"  # the model's own object is not changed


def test_cwes_come_from_the_nvd_record_not_from_the_model():
    guessed = requirement(sources={"cves": ["CVE-0000-0000"], "cwes": ["CWE-79"]})  # the model guesses XSS
    with_cwes = prepare_cve({**cve(), "cwes": ["CWE-787", "CWE-20"]})
    assert normalize([guessed], with_cwes, "X", 1)[0]["sources"]["cwes"] == ["CWE-787", "CWE-20"]
    no_cwes = prepare_cve(cve())  # NVD listed none: the model's guess must not reach the table
    assert normalize([guessed], no_cwes, "X", 1)[0]["sources"]["cwes"] == []


def test_a_rewrite_reuses_the_old_ids_and_extra_requirements_get_new_ones():
    result = normalize([requirement(), requirement(), requirement()], prepare_cve(cve()), "X", 10, reuse_ids=["REQ-003"])
    assert [r["id"] for r in result] == ["REQ-003", "REQ-010", "REQ-011"]


def test_next_number():
    assert next_number([]) == 1
    assert next_number([{"id": "REQ-004"}, {"id": "REQ-002"}, {"id": "junk"}]) == 5


# ---- Writing one component (the retry loop) ---------------------------------------

def test_passes_on_the_first_try():
    model = FakeModel(as_reply(requirement()))
    out = write_component_requirements(model, "ExampleApp 2.1", [cve()])
    assert out["cves"] == [
        {"cve_id": "CVE-2023-12345", "status": "passed", "attempts": 1, "unresolved": [], "requirement_ids": ["REQ-001"]}
    ]
    assert out["requirements"][0]["gate_status"] == "passed"
    assert out["requirements"][0]["component"] == "ExampleApp 2.1"
    assert len(model.calls) == 1


def test_gate_errors_are_shown_to_the_model_and_it_gets_to_fix_them():
    bad = requirement(statement="The File Importer should reject long names.")
    model = FakeModel(as_reply(bad), as_reply(requirement()))
    out = write_component_requirements(model, "X", [cve()])
    assert out["cves"][0]["status"] == "passed" and out["cves"][0]["attempts"] == 2
    feedback = model.calls[1][-1]["content"]
    assert "forbidden_verb" in feedback and "missing_shall" in feedback
    assert out["requirements"][0]["statement"] == GOOD_STATEMENT


def test_gives_up_after_the_cap_and_marks_failed_gate_then_moves_on():
    bad = requirement(statement="The File Importer should reject long names.")
    model = FakeModel(as_reply(bad), as_reply(bad), as_reply(bad), as_reply(requirement()))
    out = write_component_requirements(model, "X", [cve("CVE-2023-00001"), cve("CVE-2023-00002")])
    first, second = out["cves"]
    assert first["status"] == "failed_gate" and first["attempts"] == MAX_ATTEMPTS
    assert "forbidden_verb" in first["unresolved"]
    assert second["status"] == "passed"
    failed, good = out["requirements"]
    assert failed["gate_status"] == "failed_gate"
    assert "Unresolved gate rules" in failed["assumptions"][-1]
    assert good["id"] == "REQ-002"  # numbering continues across CVEs


def test_a_model_that_never_returns_json_gives_no_output_without_crashing():
    out = write_component_requirements(FakeModel("sorry, I can't"), "X", [cve()])
    assert out["requirements"] == []
    assert out["cves"][0]["status"] == "no_output"


def test_numbering_starts_where_the_caller_says():
    out = write_component_requirements(FakeModel(as_reply(requirement())), "X", [cve()], first_number=7)
    assert out["requirements"][0]["id"] == "REQ-007"


# ---- Revising after the Evaluator -------------------------------------------------

def written(bad_first=(), cves=None, never_fixed=()):
    cves = cves or [cve("CVE-2023-00001", "Router"), cve("CVE-2023-00002", "Router")]
    model = ScriptedModel(bad_first=bad_first, never_fixed=never_fixed)
    return model, cves, write_component_requirements(model, "Router", cves)["requirements"]


def request_for(cve_id, req_id):
    return {"cves": [cve_id], "ids": [req_id], "instructions": f"{req_id} (verifiable): Give a limit."}


def test_revision_rewrites_only_the_cves_with_problems_and_keeps_their_ids():
    model, cves, reqs = written(bad_first={"CVE-2023-00002"})
    assert BAD_PHRASE in reqs[1]["statement"]
    model.calls.clear()
    out = revise_component_requirements(model, "Router", reqs, cves, [request_for("CVE-2023-00002", "REQ-002")])
    assert model.calls == ["revise"]  # CVE-1 was fine, so the model is not asked about it
    assert out["requirements"][0] == reqs[0]
    assert out["requirements"][1]["id"] == "REQ-002"
    assert BAD_PHRASE not in out["requirements"][1]["statement"]
    assert out["cves"][0]["status"] == "passed"


def test_the_model_is_shown_its_earlier_requirement_and_the_problem():
    _, cves, reqs = written(bad_first={"CVE-2023-00001"})
    prompts = []

    def recording(messages, tools, **kwargs):
        prompts.append(messages[-1]["content"])
        return ScriptedModel()(messages, tools, **kwargs)

    revise_component_requirements(recording, "Router", reqs, cves, [request_for("CVE-2023-00001", "REQ-001")])
    assert BAD_PHRASE in prompts[0] and "Give a limit." in prompts[0] and "REQ-001" in prompts[0]
    assert "gate_status" not in prompts[0]


def test_a_failed_rewrite_keeps_the_earlier_requirements():
    _, cves, reqs = written(bad_first={"CVE-2023-00001"})
    out = revise_component_requirements(FakeModel("nonsense"), "Router", reqs, cves, [request_for("CVE-2023-00001", "REQ-001")])
    assert out["requirements"] == reqs
    assert out["cves"][0]["status"] == "kept_previous"


def test_a_cve_with_no_requirement_gets_a_new_one_with_a_fresh_id():
    model, cves, reqs = written()
    only_first = reqs[:1]  # pretend CVE-2 never got a requirement
    request = {"cves": ["CVE-2023-00002"], "ids": [], "instructions": "No requirement was written for CVE-2023-00002. Write one."}
    out = revise_component_requirements(model, "Router", only_first, cves, [request])
    assert [r["id"] for r in out["requirements"]] == ["REQ-001", "REQ-002"]
