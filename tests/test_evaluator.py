"""Tests for the Evaluator (evaluator/agent.py): reviewing one component, with a fake model."""

import json

from evaluator.agent import check_review, review_component
from shared.skills import get_skill

STATEMENT = (
    "When the File Importer reads a file header, the File Importer shall reject "
    "each filename field longer than 255 bytes."
)


def req(number=1, cve="CVE-2023-12345", statement=STATEMENT, **extra):
    r = {
        "id": f"REQ-{number:03d}",
        "component": "ExampleApp",
        "statement": statement,
        "rationale": "An unbounded filename allows out-of-bounds writes.",
        "sources": {"cves": [cve], "cwes": ["CWE-787"]},
        "verification": {"method": "Test", "criterion": "A 256-byte filename is rejected."},
        "assumptions": [],
        "gate_status": "passed",
    }
    r.update(extra)
    return r


def cve_row(cve_id="CVE-2023-12345"):
    return {"cve_id": cve_id, "system": "ExampleApp", "description": "Buffer overflow."}


def review(r, verdict="pass", **extra):
    rv = {
        "id": r["id"], "quote": r["statement"], "reasoning": "Singular, testable, matches the CVE.",
        "problems": [], "verdict": verdict, "severity": "none", "suggested_rewrite": "",
    }
    rv.update(extra)
    return rv


def reply(*reviews, **other):
    return json.dumps({"requirements": list(reviews), **other})


class FakeModel:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = []

    def __call__(self, messages, tools, **kwargs):
        self.calls.append([dict(m) for m in messages])
        return self.replies[min(len(self.calls), len(self.replies)) - 1]


def run(model, reqs, cves=None):
    return review_component(model, "ExampleApp", reqs, cves or [cve_row()])


# ---- Checking one review ----------------------------------------------------------

def test_a_quote_that_is_not_in_the_requirement_is_flagged():
    r = req()
    assert check_review(review(r), r)["flags"] == []
    assert "quote_mismatch" in check_review(review(r, quote="The File Importer shall be secure."), r)["flags"]
    assert "quote_mismatch" in check_review(review(r, quote=""), r)["flags"]


def test_a_revise_with_nothing_to_act_on_is_flagged():
    r = req()
    bare = review(r, "revise", severity="major", reasoning="")  # just the word "revise": no problem, reasoning or rewrite
    assert "revise_without_evidence" in check_review(bare, r)["flags"]
    full = review(r, "revise", severity="major", problems=[{"rule": "singular"}], suggested_rewrite="New text.")
    assert check_review(full, r)["flags"] == []


def test_a_revise_explained_only_in_the_reasoning_keeps_that_as_the_problem_instead_of_being_flagged():
    r = req()
    explained = review(r, "revise", severity="major", reasoning="The word quickly cannot be tested.")  # problems: []
    cleaned = check_review(explained, r)
    assert cleaned["flags"] == []
    assert cleaned["problems"] == [{"rule": "", "evidence": "", "explanation": "The word quickly cannot be tested."}]


def test_a_revise_with_a_problem_but_no_rewrite_is_not_flagged():
    r = req()
    cleaned = check_review(review(r, "revise", problems=[{"rule": "vague_term", "explanation": "quickly"}]), r)
    assert cleaned["flags"] == [] and cleaned["suggested_rewrite"] == ""


def test_the_models_other_ways_of_writing_problems_and_rewrites_are_accepted():
    r = req()
    for problems in ("vague word: quickly", {"rule": "vague_term"}, ["vague word", {"rule": "singular"}]):
        cleaned = check_review(review(r, "revise", problems=problems), r)
        assert cleaned["flags"] == [] and cleaned["problems"] and all(isinstance(p, dict) for p in cleaned["problems"])
    other_names = review(r, "revise", problems=[], suggested_rewrite="")
    other_names.update({"issues": [{"rule": "singular"}], "rewrite": ["The importer shall do one thing."]})
    cleaned = check_review(other_names, r)
    assert cleaned["problems"] == [{"rule": "singular"}] and cleaned["suggested_rewrite"] == "The importer shall do one thing."
    assert cleaned["flags"] == []


def test_the_issue_text_reads_naturally_whether_or_not_a_rule_was_named():
    r = req()
    named = check_review(review(r, "revise", problems=[{"rule": "vague_term"}], suggested_rewrite="Use 200 ms."), r)
    unnamed = check_review(review(r, "revise", reasoning="It cannot be tested."), r)
    result = run(FakeModel(reply(review(r, "revise", problems=[{"rule": "vague_term"}], suggested_rewrite="Use 200 ms."))), [r])
    assert result["issues"]["REQ-001"] == ["vague_term: Use 200 ms."]
    result = run(FakeModel(reply(review(r, "revise", reasoning="It cannot be tested."))), [r])
    assert result["issues"]["REQ-001"] == ["It cannot be tested."]  # no stray "rule:" prefix
    assert result["rewrite_requests"][0]["instructions"] == "REQ-001 (rule not named): It cannot be tested."
    assert named["flags"] == [] and unnamed["flags"] == []


def test_a_bare_revise_is_sent_back_once_with_what_is_missing_and_a_proper_answer_is_used():
    r = req()
    bare = review(r, "revise", severity="major", reasoning="")
    proper = review(r, "revise", severity="major", problems=[{"rule": "verifiable"}], suggested_rewrite="New text.")
    model = FakeModel(reply(bare), reply(proper))
    result = run(model, [r])
    assert len(model.calls) == 2
    assert "needs at least one item in \"problems\" and a \"suggested_rewrite\"" in model.calls[1][-1]["content"]
    assert result["reviews"][0]["flags"] == [] and result["reviews"][0]["suggested_rewrite"] == "New text."


def test_the_skills_own_example_is_a_valid_pass_and_a_valid_revise():
    # The model copies the shape of the skill's example, so the example must be one this code accepts.
    skill = get_skill("incose-evaluator")["instructions"]
    example = skill.split('"revise":\n', 1)[1].splitlines()[0]
    first, second = json.loads(example)["requirements"]
    pass_req = req(1, statement=first["quote"])
    revise_req = req(2, statement=second["quote"])
    passed, revised = check_review(first | {"id": "REQ-001"}, pass_req), check_review(second | {"id": "REQ-002"}, revise_req)
    assert (passed["verdict"], passed["flags"], passed["problems"]) == ("pass", [], [])
    assert (revised["verdict"], revised["flags"]) == ("revise", [])
    assert revised["problems"][0]["rule"] and revised["suggested_rewrite"]  # a real revise: problem and rewrite

# ---- Reviewing a component ---------------------------------------------------------

def test_a_clean_component_passes_in_one_call():
    r = req()
    model = FakeModel(reply(review(r)))
    result = run(model, [r])
    assert result["overall"] == "pass" and result["status"] == "checked"
    assert result["requirement_status"] == {"REQ-001": "pass"}
    assert result["issues"] == {"REQ-001": []} and result["component_issues"] == []
    assert result["rewrite_requests"] == []
    assert len(model.calls) == 1


def test_gate_status_is_not_shown_to_the_model():
    model = FakeModel(reply(review(req())))
    run(model, [req()])
    assert "gate_status" not in model.calls[0][-1]["content"]


def test_revise_verdicts_become_rewrite_requests_grouped_by_cve():
    a, b = req(1, cve="CVE-2023-00001"), req(2, cve="CVE-2023-00002")
    bad = review(b, "revise", severity="major", problems=[{"rule": "vague_term", "evidence": "fast"}],
                 suggested_rewrite="The File Importer shall respond within 200 ms.")
    result = run(FakeModel(reply(review(a), bad)), [a, b], [cve_row("CVE-2023-00001"), cve_row("CVE-2023-00002")])
    assert result["overall"] == "revise"
    assert result["rewrite_requests"] == [
        {"cves": ["CVE-2023-00002"], "ids": ["REQ-002"],
         "instructions": "REQ-002 (vague_term): The File Importer shall respond within 200 ms."}
    ]
    assert result["requirement_status"] == {"REQ-001": "pass", "REQ-002": "needs_review"}
    assert result["issues"]["REQ-002"] == ["vague_term: The File Importer shall respond within 200 ms."]


def test_a_pass_with_a_made_up_quote_needs_review_but_is_not_sent_back_for_a_rewrite():
    r = req()
    result = run(FakeModel(reply(review(r, quote="Totally different."))), [r])
    assert result["overall"] == "revise"
    assert result["requirement_status"] == {"REQ-001": "needs_review"}
    assert "human check" in result["issues"]["REQ-001"][0]
    assert result["rewrite_requests"] == []  # nothing the Vulnerability Expert could fix


def test_unreadable_model_reply_means_unchecked_and_incomplete_never_pass():
    result = run(FakeModel("I think they look fine!"), [req()])
    assert result["overall"] == "incomplete" and result["status"] == "unchecked"
    assert result["requirement_status"] == {"REQ-001": "needs_review"}
    assert "no usable review" in result["component_issues"][0]


def test_a_requirement_the_model_skipped_is_not_reviewed_and_incomplete():
    a, b = req(1), req(2)
    model = FakeModel(reply(review(a)))  # never mentions REQ-002, even after the retry
    result = run(model, [a, b])
    assert result["overall"] == "incomplete"
    assert [rv["verdict"] for rv in result["reviews"]] == ["pass", "not_reviewed"]
    assert len(model.calls) == 2  # one retry, with the problem listed
    assert "REQ-002 was not reviewed" in model.calls[1][-1]["content"]


def test_a_cve_with_no_requirement_is_reported_and_sent_back_for_a_new_one():
    result = run(FakeModel(reply(review(req()))), [req()], [cve_row(), cve_row("CVE-2023-99999")])
    assert result["code_checks"]["uncovered_cves"] == ["CVE-2023-99999"]
    assert result["overall"] == "revise"
    assert result["component_issues"] == ["No requirement covers CVE-2023-99999."]
    assert result["rewrite_requests"] == [
        {"cves": ["CVE-2023-99999"], "ids": [], "instructions": "No requirement was written for CVE-2023-99999. Write one."}
    ]


def test_duplicate_ids_and_unknown_cves_are_found_by_code():
    result = run(FakeModel(reply(review(req()))), [req(), req(cve="CVE-2023-77777")])
    assert result["code_checks"]["duplicate_ids"] == ["REQ-001"]
    assert result["code_checks"]["unknown_cves"] == ["CVE-2023-77777"]
    assert result["overall"] == "revise"


def test_no_requirements_means_incomplete_and_no_model_call():
    model = FakeModel("unused")
    result = run(model, [])
    assert result["overall"] == "incomplete"
    assert model.calls == []
    assert "No requirements were written" in result["component_issues"][0]


def test_failed_gate_requirements_need_review():
    r = req(statement="The File Importer should reject long names.", gate_status="failed_gate")
    result = run(FakeModel(reply(review(r))), [r])
    assert result["gate"]["passed"] is False
    assert result["requirement_status"] == {"REQ-001": "needs_review"}
    assert "word check: forbidden_verb" in result["issues"]["REQ-001"]


def test_model_found_duplicates_and_contradictions_are_reported_for_the_component():
    a, b = req(1), req(2)
    result = run(FakeModel(reply(review(a), review(b), duplicates=["REQ-001 and REQ-002 say the same"])), [a, b])
    assert result["overall"] == "revise"
    assert result["component_issues"] == ["Duplicate: REQ-001 and REQ-002 say the same"]


def test_a_component_is_reviewed_in_one_model_call_however_many_requirements_it_has():
    reqs = [req(i, cve=f"CVE-2023-{i:05d}") for i in range(1, 31)]
    cves = [cve_row(f"CVE-2023-{i:05d}") for i in range(1, 31)]
    model = FakeModel(reply(*[review(r) for r in reqs]))
    assert run(model, reqs, cves)["overall"] == "pass"
    assert len(model.calls) == 1
