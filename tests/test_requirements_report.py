"""Tests for the Writer's requirements formatting: the two skills, the checks on the model, the code fallback."""

import pytest

from router.requirements_graph import run_requirements
from shared.skills import get_skill
from tests.requirements_fakes import ScriptedModel
from writer.agent import write_requirements_report
from writer.requirements_report import (
    NEEDS_REVIEW,
    PASS,
    TABLE_MARKER,
    build_requirements_report,
    build_table,
    check_section,
    check_table,
    section_data,
    table_rows,
    write_component,
)

CVES = [
    {"system": "Router", "cve_id": "CVE-2023-00001", "description": "Flaw A", "cvss": 9.8, "severity": "CRITICAL"},
    {"system": "Router", "cve_id": "CVE-2023-00002", "description": "Flaw B", "cvss": 5.0, "severity": "MEDIUM"},
]


def make_item(never_fixed=()):
    return run_requirements(ScriptedModel(never_fixed=never_fixed), CVES)[0]


@pytest.fixture
def passing():
    return make_item()


@pytest.fixture
def failing():
    return make_item(never_fixed={"CVE-2023-00002"})  # REQ-002 is still wrong after the last review


class RecordingModel:
    """Wraps another model, remembers the last message of each call, and answers the first
    `wrong_first` table calls and the first `wrong_first` section calls wrongly."""

    def __init__(self, wrong_first=0):
        self.inner, self.prompts, self.wrong_first, self.seen = ScriptedModel(), [], wrong_first, {}

    def __call__(self, messages, tools, **kwargs):
        self.prompts.append(messages[-1]["content"])
        reply = self.inner(messages, tools, **kwargs)
        kind = self.inner.calls[-1]
        if kind in ("table", "section") and self.seen.get(kind, 0) < self.wrong_first:
            self.seen[kind] = self.seen.get(kind, 0) + 1
            return "nope"
        return reply


# ---- The skills --------------------------------------------------------------------

def test_both_skills_load_by_name_and_have_no_trigger_words():
    for name in ("requirements-table", "requirements-report"):
        skill = get_skill(name)
        assert skill["triggers"] == [] and skill["instructions"]
    assert TABLE_MARKER in get_skill("requirements-report")["instructions"]
    assert "| ID | Requirement | CVE | CWE | Verification | Quality check |" in get_skill("requirements-table")["instructions"]


# ---- Checking the table ------------------------------------------------------------

def test_a_correct_table_passes_the_check(passing):
    rows = table_rows(passing)
    assert check_table(build_table(rows), rows) == []


def test_the_table_check_catches_a_wrong_quality_check_id_cve_row_count_and_text(passing):
    rows = table_rows(passing)
    good = build_table(rows).splitlines()
    wrong_check = "\n".join(good).replace(PASS, NEEDS_REVIEW, 1)
    assert any("Quality check must be" in p for p in check_table(wrong_check, rows))
    assert any("exactly 2 data rows" in p for p in check_table("\n".join(good[:3]), rows))
    wrong_id = "\n".join(good).replace("REQ-001", "REQ-777")
    assert any("ID must be REQ-001" in p for p in check_table(wrong_id, rows))
    wrong_cve = "\n".join(good).replace("CVE-2023-00001", "CVE-2023-99999")
    assert any("CVE must be" in p for p in check_table(wrong_cve, rows))
    reworded = "\n".join(good).replace("When Router", "Whenever the Router")
    assert any("Requirement must be copied" in p for p in check_table(reworded, rows))
    assert check_table("no table here", rows) == ["There is no table in your reply."]


def test_a_pipe_inside_a_requirement_cannot_break_the_code_table():
    rows = [{"id": "REQ-001", "requirement": "a | b", "cve": "CVE-2023-00001", "cwe": "N/A",
             "verification": "Test: ok", "quality_check": PASS}]
    assert "a \\| b" in build_table(rows)
    assert check_table(build_table(rows), rows) == []


def test_the_requirements_table_shows_each_requirements_cwes_and_rejects_a_made_up_one():
    cves = [{**CVES[0], "cwes": ["CWE-787", "CWE-20"]}, CVES[1]]  # the second CVE has no CWE listed
    item = run_requirements(ScriptedModel(), cves)[0]
    rows = table_rows(item)
    assert [r["cwe"] for r in rows] == ["CWE-787, CWE-20", "N/A"]
    lines = build_table(rows).splitlines()
    assert lines[0] == "| ID | Requirement | CVE | CWE | Verification | Quality check |"
    assert "| CVE-2023-00001 | CWE-787, CWE-20 |" in lines[2] and "| CVE-2023-00002 | N/A |" in lines[3]
    assert check_table(build_table(rows), rows) == []
    assert any("CWE must be N/A" in p for p in check_table(build_table(rows).replace("| N/A |", "| CWE-79 |"), rows))


# ---- Checking the section ----------------------------------------------------------

def good_section(item):
    data = section_data(item)
    parts = [f"#### {data['component']}", "**CVEs:** " + ", ".join(data["cves"]), f"_{data['reviewed']}_", TABLE_MARKER]
    if data["issues"]:
        parts.append("**Issues the Evaluator found:**\n\n" + "\n".join(f"- {i}" for i in data["issues"]))
    return "\n\n".join(parts)


def test_a_correct_section_passes_the_check(passing, failing):
    assert check_section(good_section(passing), section_data(passing)) == []
    assert check_section(good_section(failing), section_data(failing)) == []
    assert check_section("```\n" + good_section(passing) + "\n```", section_data(passing)) == []  # fences are tolerated


@pytest.mark.parametrize(
    "change, expected",
    [
        (lambda t: t.replace("####", "###"), "heading line must be exactly"),
        (lambda t: t.replace("#### Router", f"#### Router: {PASS}", 1), "heading line must be exactly"),  # no mark next to the name
        (lambda t: t.replace("#### Router", f"#### Router - {NEEDS_REVIEW}", 1), "heading line must be exactly"),
        (lambda t: t.replace("CVE-2023-00002 (CVSS 5.0, MEDIUM)", "CVE-2023-00002"), "CVE list must include"),
        (lambda t: t.replace("Reviewed by the Evaluator 1 time.", "Reviewed twice."), "must say"),
        (lambda t: t.replace(TABLE_MARKER, ""), "[TABLE] must appear exactly 1"),
        (lambda t: t + "\n\n| ID | Requirement |\n| --- | --- |", "Do not write a table"),
        (lambda t: t + "\n\nAlso see CVE-2022-99999.", "is not in the data"),
        (lambda t: t + "\n\n**Issues the Evaluator found:**", "no issues"),
    ],
)
def test_the_section_check_catches_each_kind_of_mistake(passing, change, expected):
    problems = check_section(change(good_section(passing)), section_data(passing))
    assert any(expected in p for p in problems), problems


def test_the_section_check_catches_a_missing_issue_and_an_invented_requirement_id(failing):
    data = section_data(failing)
    assert data["issues"], "the failing component must have issues for this test"
    without_issues = good_section(failing).split("**Issues")[0]
    assert any("issues list must include" in p for p in check_section(without_issues, data))
    invented = good_section(failing) + "\n- REQ-099: something"
    assert any("REQ-099 is not in the data" in p for p in check_section(invented, data))


def test_an_issue_that_names_a_cve_outside_the_component_is_allowed_to_mention_it():
    item = make_item()
    item["review"] = {**item["review"], "overall": "revise",
                      "component_issues": ["A requirement cites CVE-2023-77777, which is not one of this component's CVEs."]}
    data = section_data(item)
    assert check_section(good_section(item), data) == []


# ---- Model first, code as the safety net -------------------------------------------

def test_a_correct_model_answer_is_used_and_matches_the_code_version(passing, failing):
    for item in (passing, failing):
        markdown, sources = write_component(ScriptedModel(), item)
        assert sources == {"table": "model", "section": "model"}
        assert markdown == build_requirements_report(None, [item])[0].split("\n\n", 2)[2]  # same layout as the code version
    assert "#### Router\n" in write_component(ScriptedModel(), failing)[0]


def test_the_heading_is_only_the_systems_name_never_a_pass_or_needs_review_mark(passing, failing):
    for item in (passing, failing):
        for generate in (ScriptedModel(), ScriptedModel(bad_formatting=True), None):  # model's version, code fallback, no model
            markdown = write_component(generate, item)[0]
            headings = [line for line in markdown.splitlines() if line.startswith("#### ")]
            assert headings == ["#### Router"]
            # The quality check is still there, but in each requirement's row, not beside the name.
            rows = [line for line in markdown.splitlines() if line.startswith("| REQ-")]
            assert rows and all(PASS in r or NEEDS_REVIEW in r for r in rows)


def test_a_wrong_model_answer_gets_one_retry_then_code_builds_it(failing):
    model = ScriptedModel(bad_formatting=True)
    markdown, sources = write_component(model, failing)
    assert sources == {"table": "code", "section": "code"}
    assert model.calls == ["table", "table", "section", "section"]  # one retry each, then the fallback
    assert markdown == build_requirements_report(None, [failing])[0].split("\n\n", 2)[2]
    assert "#### Router\n" in markdown  # nothing is lost...
    row = next(line for line in markdown.splitlines() if line.startswith("| REQ-002 |"))
    assert NEEDS_REVIEW in row  # ...and the requirement that still has a problem says so in its own row


def test_the_model_is_told_what_was_wrong_and_a_second_try_can_succeed(passing):
    model = RecordingModel(wrong_first=1)  # the first table and the first section are wrong
    _, sources = write_component(model, passing)
    assert sources == {"table": "model", "section": "model"}
    retry_prompts = [p for p in model.prompts if p.startswith("Your reply has problems")]
    assert len(retry_prompts) == 2
    assert "There is no table in your reply." in retry_prompts[0]
    assert "heading line must be exactly" in retry_prompts[1]


def test_without_a_model_nothing_is_asked_and_everything_is_code_built(passing):
    def explode(*args, **kwargs):
        raise AssertionError("the model must not be called")

    markdown, sources = write_component(None, passing)
    assert sources == {"table": "code", "section": "code"}
    assert "#### Router\n" in markdown and "| REQ-001 |" in markdown
    assert "language model" not in build_requirements_report(None, [passing])[0]  # no fallback note when no model was involved
    assert build_requirements_report(explode, [])[0] is None


def test_a_component_with_no_requirements_has_no_table_and_says_why():
    item = run_requirements(lambda *a, **k: "no json", CVES)[0]
    assert item["requirements"] == []
    markdown, sources = write_component(ScriptedModel(), item)
    assert sources["table"] is None and TABLE_MARKER not in markdown and "| ID |" not in markdown
    # No requirement rows, so the Issues list is what tells the reader; nothing is added next to the name.
    assert markdown.startswith("#### Router\n") and "Issues the Evaluator found" in markdown
    assert "No requirements were written" in markdown


# ---- In the Writer's report --------------------------------------------------------

def test_the_report_says_which_parts_the_model_wrote_and_which_code_built(passing, failing):
    good = write_requirements_report(ScriptedModel(), [passing])
    assert good["requirements_sources"] == {"Router": {"table": "model", "section": "model"}}
    assert "language model's formatting" not in good["markdown"]
    bad = write_requirements_report(ScriptedModel(bad_formatting=True), [failing])
    assert bad["requirements_sources"] == {"Router": {"table": "code", "section": "code"}}
    assert "language model's formatting didn't match the data" in bad["markdown"] and "Router._" in bad["markdown"]
    assert bad["table_source"] == "requirements" and "Vulnerability table" not in bad["markdown"]
