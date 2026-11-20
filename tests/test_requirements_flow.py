"""Tests for the requirements loop: the review limit, the Writer's output, and the whole conversation.

The conversation: a normal CVECheck ends with the vulnerability table and a question ("turn these CVE
records into requirements?"). The graph PAUSES there. On "yes" it resumes: the Vulnerability Expert writes
requirements one system at a time; the Evaluator reviews each (at most two reviews, with a rewrite in
between); then the Writer shows them per system.

The loop is a LangGraph subgraph (router/requirements_graph.py). run_requirements() runs it on its own.
"""

import asyncio
import json

from router import agent as router_agent
from router import graph as graph_module
from router.requirements_graph import MAX_REVIEWS, build_requirements_graph, needs_another_review, run_requirements
from tests import test_graph
from tests.requirements_fakes import ScriptedModel
from writer.agent import write_report, write_requirements_report
from writer.requirements_report import NEEDS_REVIEW, PASS, build_requirements_report


def format_requirements(done):
    """The report built by plain code only (no model), as text."""
    return build_requirements_report(None, done)[0]

ROUTER_CVES = [
    {"system": "Router", "cve_id": "CVE-2023-00001", "description": "Flaw A", "cvss": 9.8, "severity": "CRITICAL"},
    {"system": "Router", "cve_id": "CVE-2023-00002", "description": "Flaw B", "cvss": 5.0, "severity": "MEDIUM"},
]
CAMERA_CVE = {"system": "Camera", "cve_id": "CVE-2023-00009", "description": "Flaw C", "cvss": 7.5, "severity": "HIGH"}


def section_of(text, name):
    """The part of a requirements report that belongs to one system: from its heading to the next heading."""
    start = text.index(f"#### {name}\n")  # the heading is just the system's name
    end = text.find("\n#### ", start + 1)
    return text[start:] if end == -1 else text[start:end]


# ---- The rule: at most two reviews ------------------------------------------------

def test_another_review_needs_a_fixable_mistake_and_a_review_left():
    with_mistakes = {"rewrite_requests": [{"cves": ["CVE-1"]}]}
    assert MAX_REVIEWS == 2
    assert needs_another_review(with_mistakes, 1) is True
    assert needs_another_review(with_mistakes, 2) is False  # the second review is the last
    assert needs_another_review({"rewrite_requests": []}, 1) is False


# ---- The loop (the subgraph, run on its own) --------------------------------------

def test_a_clean_component_is_reviewed_once():
    model = ScriptedModel()
    item = run_requirements(model, ROUTER_CVES)[0]
    assert item["reviews_done"] == 1
    assert model.calls == ["write", "write", "review"]
    assert item["review"]["overall"] == "pass"


def test_mistakes_are_fixed_and_checked_in_a_second_review():
    model = ScriptedModel(bad_first={"CVE-2023-00002"})
    item = run_requirements(model, ROUTER_CVES)[0]
    assert model.calls == ["write", "write", "review", "revise", "review"]
    assert item["reviews_done"] == 2
    assert item["review"]["overall"] == "pass"
    assert [r["id"] for r in item["requirements"]] == ["REQ-001", "REQ-002"]  # ids survive the rewrite


def test_mistakes_after_the_second_review_are_reported_not_fixed():
    model = ScriptedModel(never_fixed={"CVE-2023-00002"})
    item = run_requirements(model, ROUTER_CVES)[0]
    assert model.calls == ["write", "write", "review", "revise", "review"]  # never a third review
    assert item["reviews_done"] == 2
    assert item["review"]["overall"] == "revise"
    assert item["review"]["requirement_status"] == {"REQ-001": "pass", "REQ-002": "needs_review"}


def test_components_are_done_one_at_a_time_in_the_given_order_with_numbering_that_continues():
    model = ScriptedModel(bad_first={"CVE-2023-00001"})
    done = run_requirements(model, ROUTER_CVES + [CAMERA_CVE], systems=["Camera", "Router"])
    assert [d["component"] for d in done] == ["Camera", "Router"]  # the systems order, not the CVE order
    assert [r["id"] for r in done[0]["requirements"]] == ["REQ-001"]
    assert [r["id"] for r in done[1]["requirements"]] == ["REQ-002", "REQ-003"]
    # Camera: write, review. Router: write x2, review, rewrite, review. One component's loop ends before the next begins.
    assert model.calls == ["write", "review", "write", "write", "review", "revise", "review"]


def test_no_rows_means_no_components_and_no_model_calls():
    model = ScriptedModel()
    assert run_requirements(model, []) == []
    assert model.calls == []


def test_the_subgraph_reports_which_agent_does_each_step_in_order():
    events = []
    run_requirements(ScriptedModel(bad_first={"CVE-2023-00002"}), ROUTER_CVES, on_event=lambda k, a: events.append((k, a)))
    starts = [agent for kind, agent in events if kind == "start"]
    assert starts == ["vulnerability_expert", "evaluator", "vulnerability_expert", "evaluator"]
    assert [a for k, a in events if k == "end"] == starts  # every step that started also ended


def test_the_evaluators_trace_step_shows_what_the_model_wrote_for_a_review_it_doubted():
    # A model that only ever says "revise": no problem, reasoning or rewrite, even when asked again.
    def bare_reviewer(messages, tools, **kwargs):
        first_user = next(m["content"] for m in messages if m["role"] == "user")
        if not first_user.startswith("Component:"):
            return ScriptedModel()(messages, tools)
        reqs = json.loads(first_user.split("Requirements (JSON):\n", 1)[1].split("\n\nCVE records", 1)[0])
        return json.dumps({"requirements": [
            {"id": r["id"], "quote": r["statement"], "reasoning": "", "problems": [], "verdict": "revise",
             "severity": "major", "suggested_rewrite": ""} for r in reqs]})

    graph = build_requirements_graph(bare_reviewer)
    final = asyncio.run(graph.ainvoke({"results": {"rows": ROUTER_CVES, "systems": None}, "req_trace": []}))
    review_steps = [s for s in final["req_trace"] if s["action"] == "review_requirements"]
    flagged = review_steps[0]["data"]["flagged_reviews"]
    assert [f["id"] for f in flagged] == ["REQ-001", "REQ-002"]
    assert "revise_without_evidence" in flagged[0]["flags"] and flagged[0]["verdict"] == "revise"
    assert {"reasoning", "problems", "suggested_rewrite", "quote"} <= set(flagged[0])  # the raw material to look at

# ---- The Writer's output ----------------------------------------------------------

def test_the_writer_marks_each_component_pass_or_needs_review_and_names_the_cves():
    model = ScriptedModel(never_fixed={"CVE-2023-00009"})
    good, bad = run_requirements(model, ROUTER_CVES + [CAMERA_CVE])
    text = format_requirements([good, bad])
    assert "#### Router\n" in text and "#### Camera\n" in text  # just the system's name in the heading
    assert [line for line in text.splitlines() if line.startswith("#### ")] == ["#### Router", "#### Camera"]
    # The quality check is in each requirement's row, not next to a system's name.
    assert PASS in section_of(text, "Router") and NEEDS_REVIEW not in section_of(text, "Router")
    assert NEEDS_REVIEW in section_of(text, "Camera")
    assert "CVE-2023-00001 (CVSS 9.8, CRITICAL)" in text  # which CVEs the component covers
    assert "| REQ-001 |" in text and "| CVE-2023-00001 |" in text  # and which CVE each requirement traces to
    assert "| REQ-003 |" in text  # numbering continues across components
    camera = text[text.index("#### Camera"):]
    assert "Issues the Evaluator found" in camera and "verifiable" in camera
    assert "Issues the Evaluator found" not in text[: text.index("#### Camera")]


def test_an_unreviewable_component_is_needs_review_with_the_reason():
    def silent_model(messages, tools, **kwargs):
        first_user = next(m["content"] for m in messages if m["role"] == "user")  # same on a retry
        return "no json" if first_user.startswith("Component:") else ScriptedModel()(messages, tools)

    item = run_requirements(silent_model, ROUTER_CVES)[0]
    assert item["review"]["overall"] == "incomplete"
    text = format_requirements([item])
    assert NEEDS_REVIEW in text and "no usable review" in text
    assert "#### Router\n" in text and PASS not in section_of(text, "Router")  # nothing in it counts as a pass


def test_the_requirements_report_is_only_the_requirements():
    item = run_requirements(ScriptedModel(), ROUTER_CVES)[0]
    report = write_requirements_report(ScriptedModel(), [item])
    assert report["table_source"] == "requirements"
    assert "### Requirements" in report["markdown"] and "Vulnerability table" not in report["markdown"]
    assert report["requirements_sources"] == {"Router": {"table": "model", "section": "model"}}


def test_the_normal_report_is_still_the_vulnerability_table():
    results = {"rows": ROUTER_CVES, "systems": ["Router"], "no_results": [], "errors": []}
    report = write_report(lambda *a, **k: "no table", results)
    assert report["table_source"] == "code" and "Vulnerability table" in report["markdown"]


# ---- The whole conversation, driven by ask() like the app does ---------------------

# The graph test's CVE ids ("CVE-1") are not real ids, and the gate rightly rejects those.
GRAPH_ROWS = {
    ("Ring Camera", "Ring Camera"): [
        {"cve_id": "CVE-2023-10001", "description": "Ring doorbell flaw A", "cvss": 5.0, "severity": "MEDIUM"},
        {"cve_id": "CVE-2023-10002", "description": "Ring doorbell flaw B", "cvss": 9.8, "severity": "CRITICAL",
         "cwes": ["CWE-787", "CWE-20"]},  # the only CVE here that NVD lists weaknesses for
    ],
    ("Roborock Qrevo S7", "Roborock Qrevo"): [
        {"cve_id": "CVE-2023-10003", "description": "Roborock vacuum flaw", "cvss": 4.0, "severity": "MEDIUM"},
    ],
}


def ask_turn(monkeypatch, model, question, session, rows=GRAPH_ROWS, on_event=None, history=None):
    test_graph.patch_check(monkeypatch)  # known systems, fake CVE search
    monkeypatch.setattr(test_graph, "ROWS", rows)  # fake_find_cves reads this when it runs
    answer, steps = asyncio.run(router_agent.ask(question, model, session, history, on_event=on_event))
    return {"answer": answer, "steps": steps}


def paused(session):
    """What the paused run is waiting for ("confirm", "requirements_offer"...), or None if no run is paused."""
    graph = graph_module.build_graph(lambda *a, **k: "", checkpointer=session.checkpointer)
    state = asyncio.run(graph.aget_state({"configurable": {"thread_id": session.thread_id}}))
    return state.values.get("waiting_for") if state.next else None


def paused_results(session):
    """The CVE results held in the notebook of the paused run."""
    graph = graph_module.build_graph(lambda *a, **k: "", checkpointer=session.checkpointer)
    return asyncio.run(graph.aget_state({"configurable": {"thread_id": session.thread_id}})).values["results"]


def table_turn(monkeypatch, model, rows=GRAPH_ROWS):
    """A normal CVECheck up to the table: start it, see the diagram, say yes. Returns the table turn and the session."""
    session = router_agent.ChatSession()
    first = ask_turn(monkeypatch, model, "CVECheck my systems", session, rows)
    assert paused(session) == "confirm" and "Is this right?" in first["answer"]  # the diagram question
    turn = ask_turn(monkeypatch, model, "yes", session, rows)
    return {**turn, "session": session}


def agents_and_actions(steps):
    return [(s["agent"], s["action"]) for s in steps if s["agent"] in ("vulnerability_expert", "evaluator")]


def test_a_cvecheck_ends_with_the_table_then_pauses_and_asks(monkeypatch):
    model = ScriptedModel()
    table = table_turn(monkeypatch, model)
    session = table["session"]
    assert "Vulnerability table" in table["answer"] and "### Requirements" not in table["answer"]
    assert "Would you like me to turn these CVE records into requirements?" in table["answer"]
    assert table["answer"].index("Vulnerability table") < table["answer"].index("Would you like me")
    assert paused(session) == "requirements_offer"  # the run waits here for the answer
    assert len(paused_results(session)["rows"]) == 3  # holding exactly the CVE records shown in the table
    assert not {"write", "revise", "review", "table", "section"} & set(model.calls)  # nothing written yet


def test_yes_resumes_with_the_saved_results_and_runs_the_vulnerability_expert_then_the_evaluator(monkeypatch):
    table = table_turn(monkeypatch, ScriptedModel())
    session, model = table["session"], ScriptedModel()
    reply = ask_turn(monkeypatch, model, "yes", session)
    answer = reply["answer"]
    assert "### Requirements" in answer and "Vulnerability table" not in answer  # only requirements this time
    assert "Confirmed. Here's what I found" not in answer
    assert answer.index("#### Roborock Qrevo S7") < answer.index("#### Ring Camera")  # the user's system order
    for cve_id in ("CVE-2023-10001", "CVE-2023-10002", "CVE-2023-10003"):
        assert cve_id in answer
    assert "#### Roborock Qrevo S7\n" in answer and "#### Ring Camera\n" in answer  # just the names
    assert answer.count(PASS) == 3 and NEEDS_REVIEW not in answer  # one quality check per requirement row, none by a name
    assert paused(session) is None and session.since_done == []  # the check is finished
    assert agents_and_actions(reply["steps"]) == [
        ("vulnerability_expert", "write_requirements"), ("evaluator", "review_requirements"),
        ("vulnerability_expert", "write_requirements"), ("evaluator", "review_requirements"),
    ]


def test_a_cwe_goes_from_the_cve_record_into_both_tables(monkeypatch):
    table = table_turn(monkeypatch, ScriptedModel())
    assert "| CVE ID | CWE | Description |" in table["answer"]  # the vulnerability table's new column
    assert "| CVE-2023-10002 | CWE-787, CWE-20 | Ring doorbell flaw B |" in table["answer"]
    assert "| CVE-2023-10003 | N/A | Roborock vacuum flaw |" in table["answer"]  # none listed: never invented

    reply = ask_turn(monkeypatch, ScriptedModel(), "yes", table["session"])["answer"]
    assert "| ID | Requirement | CVE | CWE | Verification | Quality check |" in reply  # the requirements table's column
    assert "| CVE-2023-10002 | CWE-787, CWE-20 |" in reply
    assert "| CVE-2023-10003 | N/A |" in reply


def test_the_loop_runs_per_component_with_at_most_two_reviews(monkeypatch):
    table = table_turn(monkeypatch, ScriptedModel())
    # Roborock's CVE-2023-10003 is written badly but fixed on the rewrite; Ring's CVE-2023-10002 never is.
    model = ScriptedModel(bad_first={"CVE-2023-10003"}, never_fixed={"CVE-2023-10002"})
    reply = ask_turn(monkeypatch, model, "yes", table["session"])
    assert model.calls.count("review") == 4 and model.calls.count("revise") == 2  # 2 reviews and 1 rewrite each
    roborock, ring = section_of(reply["answer"], "Roborock Qrevo S7"), section_of(reply["answer"], "Ring Camera")
    assert PASS in roborock and NEEDS_REVIEW not in roborock  # fixed on the rewrite
    assert NEEDS_REVIEW in ring  # never fixed, so its row says so
    assert agents_and_actions(reply["steps"]) == [
        ("vulnerability_expert", "write_requirements"),
        ("evaluator", "review_requirements"),
        ("vulnerability_expert", "revise_requirements"),
        ("evaluator", "review_requirements"),
        ("vulnerability_expert", "write_requirements"),  # the next component
        ("evaluator", "review_requirements"),
        ("vulnerability_expert", "revise_requirements"),
        ("evaluator", "review_requirements"),
    ]


def test_no_ends_the_check_without_writing_anything(monkeypatch):
    table = table_turn(monkeypatch, ScriptedModel())
    session, model = table["session"], ScriptedModel()
    reply = ask_turn(monkeypatch, model, "no thanks", session)
    assert "no requirements" in reply["answer"].lower()
    assert paused(session) is None and session.since_done == []  # finished: the next check starts fresh
    assert model.calls == []


def test_ignoring_the_offer_starts_something_new_and_nothing_is_written(monkeypatch):
    table = table_turn(monkeypatch, ScriptedModel())
    session, model = table["session"], ScriptedModel()
    reply = ask_turn(monkeypatch, model, "what is the weather?", session)
    assert "### Requirements" not in reply["answer"] and paused(session) is None
    assert not {"write", "review"} & set(model.calls)


def test_a_new_cvecheck_after_the_offer_does_not_reuse_the_old_chat(monkeypatch):
    table = table_turn(monkeypatch, ScriptedModel())  # the run is paused at the requirements offer
    session, seen = table["session"], {}

    def fake_intake(generate, conversation):
        seen["conversation"] = conversation
        return {"complete": False, "question": "Which systems?", "info": None}

    test_graph.patch_check(monkeypatch)
    monkeypatch.setattr(graph_module, "intake", fake_intake)  # after patch_check, so this one is used
    answer, _ = asyncio.run(router_agent.ask("CVECheck again", ScriptedModel(), session))
    assert seen["conversation"] == [{"role": "user", "content": "CVECheck again"}]  # the old systems are gone
    assert answer == "Which systems?" and paused(session) == "intake"  # a new check, waiting for its answer

def test_a_yes_when_nothing_is_pending_is_just_a_message(monkeypatch):
    session = router_agent.ChatSession()
    model = ScriptedModel()
    reply = ask_turn(monkeypatch, model, "yes", session)
    assert "### Requirements" not in reply["answer"] and not {"write", "review"} & set(model.calls)
    assert paused(session) is None


def test_a_direct_cve_lookup_gets_no_offer(monkeypatch):
    async def fake_look_up_ids(cve_ids):
        return {"rows": [{"system": "(direct lookup)", "cve_id": cve_ids[0], "description": "Flaw", "cvss": 7.5,
                          "severity": "HIGH"}], "no_results": [], "errors": [], "queries": {}}

    monkeypatch.setattr(graph_module, "look_up_ids", fake_look_up_ids)
    session = router_agent.ChatSession()
    answer, _ = asyncio.run(router_agent.ask("CVE-2024-20358", ScriptedModel(), session))
    assert "Vulnerability table" in answer and "requirements" not in answer.lower()
    assert paused(session) is None


def test_no_offer_when_there_is_nothing_to_write_requirements_for(monkeypatch):
    table = table_turn(monkeypatch, ScriptedModel(), rows={})  # no CVEs found for any system
    assert "Would you like me" not in table["answer"]
    assert paused(table["session"]) is None


def test_the_status_panel_sees_the_evaluator(monkeypatch):
    from router.status import AgentTracker

    table = table_turn(monkeypatch, ScriptedModel())
    tracker = AgentTracker()
    ask_turn(monkeypatch, ScriptedModel(bad_first={"CVE-2023-10003"}), "yes", table["session"], on_event=tracker.on_event)
    assert tracker.counts["evaluator"] >= 2  # the Vulnerability Expert and the Evaluator hand the work back and forth
    assert tracker.counts["vulnerability_expert"] >= 2
    assert tracker.active is None
