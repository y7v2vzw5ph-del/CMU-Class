"""Tests for pausing and resuming (router/agent.py ask + ChatSession, and the ask_user step in router/graph.py).

Whenever the team needs the user's reply the graph pauses; the next message resumes the SAME run with all
its state. A reply that does not belong to the question ends the run and starts a fresh one.
"""

import asyncio

import pytest

from router import agent as router_agent
from router import graph as graph_module
from tests import test_graph
from tests.requirements_fakes import ScriptedModel
from tests.test_requirements_flow import paused

SYSTEMS = test_graph.SYSTEMS


def say(model, session, message, history=None, on_event=None):
    return asyncio.run(router_agent.ask(message, model, session, history, on_event=on_event))


def scripted_intake(monkeypatch, first_question="Which systems do you have?"):
    """An intake that asks one question, then is satisfied. Returns the list of conversations it was given."""
    seen = []

    def intake(generate, conversation):
        seen.append([m["content"] for m in conversation])
        if len(seen) == 1:
            return {"complete": False, "question": first_question, "info": None}
        return {"complete": True, "question": "", "info": {"systems": SYSTEMS, "count": 3, "scope": "many"}}

    monkeypatch.setattr(graph_module, "intake", intake)
    return seen


def model_saying_yes_to_classify(messages, tools, **kwargs):
    if messages[0]["content"] == graph_module.CLASSIFY_PROMPT:
        return "yes"
    return test_graph.fake_model(messages, tools, **kwargs)


# ---- The pauses -------------------------------------------------------------------

def test_an_intake_question_pauses_and_the_answer_goes_back_to_the_systems_expert(monkeypatch):
    test_graph.patch_check(monkeypatch)
    seen = scripted_intake(monkeypatch)
    session = router_agent.ChatSession()

    first, steps1 = say(test_graph.fake_model, session, "CVECheck")
    assert first == "Which systems do you have?" and paused(session) == "intake"

    second, steps2 = say(test_graph.fake_model, session, "a Roborock, a Ring camera and an Acme Widget")
    assert "Is this right?" in second and paused(session) == "confirm"  # the next question, the same run
    # The Systems Expert read the whole conversation, including its own question and the user's answer.
    assert seen[1] == ["CVECheck", "Which systems do you have?", "a Roborock, a Ring camera and an Acme Widget"]
    # Each call reports only its own steps.
    assert steps2[0]["data"]["route"] == "intake" and not any(s["action"] == "offer_cvecheck" for s in steps2)
    assert [s["action"] for s in steps1][:2] == ["route", "intake"]


def test_a_cvecheck_offer_waits_and_yes_starts_it_using_the_first_message(monkeypatch):
    test_graph.patch_check(monkeypatch)
    seen = scripted_intake(monkeypatch)
    session = router_agent.ChatSession()

    offer, _ = say(model_saying_yes_to_classify, session, "is my Ring camera safe?")
    assert offer == graph_module.OFFER_TEXT and paused(session) == "offer"
    asked, _ = say(model_saying_yes_to_classify, session, "yes")
    assert asked == "Which systems do you have?" and paused(session) == "intake"
    # The first message ("is my Ring camera safe?") is part of what the Systems Expert reads.
    assert seen[0][0] == "is my Ring camera safe?"


def test_anything_but_yes_after_the_offer_is_just_chat(monkeypatch):
    test_graph.patch_check(monkeypatch)
    session = router_agent.ChatSession()
    say(model_saying_yes_to_classify, session, "is my Ring camera safe?")
    answer, _ = say(model_saying_yes_to_classify, session, "what is the weather like?")
    assert answer == "no table from me"  # the Router's own chat reply (the fake model's usual answer)
    assert paused(session) is None


def test_a_paused_diagram_question_survives_a_correction_that_changes_nothing(monkeypatch):
    test_graph.patch_check(monkeypatch)
    monkeypatch.setattr(
        graph_module, "revise", lambda generate, info, text: {"changed": False, "message": "I couldn't change that.", "info": info}
    )
    session = router_agent.ChatSession()
    say(test_graph.fake_model, session, "CVECheck my systems")
    said, _ = say(test_graph.fake_model, session, "the moon is made of cheese")
    assert said == "I couldn't change that." and paused(session) == "confirm"  # still waiting, same run
    table, _ = say(test_graph.fake_model, session, "yes")  # and a yes still works afterwards
    assert "Vulnerability table" in table and paused(session) == "requirements_offer"


def test_a_correction_that_changes_the_systems_shows_the_diagram_question_again(monkeypatch):
    test_graph.patch_check(monkeypatch)
    smaller = {"systems": SYSTEMS[:2], "count": 2, "scope": "many", "industry": {s: "IoT" for s in SYSTEMS[:2]}}
    monkeypatch.setattr(graph_module, "revise", lambda generate, info, text: {"changed": True, "message": "", "info": smaller})
    session = router_agent.ChatSession()
    say(test_graph.fake_model, session, "CVECheck my systems")
    again, _ = say(test_graph.fake_model, session, "remove Acme Widget 9")
    assert "Is this right?" in again and "Acme Widget 9" not in again and paused(session) == "confirm"


# ---- A reply that does not belong to the question ends the run -------------------------

def test_a_cve_id_while_waiting_for_the_diagram_answer_is_a_fresh_start_with_nothing_left_over(monkeypatch):
    async def fake_look_up_ids(cve_ids):
        return {"rows": [{"system": "(direct lookup)", "cve_id": cve_ids[0], "description": "Flaw", "cvss": 7.5,
                          "severity": "HIGH"}], "no_results": [], "errors": [], "queries": {}}

    test_graph.patch_check(monkeypatch)
    monkeypatch.setattr(graph_module, "look_up_ids", fake_look_up_ids)
    session = router_agent.ChatSession()
    say(test_graph.fake_model, session, "CVECheck my systems")  # paused: the diagram, with all the systems known
    answer, _ = say(test_graph.fake_model, session, "CVE-2024-20358")
    # If the old run's systems had leaked in, this would have said "Confirmed. Here's what I found" with them.
    assert "Confirmed" not in answer and "Is this right?" not in answer
    assert "CVE-2024-20358" in answer and "Vulnerability table" in answer
    assert paused(session) is None


def test_cancel_while_waiting_ends_the_check_and_forgets_it(monkeypatch):
    test_graph.patch_check(monkeypatch)
    session = router_agent.ChatSession()
    say(test_graph.fake_model, session, "CVECheck my systems")
    answer, _ = say(test_graph.fake_model, session, "cancel")
    assert answer == graph_module.CANCEL_TEXT
    assert paused(session) is None and session.since_done == []


def test_a_finished_run_does_not_leak_into_the_next_one(monkeypatch):
    test_graph.patch_check(monkeypatch)
    monkeypatch.setattr(test_graph, "ROWS", {("Ring Camera", "Ring Camera"): [
        {"cve_id": "CVE-2023-10001", "description": "Flaw", "cvss": 5.0, "severity": "MEDIUM"}]})
    session = router_agent.ChatSession()
    say(test_graph.fake_model, session, "CVECheck my systems")
    say(test_graph.fake_model, session, "yes")
    say(ScriptedModel(), session, "yes")  # the requirements
    assert paused(session) is None
    # A second check starts from nothing: its first answer is the diagram question, and its steps are its own.
    answer, steps = say(test_graph.fake_model, session, "CVECheck my systems")
    assert "Is this right?" in answer
    assert not any(s["action"] in ("requirements_report", "write_requirements", "final_report") for s in steps)


def test_a_finished_runs_saved_state_is_deleted_from_the_checkpointer(monkeypatch):
    test_graph.patch_check(monkeypatch)
    session = router_agent.ChatSession()
    first_thread = session.thread_id
    say(test_graph.fake_model, session, "hello there")  # a plain chat reply ends its run at once
    assert session.thread_id != first_thread
    assert list(session.checkpointer.list({"configurable": {"thread_id": first_thread}})) == []


# ---- When something goes wrong -----------------------------------------------------

def test_an_error_mid_run_drops_that_run_so_the_next_message_starts_clean(monkeypatch):
    test_graph.patch_check(monkeypatch)
    session = router_agent.ChatSession()
    say(test_graph.fake_model, session, "CVECheck my systems")  # paused at the diagram question

    async def broken_find_cves(info, systems=None, queries=None):
        raise RuntimeError("the CVE tool is down")

    monkeypatch.setattr(graph_module, "find_cves", broken_find_cves)
    stuck_thread = session.thread_id
    with pytest.raises(RuntimeError, match="down"):
        say(test_graph.fake_model, session, "yes")
    assert session.thread_id != stuck_thread and paused(session) is None  # not stuck waiting on a broken run

    monkeypatch.setattr(graph_module, "find_cves", test_graph.fake_find_cves)
    answer, _ = say(test_graph.fake_model, session, "CVECheck my systems")  # starts over, no half-run to resume
    assert "Is this right?" in answer


# ---- The chat the Systems Expert reads ---------------------------------------------

def test_the_chat_before_a_cvecheck_is_still_read_by_the_systems_expert(monkeypatch):
    test_graph.patch_check(monkeypatch)
    seen = scripted_intake(monkeypatch)
    session = router_agent.ChatSession()
    say(test_graph.fake_model, session, "I have a Roborock Qrevo S7 and a Ring Camera")  # plain chat
    say(test_graph.fake_model, session, "CVECheck")
    assert seen[0][0] == "I have a Roborock Qrevo S7 and a Ring Camera"  # so the systems need not be repeated
    assert seen[0][-1] == "CVECheck"


def test_end_run_keeps_or_forgets_the_chat_depending_on_how_the_run_ended():
    chat = [{"role": "user", "content": "hi"}]
    session = router_agent.ChatSession()
    session.end_run({"cvecheck_conversation": chat, "answer": "hello"})
    assert session.since_done == chat + [{"role": "assistant", "content": "hello"}]  # an ordinary reply is remembered

    session.end_run({"cvecheck_conversation": chat, "answer": "bye", "done": True})
    assert session.since_done == []  # a finished CVECheck is forgotten

    both = chat + [{"role": "assistant", "content": "Is this right?"}, {"role": "user", "content": "CVE-2024-20358"}]
    session.end_run({"cvecheck_conversation": both, "moved_on": "CVE-2024-20358", "answer": "Is this right?"})
    assert session.since_done == both[:-1]  # the reply that did not fit is run again, so it is not kept twice
    assert session.thread_id == "run-3"  # every run gets its own thread
