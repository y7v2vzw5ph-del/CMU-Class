"""Tests for the agent panel (router/status.py): the registry, the call counter and the HTML."""

from evaluator import agent as evaluator_agent
from router.status import AGENTS, NODE_AGENT, AgentTracker, agent_panel_html
from systems_expert import agent as systems_expert_agent
from vulnerability_expert import agent as vulnerability_expert_agent
from writer import agent as writer_agent


def run_steps(tracker, agents):
    """Pretend each agent in `agents` ran one step, one after another."""
    for agent in agents:
        tracker.on_event("start", agent)
        tracker.on_event("end", agent)


# ---- The list of agents -----------------------------------------------------------

def test_the_listed_agents_match_the_agent_modules():
    names = {a["key"]: a["name"] for a in AGENTS}
    assert names["systems_expert"] == systems_expert_agent.NAME
    assert names["vulnerability_expert"] == vulnerability_expert_agent.NAME
    assert names["writer"] == writer_agent.NAME
    assert names["evaluator"] == evaluator_agent.NAME
    assert names["router"] == "Router"


def test_every_graph_node_belongs_to_a_listed_agent():
    keys = {a["key"] for a in AGENTS}
    from router.graph_diagram import read_graph

    nodes = set(read_graph()[0])  # every step of the graph, including the steps inside the requirements subgraph
    assert nodes == set(NODE_AGENT), "NODE_AGENT in router/status.py is out of date with the graph"
    assert set(NODE_AGENT.values()) <= keys


# ---- Counting calls -----------------------------------------------------------------

def test_a_call_is_an_agent_taking_over_from_another():
    tracker = AgentTracker()
    # Systems Expert does three steps in a row: that is ONE call.
    run_steps(tracker, ["router", "systems_expert", "systems_expert", "systems_expert", "router"])
    assert tracker.counts == {"router": 2, "systems_expert": 1, "vulnerability_expert": 0, "evaluator": 0, "writer": 0}


def test_going_back_and_forth_counts_each_hand_over():
    tracker = AgentTracker()
    run_steps(tracker, ["vulnerability_expert", "systems_expert", "vulnerability_expert", "systems_expert"])
    assert tracker.counts["vulnerability_expert"] == 2
    assert tracker.counts["systems_expert"] == 2


def test_counts_keep_growing_across_answers():
    tracker = AgentTracker()
    run_steps(tracker, ["router", "writer"])
    tracker.finish()
    run_steps(tracker, ["router"])  # a new answer: the router takes over again
    assert tracker.counts["router"] == 2 and tracker.counts["writer"] == 1


def test_active_agent_is_set_while_a_step_runs():
    tracker = AgentTracker()
    assert tracker.active is None
    tracker.on_event("start", "writer")
    assert tracker.active == "writer"
    tracker.on_event("end", "writer")
    assert tracker.active is None and tracker.last == "writer"


def test_finish_clears_the_active_agent_even_after_an_error():
    tracker = AgentTracker()
    tracker.on_event("start", "writer")  # ...and then something crashed: no "end"
    tracker.finish()
    assert tracker.active is None


def test_unknown_agents_are_ignored():
    tracker = AgentTracker()
    tracker.on_event("start", "nobody")
    assert tracker.active is None and sum(tracker.counts.values()) == 0


# ---- The panel ----------------------------------------------------------------------

def test_panel_lists_every_agent_with_its_count():
    tracker = AgentTracker()
    run_steps(tracker, ["router", "writer"])
    page = agent_panel_html(tracker)
    for agent in AGENTS:
        assert agent["name"] in page
    assert "Called: <b>1</b> time" in page and "Called: <b>0</b> times" in page


def test_panel_marks_only_the_active_agent():
    tracker = AgentTracker()
    tracker.on_event("start", "systems_expert")
    page = agent_panel_html(tracker)
    assert page.count("🟢 Active") == 1
    assert page.index("Systems Expert") < page.index("🟢 Active") < page.index("Vulnerability Expert")


def test_panel_says_who_was_last_used_when_idle():
    tracker = AgentTracker()
    run_steps(tracker, ["writer"])
    page = agent_panel_html(tracker)
    assert "🟢" not in page
    assert page.count("Idle (last used)") == 1


# ---- Watching a real graph run ------------------------------------------------------

def run_graph(on_event):
    """A CVECheck up to the diagram (not watched), then "yes" (reported to on_event)."""
    from tests import test_graph

    chat = test_graph.Chat(test_graph.fake_model)
    chat.say("CVECheck my systems")
    return chat.say("yes", on_event=on_event)

def test_a_graph_run_reports_every_step_and_leaves_nobody_active(monkeypatch):
    from tests import test_graph

    test_graph.patch_check(monkeypatch)
    events, tracker = [], AgentTracker()

    def on_event(kind, agent):
        events.append((kind, agent))
        tracker.on_event(kind, agent)

    run_graph(on_event)

    starts = [agent for kind, agent in events if kind == "start"]
    ends = [agent for kind, agent in events if kind == "end"]
    assert starts == ends  # every step that started also ended, in the same order
    # router -> VE -> SE -> VE (broader search) -> SE -> writer -> router
    assert starts[0] == "router" and starts[-1] == "router"
    assert "writer" in starts and "systems_expert" in starts and "vulnerability_expert" in starts
    assert tracker.active is None
    # No requirements were asked for, so the Evaluator is never called.
    assert tracker.counts == {"router": 2, "systems_expert": 2, "vulnerability_expert": 2, "evaluator": 0, "writer": 1}


def test_only_one_agent_is_ever_active_at_a_time(monkeypatch):
    from tests import test_graph

    test_graph.patch_check(monkeypatch)
    depth = {"now": 0, "max": 0}

    def on_event(kind, agent):
        depth["now"] += 1 if kind == "start" else -1
        depth["max"] = max(depth["max"], depth["now"])

    run_graph(on_event)
    assert depth["max"] == 1 and depth["now"] == 0


def test_the_answer_is_the_same_with_or_without_watching(monkeypatch):
    from tests import test_graph

    test_graph.patch_check(monkeypatch)
    plain = run_graph(None)["answer"]
    watched = run_graph(lambda kind, agent: None)["answer"]
    assert plain == watched


def test_a_broken_callback_cannot_stop_the_check(monkeypatch):
    from tests import test_graph

    test_graph.patch_check(monkeypatch)

    def broken(kind, agent):
        raise RuntimeError("the page crashed")

    assert "Vulnerability table" in run_graph(broken)["answer"]
