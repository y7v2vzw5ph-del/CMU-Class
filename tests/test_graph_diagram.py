"""Tests for the agent-connection diagram (router/graph_diagram.py). Plain text in, plain text out."""

from router import graph_diagram
from router.graph_diagram import agent_diagram, read_graph, sidebar_diagram
from router.status import AGENTS, NODE_AGENT

RESERVED = {"end", "start", "graph", "flowchart", "subgraph", "class", "classdef", "style", "click", "default"}


def lines_of(text):
    return text.splitlines()


# ---- Read from the real graph -----------------------------------------------------

def test_the_requirements_subgraph_is_opened_and_its_steps_are_joined_to_the_rest_of_the_graph():
    nodes, edges = read_graph()
    assert {"write_requirements", "review_requirements", "revise_requirements"} <= set(nodes)  # no ":" prefixes
    assert not [n for n in nodes if ":" in n or n.startswith("__")]
    assert ("write_requirements", "review_requirements", False) in edges  # always
    assert ("revise_requirements", "review_requirements", False) in edges  # always
    assert ("review_requirements", "revise_requirements", True) in edges  # a decision
    assert ("review_requirements", "write_requirements", True) in edges  # the next component: a decision
    assert ("review_requirements", "writer", True) in edges
    assert ("router_decide", "write_requirements", True) in edges  # the user said yes under the table


# ---- The agent diagram -----------------------------------------------------------

def test_every_agent_is_in_the_diagram_by_name_only():
    lines = lines_of(sidebar_diagram())
    for agent in AGENTS:
        assert f'  {agent["key"]}["<b>{agent["name"]}</b>"]' in lines
        assert not any(agent["role"] in ln for ln in lines)  # the cards already show the roles


def test_the_diagram_shows_the_hand_overs_between_agents():
    lines = lines_of(sidebar_diagram())
    assert "  user_message --> router" in lines
    assert "  vulnerability_expert --> evaluator" in lines  # the write -> review step always follows
    assert "  evaluator -.-> vulnerability_expert" in lines  # sent back for a rewrite: a decision
    assert "  evaluator -.-> writer" in lines  # handed over when clean or after the 2nd review: a decision
    assert "  systems_expert -.-> vulnerability_expert" in lines and "  vulnerability_expert -.-> systems_expert" in lines
    assert "  writer --> router" in lines and "  router --> final_answer" in lines


def test_the_diagram_only_has_arrows_between_different_agents():
    arrows = [ln.split() for ln in lines_of(sidebar_diagram()) if " --> " in ln or " -.-> " in ln]
    assert arrows and all(source != target for source, _, target in arrows)  # no agent points at itself


# ---- It follows the graph, it is not hard-coded -------------------------------------

def test_the_diagram_is_built_from_the_arrows_it_is_given(monkeypatch):
    monkeypatch.setitem(NODE_AGENT, "node_a", "router")
    monkeypatch.setitem(NODE_AGENT, "node_b", "writer")
    text = agent_diagram([("node_a", "node_b", False), ("node_b", "node_a", True), ("node_a", "node_a", False)])
    lines = lines_of(text)
    assert "  router --> writer" in lines and "  writer -.-> router" in lines
    assert not any(ln.startswith("  router") and ln.endswith(" router") for ln in lines)  # no self-arrow


def test_an_arrow_between_agents_is_dotted_only_if_every_step_arrow_behind_it_is(monkeypatch):
    for name, agent in {"a1": "router", "a2": "router", "w": "writer"}.items():
        monkeypatch.setitem(NODE_AGENT, name, agent)
    mixed = lines_of(agent_diagram([("a1", "w", True), ("a2", "w", False)]))
    assert "  router --> writer" in mixed  # one of the two is always taken, so the connection is solid
    both = lines_of(agent_diagram([("a1", "w", True), ("a2", "w", True)]))
    assert "  router -.-> writer" in both


# ---- The Mermaid text is well-formed ----------------------------------------------

def test_the_text_is_well_formed_and_deterministic():
    text = sidebar_diagram()
    assert text == sidebar_diagram()  # same graph, same text (no random order)
    assert lines_of(text)[0] == "flowchart TD"
    nodes, _ = read_graph()
    assert not {n.lower() for n in nodes} & RESERVED  # Mermaid would misread these as keywords
    assert graph_diagram.START_ID not in RESERVED and graph_diagram.END_ID not in RESERVED


def test_every_agent_gets_a_colour_and_the_styles_reference_real_nodes():
    text = sidebar_diagram()
    for agent in AGENTS:
        assert f"classDef c_{agent['key']} " in text
        assert f"class {agent['key']} c_{agent['key']}" in text
    assert "class user_message,final_answer c_edge" in text
