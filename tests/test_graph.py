"""End-to-end test of the LangGraph with a fake CVE search and a fake model (no network, no GPU).

The user starts a CVECheck and sees the diagram (the graph pauses and waits), then says "yes", so the
graph resumes and runs:
vulnerability_expert -> verify_cves (-> searches again with a broader name) -> writer -> router_reply.

Three systems, one for each situation:
- Roborock Qrevo S7: nothing under its own name, but its broader name ("Roborock Qrevo") has a CVE.
- Ring Camera: has CVEs straight away, with the highest scores overall.
- Acme Widget 9: nothing under either name (the zero-CVE warning).

This file also has the helpers other test files use to drive the graph one message at a time.
"""

import asyncio

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from router import graph as graph_module

SYSTEMS = ["Roborock Qrevo S7", "Ring Camera", "Acme Widget 9"]  # the user's order
INFO = {
    "systems": SYSTEMS,
    "count": 3,
    "scope": "many",
    "industry": {s: "IoT" for s in SYSTEMS},
}

ROWS = {
    # (system, the search text that finds it): its CVEs
    ("Ring Camera", "Ring Camera"): [
        {"cve_id": "CVE-1", "description": "Ring doorbell flaw A", "cvss": 5.0, "severity": "MEDIUM"},
        {"cve_id": "CVE-2", "description": "Ring doorbell flaw B", "cvss": 9.8, "severity": "CRITICAL"},
    ],
    ("Roborock Qrevo S7", "Roborock Qrevo"): [
        {"cve_id": "CVE-3", "description": "Roborock vacuum flaw", "cvss": 4.0, "severity": "MEDIUM"},
    ],
}


async def fake_find_cves(info, systems=None, queries=None):
    """Stands in for the Vulnerability Expert."""
    systems = systems or info["systems"]
    queries = {s: (queries or {}).get(s, s) for s in systems}
    rows, no_results = [], []
    for system in systems:
        found = ROWS.get((system, queries[system]), [])
        rows += [{"system": system, "query": queries[system], **r} for r in found]
        if not found:
            no_results.append(system)
    return {
        "rows": rows,
        "no_results": no_results,
        "errors": [],
        "error_systems": [],
        "queries": queries,
        "systems": info["systems"],
        "scope": info.get("scope"),
    }


def fake_model(messages, tools, **kwargs):
    """Labels every CVE as the same product, and refuses to write a table (so code builds it)."""
    if "CVE-" in messages[-1]["content"] and "product_family" in messages[0]["content"]:
        return '{"product_family": "same", "cve_industry": "IoT", "reason": ""}'
    return "no table from me"


def fake_intake(generate, conversation):
    """The Systems Expert already knows the user's systems, so it asks no questions."""
    return {"complete": True, "question": "", "info": {"systems": SYSTEMS, "count": 3, "scope": "many"}}


def fake_classify_industry(generate, systems):
    return {s: "IoT" for s in systems}


def patch_check(monkeypatch):
    """A CVECheck with no network and no intake questions: the systems are known and the CVE search is fake."""
    monkeypatch.setattr(graph_module, "find_cves", fake_find_cves)
    monkeypatch.setattr(graph_module, "intake", fake_intake)
    monkeypatch.setattr(graph_module, "classify_industry", fake_classify_industry)


class Chat:
    """One run of the graph, driven one message at a time.

    Like the app (router/agent.py ask), every message builds a NEW graph over the same checkpointer. If the
    graph is paused the message resumes it; otherwise it starts a run. say() returns the graph's state
    values (plus "__interrupt__" if the graph is waiting for the next reply).
    """

    def __init__(self, model):
        self.model = model
        self.checkpointer = InMemorySaver()
        self.config = {"configurable": {"thread_id": "test-run"}, "recursion_limit": 200}

    def say(self, message, on_event=None):
        graph = graph_module.build_graph(self.model, on_event, checkpointer=self.checkpointer)
        paused = asyncio.run(graph.aget_state(self.config)).next
        if paused:
            return asyncio.run(graph.ainvoke(Command(resume=message), self.config))
        first = {"role": "user", "content": message}
        return asyncio.run(
            graph.ainvoke({"conversation": [first], "cvecheck_conversation": [first], "trace": []}, self.config)
        )

def run_yes(monkeypatch):
    """Start a CVECheck, see the diagram, say yes. Returns the state after the table (and the offer under it)."""
    patch_check(monkeypatch)
    chat = Chat(fake_model)
    chat.say("CVECheck my systems")  # intake -> diagram -> the graph pauses and asks "is this right?"
    return chat.say("yes")


def test_the_table_is_grouped_by_system_in_the_users_order(monkeypatch):
    answer = run_yes(monkeypatch)["answer"]
    # Roborock was listed first, so its CVE comes first even though Ring's scores are higher.
    # (A plain "worst CVSS first" table would start with CVE-2.)
    assert answer.index("| 1 | Roborock Qrevo S7 | CVE-3 |") < answer.index("| 2 | Ring Camera | CVE-2 |")
    # Inside Ring Camera: worst CVSS first.
    assert answer.index("| 2 | Ring Camera | CVE-2 |") < answer.index("| 3 | Ring Camera | CVE-1 |")


def test_a_system_with_no_cves_gets_a_warning_listing_every_search(monkeypatch):
    answer = run_yes(monkeypatch)["answer"]
    assert "No CVEs matched Acme Widget 9" in answer
    assert '"Acme Widget 9", then "Acme Widget"' in answer  # its own name, then the broader one
    assert "does not mean this system is secure" in answer


def test_systems_that_have_cves_get_no_warning(monkeypatch):
    answer = run_yes(monkeypatch)["answer"]
    assert "No CVEs matched Ring Camera" not in answer
    assert "No CVEs matched Roborock" not in answer  # found by the broader search
    assert 'also searched for "Roborock Qrevo"' in answer  # the existing "broadened" note


def test_the_graph_remembers_every_search_it_made(monkeypatch):
    results = run_yes(monkeypatch)["results"]
    assert results["searched"]["Roborock Qrevo S7"] == ["Roborock Qrevo S7", "Roborock Qrevo"]
    assert results["searched"]["Ring Camera"] == ["Ring Camera"]
    assert results["searched"]["Acme Widget 9"] == ["Acme Widget 9", "Acme Widget"]
    assert results["no_results"] == ["Acme Widget 9"]
