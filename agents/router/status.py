"""Which agents exist, how often each was called, and which one is active right now.

Pure Python (no Streamlit, no model), so it is easy to test. The Streamlit page
(CVE_TASK.py) draws it; the graph (router/graph.py) reports to it.

What counts as a "call": an agent is called when it TAKES OVER from a different
agent. The Systems Expert's three steps in a row (intake -> industry -> diagram)
are ONE call, and the search-again loop (Vulnerability Expert -> Systems Expert ->
Vulnerability Expert ...) counts each hand-over. Counting every internal step
would make the Router look like it was called three times per message.
"""

import html

# The agents that can be used.
# The names must match NAME in each agent's module; tests/test_status.py checks that.
AGENTS = [
    {"key": "router", "name": "Router", "role": "Talks to you and decides who does what"},
    {"key": "systems_expert", "name": "Systems Expert", "role": "Understands your systems and checks if the CVEs fit"},
    {"key": "vulnerability_expert", "name": "Vulnerability Expert", "role": "Looks up CVEs and writes requirements"},
    {"key": "evaluator", "name": "Evaluator", "role": "Checks the requirements against INCOSE rules"},
    {"key": "writer", "name": "Writer", "role": "Turns the findings into a report"},
]

# Which agent owns each node of the LangGraph (the names used in router/graph.py).
NODE_AGENT = {
    "router_decide": "router",
    "classify": "router",
    "offer": "router",
    "cancel": "router",
    "decline": "router",
    "ask_user": "router",
    "chat": "router",
    "confirm_prompt": "router",
    "router_reply": "router",
    "systems_intake": "systems_expert",
    "classify_industry": "systems_expert",
    "draw_diagram": "systems_expert",
    "revise": "systems_expert",
    "verify_cves": "systems_expert",
    "vulnerability_expert": "vulnerability_expert",
    "write_requirements": "vulnerability_expert",
    "revise_requirements": "vulnerability_expert",
    "review_requirements": "evaluator",
    "writer": "writer",
}


class AgentTracker:
    """Counts the calls of each agent and remembers which one is active.

    The graph reports with on_event("start" | "end", agent_key).
    Call finish() when the whole answer is done (or failed).
    """

    def __init__(self, agents=AGENTS):
        self.agents = agents
        self.counts = {a["key"]: 0 for a in agents}
        self.active = None  # the agent working right now, or None when idle
        self.last = None  # the agent that worked most recently
        self._previous = None  # the agent of the previous step in THIS answer

    def on_event(self, kind, agent):
        if agent not in self.counts:
            return  # an agent we don't list: ignore it
        if kind == "start":
            if agent != self._previous:  # a hand-over, not a continuation
                self.counts[agent] += 1
            self._previous = agent
            self.active = agent
            self.last = agent
        elif kind == "end" and self.active == agent:
            self.active = None

    def finish(self):
        """The answer is done: nobody is active, and the next answer starts a new hand-over chain."""
        self.active = None
        self._previous = None


def agent_panel_html(tracker):
    """The panel the page shows: one card per agent with its call count and status.

    Only our own fixed text and numbers go into the HTML, and they are escaped anyway.
    """
    cards = []
    for agent in tracker.agents:
        key = agent["key"]
        is_active = tracker.active == key
        if is_active:
            style = "border:2px solid #2e9e5b;background:rgba(46,158,91,0.18);"
            status = "🟢 Active"
        else:
            style = "border:1px solid rgba(128,128,128,0.4);background:rgba(128,128,128,0.08);"
            status = "⚪ Idle (last used)" if tracker.last == key else "⚪ Idle"
        calls = tracker.counts[key]
        cards.append(
            f'<div style="flex:1 1 150px;min-width:150px;padding:8px 10px;border-radius:8px;{style}">'
            f'<div style="font-weight:600;">{html.escape(agent["name"])}</div>'
            f'<div style="font-size:0.75em;opacity:0.7;margin:2px 0 6px 0;">{html.escape(agent["role"])}</div>'
            f'<div style="font-size:0.85em;">{status}</div>'
            f'<div style="font-size:0.85em;">Called: <b>{calls}</b> time{"" if calls == 1 else "s"}</div>'
            "</div>"
        )
    return '<div style="display:flex;flex-wrap:wrap;gap:8px;">' + "".join(cards) + "</div>"
