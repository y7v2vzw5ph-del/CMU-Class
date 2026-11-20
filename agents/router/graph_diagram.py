"""Mermaid diagrams of how the agents are connected, generated from the REAL LangGraph.

Nothing is drawn by hand: we build the graph (router/graph.py), read its nodes and arrows, and
turn them into Mermaid text. So when a node or an agent is added, the diagram changes with it.
Which agent owns each node comes from NODE_AGENT in router/status.py (the same table the agent
panel uses).

The diagram has one box per agent and an arrow for every hand-over between two agents.

A dotted arrow means the path depends on a decision (a "conditional edge", like the Router
choosing a route or the Evaluator deciding whether to send the work back). A solid arrow
always happens. No model and no Streamlit here, so it is easy to test.
"""

from router.graph import build_graph
from router.status import AGENTS, NODE_AGENT

# (fill, border) per agent. Dark text on light fills reads well on the white page the diagram is drawn on.
AGENT_COLOURS = {
    "router": ("#dbeafe", "#2563eb"),
    "systems_expert": ("#ffedd5", "#ea580c"),
    "vulnerability_expert": ("#fee2e2", "#dc2626"),
    "evaluator": ("#ede9fe", "#7c3aed"),
    "writer": ("#dcfce7", "#16a34a"),
}
FALLBACK_COLOURS = ("#f3f4f6", "#6b7280")

START_ID, END_ID = "user_message", "final_answer"  # not "start"/"end": Mermaid reserves those words


def _bridge(edges, hidden):
    """Remove the `hidden` nodes, joining each arrow into one to each arrow out of it.

    A joined arrow is conditional if either half is.
    """
    edges = set(edges)
    for node in sorted(hidden):
        incoming = [(s, c) for s, t, c in edges if t == node]
        outgoing = [(t, c) for s, t, c in edges if s == node]
        edges = {e for e in edges if node not in (e[0], e[1])}
        edges |= {(s, t, c1 or c2) for s, c1 in incoming for t, c2 in outgoing}
    return edges


def read_graph():
    """The real graph as plain data: (node names, [(source, target, is_conditional), ...]).

    The requirements loop is a subgraph, so `xray` opens it: its steps appear as
    "requirements:write_requirements", which we shorten to the step's own name. The invisible
    start/end markers of the subgraph are bridged over, so the arrows run from step to step.
    """
    drawable = build_graph(lambda *args, **kwargs: "").get_graph(xray=True)
    short = {name: name.split(":")[-1] for name in drawable.nodes}
    hidden = {name for name in drawable.nodes if ":" in name and short[name].startswith("__")}
    edges = _bridge({(e.source, e.target, bool(e.conditional)) for e in drawable.edges}, hidden)

    by_pair = {}  # an arrow is dotted only if every arrow between the same two steps is
    for source, target, conditional in edges:
        by_pair.setdefault((short[source], short[target]), []).append(conditional)
    nodes = [short[name] for name in drawable.nodes if name not in hidden and not name.startswith("__")]
    return nodes, sorted((s, t, all(flags)) for (s, t), flags in by_pair.items())


def _owner(name):
    """The agent key that owns a node. LangGraph's start/end markers are the user's message and the answer."""
    if name == "__start__":
        return START_ID
    if name == "__end__":
        return END_ID
    return NODE_AGENT[name]


def _arrow(source, target, conditional):
    return f"  {source} -.-> {target}" if conditional else f"  {source} --> {target}"


def _styles(ids_by_agent):
    """classDef lines for every agent, plus a `class` line for the nodes that belong to it."""
    lines = []
    for agent in AGENTS:
        fill, border = AGENT_COLOURS.get(agent["key"], FALLBACK_COLOURS)
        lines.append(f"  classDef c_{agent['key']} fill:{fill},stroke:{border},stroke-width:2px,color:#111827")
        ids = ids_by_agent.get(agent["key"])
        if ids:
            lines.append(f"  class {','.join(ids)} c_{agent['key']}")
    lines.append("  classDef c_edge fill:#ffffff,stroke:#6b7280,stroke-dasharray:4 3,color:#111827")
    lines.append(f"  class {START_ID},{END_ID} c_edge")
    return lines


def agent_diagram(edges):
    """One box per agent (just the name: the agent cards already show the roles), one arrow per
    hand-over between two different agents.

    An arrow is dotted only if EVERY step-level arrow it stands for is conditional.
    """
    paths = {}  # (from, to) -> [is_conditional, ...]
    for source, target, conditional in edges:
        a, b = _owner(source), _owner(target)
        if a != b:  # work staying inside one agent is not a connection between agents
            paths.setdefault((a, b), []).append(conditional)

    lines = ["flowchart TD", f'  {START_ID}(["User message"])', f'  {END_ID}(["Answer"])']
    for agent in AGENTS:
        lines.append(f'  {agent["key"]}["<b>{agent["name"]}</b>"]')
    for (a, b), flags in sorted(paths.items()):
        lines.append(_arrow(a, b, all(flags)))
    lines += _styles({agent["key"]: [agent["key"]] for agent in AGENTS})
    return "\n".join(lines)


def sidebar_diagram():
    """The agent diagram for the sidebar, read from the real graph right now."""
    _, edges = read_graph()
    return agent_diagram(edges)
