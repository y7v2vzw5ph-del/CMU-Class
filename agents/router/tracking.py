"""Two small helpers shared by the app's graph and the requirements subgraph.

- step(): one line of the trace the UI shows ("which agent did what").
- track_node(): wraps a node so the UI hears when its agent starts and ends (router/status.py).
"""

import inspect

from router.status import NODE_AGENT


def step(agent, action, data) -> dict:
    """One line of the trace, shown in the UI."""
    return {"agent": agent, "action": action, "data": data}


def track_node(name, node, on_event=None):
    """Wrap a node so the UI hears when it starts and ends (see router/status.py).

    Without `on_event` the node is used as it is. With it, the node runs inside an
    async wrapper: it runs on the same thread as the page, which is what lets the
    page update itself while the node works. A problem in the UI callback must never
    stop the CVE check, so errors in it are ignored.

    A node that pauses the run (LangGraph's interrupt()) still reports "end": the pause
    raises inside `node(state)`, and the `finally` runs on the way out.
    """
    if on_event is None:
        return node
    agent = NODE_AGENT[name]

    def report(kind):
        try:
            on_event(kind, agent)
        except Exception:
            pass

    async def run(state):
        report("start")
        try:
            result = node(state)
            if inspect.isawaitable(result):
                result = await result
            return result
        finally:
            report("end")

    return run
