"""The Router Agent (RA) and the model backend.

The RA is the only agent the user talks to. It runs Qwen2.5-3B on Colab (see
colab_server.ipynb) and has NO tools of its own. The agents are coordinated by a
LangGraph (see graph.py), which shows the whole flow. `ask()` below runs one user
message through that graph.

A CVECheck takes several messages (which systems? is the diagram right? write requirements?). The graph
PAUSES at each question and resumes with the user's next message: a checkpointer (kept in a ChatSession)
holds the run's state in between. See the top of graph.py.
"""

import requests
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from router.graph import build_graph
MODEL_ID = "Qwen/Qwen2.5-3B-Instruct"

MAX_HISTORY_MESSAGES = 8  # how many earlier chat messages the agents get to see
MAX_NEW_TOKENS = 400
MAX_PARALLEL_CALLS = 4  # model calls at the same time on the Colab server
GRAPH_RECURSION_LIMIT = 200  # max graph steps in one call (LangGraph's default is 25)


def remote_generator(url, api_key):
    """The model backend: send the conversation to the model server running on Colab.

    A "generator" is just a function: (messages, tools) -> the model's reply text.
    The agents don't care where that text comes from, only that they can call it.
    An agent that needs a longer reply (the Writer's table) can pass max_new_tokens.
    """

    def generate(messages, tools, max_new_tokens=MAX_NEW_TOKENS):
        response = requests.post(
            url.rstrip("/") + "/generate",
            json={
                "messages": messages,
                "tools": tools,
                "max_new_tokens": max_new_tokens,
            },
            headers={"X-API-Key": api_key},
            timeout=300,
        )
        response.raise_for_status()
        return response.json()["text"]

    # The Colab server runs each request in its own thread on a GPU, so a few calls
    # can be in flight at once (see run_model_calls in systems_expert/agent.py).
    generate.max_parallel = MAX_PARALLEL_CALLS
    return generate


class ChatSession:
    """What the app remembers between messages. Keep one per browser session (the page does).

    - the checkpointer: LangGraph saves a run's state here while it waits for the user's reply. Each
      run (one CVECheck question and everything it leads to) has its own thread, so a finished
      run can never leak into the next one.
    - since_done: the chat since the last finished CVECheck. The Systems Expert reads it, so a
      short answer like "Windows 11" still works, and a new CVECheck starts without the old systems.
    """

    def __init__(self):
        self.checkpointer = InMemorySaver()
        self.since_done = []  # [{"role", "content"}, ...]
        self._run = 0

    @property
    def thread_id(self):
        return f"run-{self._run}"

    def end_run(self, values):
        """The run finished. Forget its saved state, work out the chat to carry on with, start a new thread."""
        messages = list(values.get("cvecheck_conversation") or [])
        if values.get("moved_on"):
            messages = messages[:-1]  # the reply that did not fit is run again as a new message
        elif values.get("answer"):
            messages.append({"role": "assistant", "content": values["answer"]})
        self.since_done = [] if values.get("done") else messages
        self._next_run()

    def abandon_run(self):
        """Something went wrong mid-run: drop its saved state so the next message starts fresh."""
        self._next_run()

    def _next_run(self):
        self.checkpointer.delete_thread(self.thread_id)
        self._run += 1


async def ask(question, generate, session, history=None, on_event=None):
    """Handle one user message by running (or resuming) the LangGraph.

    `generate` is the model backend from remote_generator().
    `session` is the ChatSession that holds the paused run between messages.
    `history` is the earlier chat as [{"role": "user"/"assistant", "content": ...}]; the Router's
    plain chat replies see the last few messages of it.

    If the graph is paused, the message is the user's reply and the run RESUMES. Otherwise it starts a
    new run. If the reply does not belong to the question that was asked (the run ends with `moved_on`),
    the message is run again as a fresh start.

    Returns (answer, steps). `steps` lists what each agent did during THIS call (the graph's trace), so
    the UI can show them.

    `on_event(kind, agent_key)` is optional: it is called when each agent starts and ends a
    step, so the page can show who is active (see router/status.py).
    """
    # Keep only the last few earlier messages (a small model has a short context).
    recent = [{"role": m["role"], "content": m["content"]} for m in (history or [])[-MAX_HISTORY_MESSAGES:]]
    graph = build_graph(generate, on_event, checkpointer=session.checkpointer)
    steps, message = [], question
    try:
        while True:
            config = {
                "configurable": {"thread_id": session.thread_id},
                # The requirements loop takes up to 4 steps per system (write, review, rewrite, review),
                # so the default limit of 25 steps is too low for many systems.
                "recursion_limit": GRAPH_RECURSION_LIMIT,
            }
            before = await graph.aget_state(config)
            if before.next:  # paused, waiting for exactly this reply
                seen = len(before.values.get("trace", []))
                await graph.ainvoke(Command(resume=message), config)
            else:
                seen = 0
                new_message = {"role": "user", "content": message}
                await graph.ainvoke(
                    {
                        "conversation": recent + [new_message],
                        "cvecheck_conversation": session.since_done[-MAX_HISTORY_MESSAGES:] + [new_message],
                        "trace": [],
                    },
                    config,
                )
            after = await graph.aget_state(config)
            values = after.values
            steps += values.get("trace", [])[seen:]
            if after.next:  # paused again: the answer is a question for the user
                return values["answer"], steps
            session.end_run(values)
            if values.get("moved_on"):
                message = values["moved_on"]
                continue
            return values["answer"], steps
    except BaseException:
        session.abandon_run()
        raise
