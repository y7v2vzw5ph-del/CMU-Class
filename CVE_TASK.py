"""Streamlit chat UI for the Router agent.

Run from the AIClass_PythonCode folder:
    uv run --project agents streamlit run CVE_TASK.py

(--project agents tells uv to use the environment in the agents folder,
where the router and the other agent packages are installed.)
"""

import asyncio
import html
import re
from pathlib import Path

import streamlit as st
from dotenv import dotenv_values

from router.agent import MODEL_ID, ChatSession, ask, remote_generator
from router.graph_diagram import sidebar_diagram
from router.status import AGENTS, AgentTracker, agent_panel_html

# Read the .env file that sits next to this script. Read on every page rerun, so
# after you edit .env (e.g. a new Colab URL), just refresh the page.
ENV = dotenv_values(Path(__file__).resolve().parent / ".env")

# Pinned version, loaded from a CDN in the browser (so it needs internet to draw).
MERMAID_JS = "https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.esm.min.mjs"


def mermaid_page(code):
    """The HTML page that draws one Mermaid diagram (for st.iframe)."""
    # html.escape() matters: st.iframe runs this HTML as-is, so nothing typed or
    # generated may be inserted unescaped. (The browser turns the text back into
    # the original Mermaid before drawing.)
    return f"""
    <body style="margin:0;background:white;">
    <pre class="mermaid">{html.escape(code)}</pre>
    <script type="module">
      import mermaid from "{MERMAID_JS}";
      mermaid.initialize({{ startOnLoad: true }});
    </script>
    </body>"""


# The sidebar starts this wide (pixels; Streamlit allows 200 to 600). It is still hidden on small
# screens, and you can drag its edge to resize it.
SIDEBAR_WIDTH_PX = 480
SIDEBAR_DIAGRAM_HEIGHT_PX = 560  # room for the agent diagram under the cards; raise it if the picture is cut off
st.set_page_config(page_title="SCORP", page_icon="🦂", initial_sidebar_state=SIDEBAR_WIDTH_PX)
st.title("SCORP (System CVE Observation & Remediation Protocol)")

# ---- Sidebar: the Colab connection (the model always runs on Colab) ----
with st.sidebar:
    st.header("Colab connection")
    # Pre-filled from COLAB_URL / COLAB_KEY in the .env file (you can still edit them here).
    colab_url = st.text_input(
        "Colab URL",
        value=ENV.get("COLAB_URL") or "",
        placeholder="https://xxxx.trycloudflare.com",
        help="Start the Colab notebook first, then paste the address it shows.",
    )
    colab_key = st.text_input("API key", value=ENV.get("COLAB_KEY") or "", type="password")
    if ENV.get("COLAB_URL") or ENV.get("COLAB_KEY"):
        st.caption("Filled in from your .env file.")

if not (colab_url and colab_key):
    st.info("Paste the Colab URL and API key in the sidebar to start.")
    st.stop()  # nothing below this line runs until both are filled in
generate = remote_generator(colab_url, colab_key)
st.caption(f"{MODEL_ID} running on Colab.")

# ---- The agents: who can be used, how often each was called, who is active ----
# The tracker lives in session_state so the counts survive the page rerunning.
tracker = st.session_state.get("agent_tracker")
if tracker is None or tracker.agents != AGENTS:
    # A tracker saved by an older run does not know about newer agents (like the Evaluator), so it
    # would ignore them and the panel would never show them. Start a fresh one when the list changed.
    tracker = st.session_state["agent_tracker"] = AgentTracker()
with st.sidebar:  # under the Colab connection
    st.header("Agents")
    # Show or hide the step rows under each answer (what each agent passed on). The steps are always
    # collected and saved, so turning this back on shows them for the whole chat.
    show_step_details = st.toggle("Show agent steps", value=True, key="show_step_details")
    agent_panel = st.empty()  # one slot we redraw as agents start and finish
    # A static picture of how the agents are connected, drawn from the real graph (router/graph.py),
    # so it is never out of date. It does not change while a question runs; the cards above do.
    st.subheader("How the agents are connected")
    st.iframe(mermaid_page(sidebar_diagram()), height=SIDEBAR_DIAGRAM_HEIGHT_PX)
    st.caption(
        "Solid arrow: always happens. Dotted arrow: depends on a decision (the Router picking a route, "
        "the Evaluator sending work back for a rewrite, and so on). It shows every possible path, "
        "not the path of one question."
    )


def show_agent_panel():
    agent_panel.markdown(agent_panel_html(tracker), unsafe_allow_html=True)


def on_agent_event(kind, agent):
    """Called by the graph whenever an agent starts or ends a step (see router/graph.py)."""
    tracker.on_event(kind, agent)
    show_agent_panel()


show_agent_panel()

# Streamlit reruns this whole script on every interaction, so what must survive lives in session_state:
# the chat shown on the page, and the ChatSession (the paused graph run waiting for your next reply).
if "history" not in st.session_state:
    st.session_state.history = []
session = st.session_state.setdefault("chat_session", ChatSession())


def show_steps(steps):
    if not show_step_details:
        return
    for s in steps:
        # One step of the LangGraph run: which agent did what (see router/graph.py).
        with st.expander(f"🤖 {s['agent']}: {s['action']}"):
            st.json(s["data"])


MERMAID_BLOCK_RE = re.compile(r"```mermaid\n(.*?)```", re.DOTALL)


def draw_mermaid(code):
    """Draw a Mermaid diagram as boxes and arrows, and keep the text underneath."""
    nodes = len(re.findall(r"^\s*S\d+\[", code, re.MULTILINE))
    st.iframe(mermaid_page(code), height=min(700, 160 + 70 * nodes))
    with st.expander("Mermaid text"):
        st.code(code, language="text")


def show_answer(text):
    """Show markdown, but draw any ```mermaid blocks as a real diagram."""
    position = 0
    for block in MERMAID_BLOCK_RE.finditer(text):
        if text[position:block.start()].strip():
            st.markdown(text[position:block.start()])
        draw_mermaid(block.group(1))
        position = block.end()
    if text[position:].strip():
        st.markdown(text[position:])


for msg in st.session_state.history:
    with st.chat_message(msg["role"]):
        show_steps(msg.get("steps", []))
        show_answer(msg["content"])

if question := st.chat_input("Type 'CVECheck' to check your systems, or ask about a CVE, e.g. 'CVE-2024-20358'"):
    # Chat so far (before this question), so the model remembers earlier turns.
    earlier = list(st.session_state.history)
    st.session_state.history.append({"role": "user", "content": question})
    with st.chat_message("user"):
        st.markdown(question)

    with st.chat_message("assistant"):
        try:
            with st.spinner("Thinking..."):
                answer, steps = asyncio.run(
                    ask(question, generate, session, earlier, on_event=on_agent_event)
                )
        except Exception as e:
            st.error(f"Something went wrong: {e}")
            st.stop()
        finally:
            tracker.finish()  # nobody is active any more, even after an error
            show_agent_panel()
        show_steps(steps)
        show_answer(answer)

    st.session_state.history.append({"role": "assistant", "content": answer, "steps": steps})
