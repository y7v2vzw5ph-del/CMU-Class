"""The LangGraph that coordinates the agents.

A LangGraph is a flowchart made of:
- STATE: one shared notebook (a dict) that every node can read and add to.
- NODES: functions. Each one reads the state and returns the keys it wants to update.
- EDGES: arrows saying which node runs next. A "conditional" edge picks the next
  node with a small function (that is how the Router chooses a path).

THE PAUSES. Whenever the team needs the user's reply, the graph stops at the `ask_user` node
(LangGraph's interrupt()). The answer is shown, and the run waits. The user's next message RESUMES the
same run at that point, with all of its state (the systems, the diagram, the CVE results...) still in the
notebook: a "checkpointer" saves it between messages (see ask() in router/agent.py). So nothing has to be
copied into the chat history to remember it. `waiting_for` says what we asked:

    "offer"               the Router offered a CVECheck       -> yes starts it
    "intake"              the Systems Expert needs more info  -> the answer goes back to it
    "confirm"             the diagram, "is this right?"       -> yes / a correction / cancel
    "requirements_offer"  the table, "write requirements?"    -> yes / no

If the reply does not belong to what we asked (a CVE id, a new question), the run ends
(route "restart") and ask() starts a fresh run with that message, so nothing left over from the
old run can leak into it.

Our flow (each box is a node, "agent" in brackets):

    START -> router_decide [Router]
                |-- CVE id typed ----> vulnerability_expert -> writer -> router_reply -> END
                |-- vulnerability Q -> systems_intake [SE]
                |                         |-- still missing something -> router_reply -> ask_user (waits)
                |                         '-- complete -> classify_industry [SE] -> draw_diagram [SE]
                |                                          (one system: no diagram, straight to confirm_prompt)
                |                                          -> confirm_prompt [Router] -> ask_user (waits)
                |-- a reply to the diagram question (waiting_for "confirm"):
                |        "yes" -> vulnerability_expert [VE] -> verify_cves [SE] -> writer [Writer]
                |                 -> router_reply [Router] -> ask_user (waits for the requirements answer)
                |              (verify_cves: the SE checks each CVE record really belongs to its system.
                |               If a system has nothing relevant, loop back to the VE for a broader search.)
                |        a correction -> revise [SE] -> confirm_prompt (redrawn) -> ask_user (waits)
                |                           (or, if nothing could be changed, say how to phrase it -> ask_user)
                |        "cancel" -> cancel [Router] -> END
                |-- a reply to the requirements question (waiting_for "requirements_offer"):
                |        "yes" -> requirements (a SUBGRAPH, see router/requirements_graph.py)
                |                   one system at a time: write [VE] -> review [Evaluator]
                |                      -> clean, or 2 reviews done -> next system
                |                      -> mistakes and a review left -> rewrite [VE] -> review again
                |                 -> writer [Writer] (the requirements per system, Pass / Needs review)
                |                 -> router_reply [Router] -> END
                |        "no" -> decline [Router] -> END

Only the Router talks to the user: `router_reply` and `chat` write the `answer`.
Only the Vulnerability Expert node uses the CVE tool.

The model is not wrapped by LangChain: each node just calls our own `generate`
function (the model server on Colab), exactly as before.
"""

import operator
import re
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from router.requirements_graph import build_requirements_graph
from router.tracking import step, track_node
from shared.skills import get_skill, is_triggered
from systems_expert.agent import (
    ADD_RE,
    REMOVE_RE,
    classify_industry,
    draw_diagram,
    intake,
    revise,
    verify_cves,
)
from systems_expert.diagram import build_diagram, colour_key
from vulnerability_expert.agent import MAX_CVES_PER_SYSTEM, find_cves, look_up_ids, query_variants
from writer.agent import write_report, write_requirements_report

SYSTEM_PROMPT = (
    "You are the Router Agent for a small team of security agents. You can't look "
    "anything up yourself. If the user wants to check their systems for vulnerabilities, "
    "tell them to start with the word CVECheck (for example 'CVECheck my systems'). "
    "For one specific CVE, they can give its id (for example CVE-2024-20358). "
    "Keep replies short and friendly."
)

CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
YES_RE = re.compile(
    r"^\W*(y|yes|yeah|yep|yup|sure|ok|okay|please|go ahead|do it|let'?s do it)\b", re.IGNORECASE
)

CONFIRM_RE = re.compile(
    r"^\W*(y|yes|yeah|yep|yup|sure|ok|okay|correct|right|good|looks good|that'?s right|"
    r"that is right|confirm(ed)?|perfect|proceed|go ahead|continue|go on)\b",
    re.IGNORECASE,
)
MAX_CONFIRM_WORDS = 5  # longer replies are treated as corrections

CANCEL_RE = re.compile(
    r"^\W*(cancel|stop|abort|quit|exit|never\s*mind|forget\s+it|start\s+over)\b", re.IGNORECASE
)
CANCEL_TEXT = "Okay, I've cancelled the CVECheck. Type **CVECheck** whenever you want to start a new one."

# Under the vulnerability table: ask before writing requirements (it takes a while).
REQUIREMENTS_OFFER = (
    "**Would you like me to turn these CVE records into requirements?** Reply **yes** and the "
    "Vulnerability Expert will write requirements for each system, and the Evaluator will check them "
    "(this takes a few minutes). Reply **no**, or ask something else, to skip it."
)
DECLINE_RE = re.compile(r"^\W*(n|no|nope|nah|not now|no thanks|no thank you|skip|don'?t)\b", re.IGNORECASE)
DECLINE_TEXT = "Okay, no requirements. Type **CVECheck** whenever you want to start a new check."

CLASSIFY_PROMPT = (
    "Decide whether the user's message asks about the security of a specific product, "
    "device or system: whether it is vulnerable, risky, safe, exposed, hackable or needs "
    "security patches. Reply with exactly one word: yes or no."
)

CONFIRM_QUESTION = (
    "**Is this right?** Please make sure every system name is correct, with the right spelling "
    "and version. Reply **yes** to look up CVEs, or tell me what to change, using the names "
    "exactly as they appear {where} "
    '(for example "the Ring Camera is IoT", "remove Apache HTTP Server 2.4.57", '
    '"add a Cisco RV340 router"). '
    "Say **cancel** to stop."
)
CONFIRM_WHERE_DIAGRAM = "in the diagram"
CONFIRM_WHERE_SINGLE = "above"

OFFER_TEXT = (
    "That sounds like a security question. I can run a **CVECheck**: I'll ask which "
    "systems you have, then look up their known CVEs. "
    "Want me to? Reply **yes** to start, or keep chatting."
)

# What a reply can mean while the graph waits for it. A reply that routes anywhere else ends the run
# and starts a fresh one (route "restart"), see router_decide.
REPLIES_WE_HANDLE = {
    "offer": {"intake", "chat"},
    "intake": {"intake", "cancel"},
    "confirm": {"continue", "revise", "cancel"},
    "requirements_offer": {"requirements", "decline"},
}
MAX_KEPT_MESSAGES = 10  # how much of the chat the Router's own chat reply gets to see


class State(TypedDict, total=False):
    """The shared notebook. Nodes only fill in the keys they own."""

    # Input (set by ask() when a run starts)
    conversation: list  # recent chat + the new question: [{"role", "content"}, ...]
    cvecheck_conversation: list  # same, but only the messages since the last finished CVECheck
    # Router
    route: str  # "cve_lookup" | "intake" | "classify" | "offer" | "cancel" | "continue" | "revise" | "requirements" | "decline" | "chat" | "restart"
    cve_ids: list
    waiting_for: str  # what the last answer asked the user: "offer" | "intake" | "confirm" | "requirements_offer" | None
    done: bool  # this CVECheck is finished: the next one starts without the old chat
    moved_on: str  # (route "restart") the user's message, to run again as a fresh start
    # Systems Expert
    complete: bool  # intake finished?
    question: str  # what to ask the user next (when not complete)
    info: dict  # {"scope", "systems", "count", "industry"}
    diagram: dict  # {"mermaid", "source"}
    # Vulnerability Expert
    results: dict  # {"rows", "no_results", "errors", ...}
    # Requirements loop (a subgraph, router/requirements_graph.py). One component = one system.
    req_groups: dict  # {component: its verified CVE rows}
    req_queue: list  # components still to do
    req_current: dict  # the component being worked on (None between components)
    req_done: list  # finished components, in order: what the Writer shows
    req_trace: Annotated[list, operator.add]  # the subgraph's steps; the Writer node moves them into `trace`
    # Writer
    report: dict  # {"markdown", "table_source"}
    # Final answer for the user
    answer: str
    changed: bool  # did the user's correction change anything?
    # Search-again loop (VE <-> SE): when nothing relevant survives for a system,
    # the VE searches again with a broader name.
    queue: list  # systems that still need another, broader search
    tried: dict  # {system: how many search texts were used so far}
    pool: dict  # everything kept/excluded so far, across rounds
    # Every node adds a line here (the reducer `operator.add` appends instead of
    # overwriting). The UI shows it.
    trace: Annotated[list, operator.add]


def industry_text(info) -> str:
    """'Windows 11 → Software, Ring Camera → IoT' (the labels the user confirms)."""
    labels = info.get("industry") or {}
    return ", ".join(f"{s} → {labels[s]}" for s in info["systems"] if s in labels)


def build_graph(generate, on_event=None, checkpointer=None):
    """Build the flowchart. `generate` is the model backend (the Colab server).

    `on_event(kind, agent_key)` is optional. It is called with "start" and "end" around
    every node, so a UI can show which agent is working (see router/status.py).

    `checkpointer` saves the state while the graph waits for the user. Without one the graph
    cannot be resumed (ask() always passes one)."""

    # ---- Router ------------------------------------------------------------
    def router_decide(state: State):
        """Pick a path. Plain code, no model: specific CVE id, vulnerability talk, or chat."""
        conversation = state["conversation"]
        question = conversation[-1]["content"]
        waiting = state.get("waiting_for")  # what the user is replying to, if anything
        user_texts = [m["content"] for m in state["cvecheck_conversation"] if m["role"] == "user"]

        cve_ids = list(dict.fromkeys(i.upper() for i in CVE_ID_RE.findall(question)))
        if cve_ids:
            route = "cve_lookup"
        elif waiting == "requirements_offer" and YES_RE.match(question) and len(question.split()) <= MAX_CONFIRM_WORDS + 3:
            route = "requirements"  # "yes" under the table: write requirements for those CVEs
        elif waiting == "requirements_offer" and DECLINE_RE.match(question):
            route = "decline"  # "no": the check is finished
        elif waiting in ("intake", "confirm") and CANCEL_RE.match(question):
            route = "cancel"  # the user wants out of an unfinished CVECheck
        elif waiting == "confirm":
            # The user has seen the diagram: a short "yes" continues, anything else is a correction.
            # A short reply with no add/remove words in it. "yes, but remove Apache"
            # is a correction, so it must not count as a yes.
            lowered = question.lower()
            confirmed = (
                CONFIRM_RE.match(question)
                and len(question.split()) <= MAX_CONFIRM_WORDS
                and not REMOVE_RE.search(lowered)
                and not ADD_RE.search(lowered)
            )
            route = "continue" if confirmed else "revise"
        elif waiting == "intake" or is_triggered(get_skill("vulnerability-intake"), user_texts):
            route = "intake"  # an unfinished intake, or the CVECheck word
        elif waiting == "offer":
            # We offered a CVECheck: "yes" starts it, anything else is just chat.
            route = "intake" if YES_RE.match(question) else "chat"
        else:
            route = "classify"  # nothing matched: let the model judge (yes/no)

        if waiting and route not in REPLIES_WE_HANDLE[waiting]:
            # The user moved on (a CVE id, a new question...). End this run; ask() runs the message again
            # as a fresh start, so nothing from this run can leak into it. Moving on from the
            # requirements question also ends the CVECheck.
            return {
                "route": "restart",
                "moved_on": question,
                "done": waiting == "requirements_offer",
                "waiting_for": None,
                "trace": [step("router", "route", {"route": "restart", "cve_ids": cve_ids})],
            }
        return {
            "route": route,
            "cve_ids": cve_ids,
            "waiting_for": None,  # the user answered; a node below sets it again if it asks something
            "trace": [step("router", "route", {"route": route, "cve_ids": cve_ids})],
        }

    def pick_path(state: State):
        return state["route"]

    def ask_user(state: State):
        """Pause the run and show `answer`. The graph resumes HERE with the user's next message.

        When it resumes, LangGraph runs this node again from the top, and interrupt() hands back the
        reply instead of pausing. So everything before interrupt() must only READ the state.
        """
        answer = state["answer"]
        reply = interrupt(answer)
        shown = {"role": "assistant", "content": answer}
        said = {"role": "user", "content": reply}
        return {
            "conversation": (state["conversation"] + [shown, said])[-MAX_KEPT_MESSAGES:],
            "cvecheck_conversation": state["cvecheck_conversation"] + [shown, said],
        }

    def classify(state: State):
        """Ask the model one yes/no question about the newest message only."""
        question = state["conversation"][-1]["content"]
        messages = [
            {"role": "system", "content": CLASSIFY_PROMPT},
            {"role": "user", "content": question},
        ]
        reply = generate(messages, [], max_new_tokens=3)
        route = "offer" if reply.strip().lower().startswith("yes") else "chat"
        return {"route": route, "trace": [step("router", "classify", {"model_said": reply, "route": route})]}

    def cancel(state: State):
        # done: the next CVECheck starts fresh (no old CVECheck word, no old systems).
        return {"answer": CANCEL_TEXT, "done": True, "trace": [step("router", "cancel_cvecheck", {})]}

    def offer(state: State):
        return {"answer": OFFER_TEXT, "waiting_for": "offer", "trace": [step("router", "offer_cvecheck", {})]}

    def chat(state: State):
        messages = [{"role": "system", "content": SYSTEM_PROMPT}, *state["conversation"]]
        return {"answer": generate(messages, []), "trace": [step("router", "chat", {})]}

    def decline(state: State):
        return {"answer": DECLINE_TEXT, "done": True, "trace": [step("router", "decline_requirements", {})]}

    def router_reply(state: State):
        """Turn whatever the team produced into the message the user sees."""
        report = state.get("report")
        info = state.get("info")
        if state.get("route") == "requirements":  # the user already saw the table: show only the requirements
            return {"answer": report["markdown"] if report else "I couldn't write the requirements.", "done": True}
        if not info or not state.get("complete"):
            if state.get("route") == "cve_lookup":  # direct CVE lookup: just the report
                return {"answer": report["markdown"] if report else "I couldn't get any results."}
            # The Systems Expert needs another answer from the user.
            return {"answer": state["question"], "waiting_for": "intake"}
        systems = ", ".join(info["systems"])
        answer = (
            "Confirmed. Here's what I found:\n\n"
            f"- **Systems ({info['count']}, {info['scope']}):** {systems}\n"
            f"- **Industry:** {industry_text(info)}\n\n"
            f"{report['markdown'] if report else 'I could not get a report.'}\n\n"
            "_(Showing the highest-severity CVEs per system.)_"
        )
        if state.get("route") == "continue":
            if state["results"]["rows"]:
                # Stop here and ask. The results stay in the notebook, so a "yes" resumes with exactly
                # these CVE records.
                return {"answer": answer + "\n\n" + REQUIREMENTS_OFFER, "waiting_for": "requirements_offer"}
            return {"answer": answer, "done": True}  # nothing to write requirements for: the check is finished
        return {"answer": answer}

    def after_reply(state: State):
        return "ask_user" if state.get("waiting_for") else END

    # ---- Systems Expert ----------------------------------------------------
    def systems_intake(state: State):
        status = intake(generate, state["cvecheck_conversation"])
        return {
            "complete": status["complete"],
            "question": status["question"],
            "info": status["info"],
            "trace": [step("systems_expert", "intake", status)],
        }

    def after_intake(state: State):
        return "classify_industry" if state["complete"] else "router_reply"

    def after_industry(state: State):
        # One system: a diagram would be a single box, so skip it.
        return "draw_diagram" if len(state["info"]["systems"]) > 1 else "confirm_prompt"

    def classify_industry_node(state: State):
        """Systems Expert: label each system's industry so the user can check it
        before any CVE lookup. The confirmed labels are saved inside `info`."""
        labels = classify_industry(generate, state["info"]["systems"])
        return {
            "info": {**state["info"], "industry": labels},
            "trace": [step("systems_expert", "classify_industry", labels)],
        }

    def confirm_prompt(state: State):
        """Router: show the diagram and wait for the user's OK before any CVE lookup."""
        info, diagram = state["info"], state.get("diagram")
        if diagram:
            key = colour_key(info["systems"], info.get("industry"))
            answer = (
                "Here's the network I'll check:\n\n"
                f"- **Systems ({info['count']}, {info['scope']}):** {', '.join(info['systems'])}\n"
                f"- **Industry:** {industry_text(info)}\n\n"
                f"### Block diagram\n\n```mermaid\n{diagram['mermaid']}\n```\n\n"
                + (f"**Colours:** {key}\n\n" if key else "")
                + "_Connections are assumed: every system is linked to the networking device (the red box). "
                "If there is no networking device, no systems are shown as connected._\n\n"
                + CONFIRM_QUESTION.format(where=CONFIRM_WHERE_DIAGRAM)
            )
        else:  # one system: no diagram
            answer = (
                "Here's the system I'll check:\n\n"
                f"- **System:** {info['systems'][0]}\n"
                f"- **Industry:** {industry_text(info)}\n\n"
                + CONFIRM_QUESTION.format(where=CONFIRM_WHERE_SINGLE)
            )
        return {
            "answer": answer,
            "waiting_for": "confirm",
            "trace": [step("router", "confirm_diagram", {})],
        }

    def revise_node(state: State):
        """Systems Expert: apply the user's correction, then redraw."""
        info = state["info"]
        result = revise(generate, info, state["conversation"][-1]["content"])
        trace = step("systems_expert", "revise", result)
        if not result["changed"]:
            # Nothing changed: explain, and keep waiting with the same diagram.
            return {"changed": False, "answer": result["message"], "waiting_for": "confirm", "trace": [trace]}
        # The correction may have added a second system (now a diagram is useful)
        # or removed down to one (the diagram goes away).
        new_diagram = None
        if len(result["info"]["systems"]) > 1:
            new_diagram = {
                "mermaid": build_diagram(result["info"]["systems"], result["info"].get("industry")),
                "source": "edited",
            }
        return {"changed": True, "info": result["info"], "diagram": new_diagram, "trace": [trace]}

    def after_revise(state: State):
        return "confirm_prompt" if state["changed"] else "ask_user"

    def draw_diagram_node(state: State):
        diagram = draw_diagram(state["info"])
        return {"diagram": diagram, "trace": [step("systems_expert", "block_diagram", diagram)]}

    # ---- Vulnerability Expert (the only node with the CVE tool) -------------
    async def vulnerability_expert(state: State):
        if state["route"] == "cve_lookup":
            results = await look_up_ids(state["cve_ids"])
        else:
            systems = state.get("queue") or state["info"]["systems"]
            tried = state.get("tried") or {}
            queries = {s: query_variants(s)[tried.get(s, 0)] for s in systems}
            results = await find_cves(state["info"], systems, queries)
        return {"results": results, "trace": [step("vulnerability_expert", "vulnerability_results", results)]}

    def verify_node(state: State):
        """Systems Expert: drop CVE records that only share a keyword with the system.

        Relevance is judged BEFORE the cut to the worst few per system, so
        irrelevant high-scoring records can't crowd out real ones. If a system
        has nothing relevant left, `queue` asks the Vulnerability Expert to
        search again with a broader name (see after_verify).
        """
        results, info = state["results"], state["info"]  # results = this round's findings
        verdict = verify_cves(generate, results, info.get("industry"))

        old = state.get("pool") or {}
        # The same CVE can turn up again in a broader search round: list a demoted one once.
        demoted = old.get("demoted", [])
        seen = {(d["system"], d["cve_id"]) for d in demoted}
        demoted = demoted + [d for d in verdict["demoted"] if (d["system"], d["cve_id"]) not in seen]
        # Every search text tried for each system (a broader one is added each round),
        # so the Writer can say what was searched when a system matches nothing.
        searched = {system: list(texts) for system, texts in old.get("searched", {}).items()}
        for system, query in results["queries"].items():
            if query not in searched.setdefault(system, []):
                searched[system].append(query)
        pool = {
            "searched": searched,
            "kept": old.get("kept", []) + verdict["kept"],
            "excluded": old.get("excluded", []) + verdict["excluded"],
            "demoted": demoted,
            "unverified": old.get("unverified", []) + verdict["unverified"],
            "errors": old.get("errors", []) + results["errors"],
            "error_systems": old.get("error_systems", []) + results["error_systems"],
        }
        kept_systems = {r["system"] for r in pool["kept"]}

        # Which systems still have nothing relevant, and still have a broader search to try?
        tried = dict(state.get("tried") or {})
        queue = []
        for system in results["queries"]:
            tried[system] = tried.get(system, 0) + 1
            if (
                system not in kept_systems
                and system not in pool["error_systems"]
                and tried[system] < len(query_variants(system))
            ):
                queue.append(system)

        # The results the Writer will use: worst few per system, relevant only.
        rows, per_system = [], {}
        for row in sorted(pool["kept"], key=lambda r: r.get("cvss") or 0, reverse=True):
            if per_system.get(row["system"], 0) < MAX_CVES_PER_SYSTEM:
                per_system[row["system"]] = per_system.get(row["system"], 0) + 1
                rows.append(row)
        no_results = [s for s in info["systems"] if s not in kept_systems and s not in pool["error_systems"]]
        # A system is "broadened" when its CVEs only came from a broader search than its own name.
        broadened = {}
        for system in kept_systems:
            queries = {r["query"] for r in pool["kept"] if r["system"] == system}
            if system not in queries:
                broadened[system] = sorted(queries)[0]

        checked = dict(
            results,
            rows=rows,
            no_results=no_results,
            errors=pool["errors"],
            excluded=pool["excluded"],
            demoted=pool["demoted"],
            unverified=pool["unverified"],
            broadened=broadened,
            searched=pool["searched"],
        )
        summary = {
            "searched_for": results["queries"],
            "checked": len(results["rows"]),
            "kept": len(verdict["kept"]),
            "excluded": verdict["excluded"],
            "demoted": verdict["demoted"],
            "unverified": verdict["unverified"],
            "search_again_for": queue,
        }
        return {
            "results": checked,
            "pool": pool,
            "tried": tried,
            "queue": queue,
            "trace": [step("systems_expert", "verify_cves", summary)],
        }

    def after_verify(state: State):
        # Loop back to the Vulnerability Expert while some system has nothing relevant yet.
        if state["queue"]:
            return "vulnerability_expert"
        return "writer"

    def after_vulnerability_expert(state: State):
        # A direct CVE id lookup has no system to check it against.
        return "writer" if state["route"] == "cve_lookup" else "verify_cves"

    # ---- Writer ------------------------------------------------------------
    def writer(state: State):
        if state["route"] == "requirements":  # after the Evaluator handed over: the requirements per component
            report = write_requirements_report(generate, state.get("req_done") or [])
            # The subgraph kept its steps in its own key; this is where they join the trace, once.
            return {
                "report": report,
                "trace": [*state.get("req_trace", []), step("writer", "requirements_report", report)],
            }
        report = write_report(generate, state["results"])
        return {"report": report, "trace": [step("writer", "final_report", report)]}

    # ---- Wire it together --------------------------------------------------
    graph = StateGraph(State)

    def add(name, node):
        graph.add_node(name, track_node(name, node, on_event))

    add("router_decide", router_decide)
    add("classify", classify)
    add("offer", offer)
    add("cancel", cancel)
    add("decline", decline)
    add("chat", chat)
    add("ask_user", ask_user)
    add("systems_intake", systems_intake)
    add("classify_industry", classify_industry_node)
    add("draw_diagram", draw_diagram_node)
    add("confirm_prompt", confirm_prompt)
    add("revise", revise_node)
    add("vulnerability_expert", vulnerability_expert)
    add("verify_cves", verify_node)
    add("writer", writer)
    add("router_reply", router_reply)
    # The requirements loop is a graph of its own; here it is one node. It tracks its own inner steps.
    graph.add_node("requirements", build_requirements_graph(generate, on_event))

    graph.add_edge(START, "router_decide")
    graph.add_conditional_edges(
        "router_decide",
        pick_path,
        {
            "cve_lookup": "vulnerability_expert",
            "intake": "systems_intake",
            "classify": "classify",
            "cancel": "cancel",
            "continue": "vulnerability_expert",
            "revise": "revise",
            "requirements": "requirements",
            "decline": "decline",
            "chat": "chat",
            "restart": END,
        },
    )
    graph.add_edge("ask_user", "router_decide")  # the user replied: decide what that reply means
    graph.add_conditional_edges("revise", after_revise, {"confirm_prompt": "confirm_prompt", "ask_user": "ask_user"})
    graph.add_edge("confirm_prompt", "ask_user")
    graph.add_edge("cancel", END)
    graph.add_edge("decline", END)
    graph.add_conditional_edges("classify", pick_path, {"offer": "offer", "chat": "chat"})
    graph.add_edge("offer", "ask_user")
    graph.add_conditional_edges(
        "systems_intake", after_intake, {"classify_industry": "classify_industry", "router_reply": "router_reply"}
    )
    graph.add_conditional_edges(
        "classify_industry", after_industry, {"draw_diagram": "draw_diagram", "confirm_prompt": "confirm_prompt"}
    )
    graph.add_edge("draw_diagram", "confirm_prompt")
    graph.add_conditional_edges(
        "vulnerability_expert", after_vulnerability_expert, {"writer": "writer", "verify_cves": "verify_cves"}
    )
    graph.add_conditional_edges(
        "verify_cves", after_verify, {"vulnerability_expert": "vulnerability_expert", "writer": "writer"}
    )
    graph.add_edge("requirements", "writer")
    graph.add_edge("writer", "router_reply")
    graph.add_conditional_edges("router_reply", after_reply, {"ask_user": "ask_user", END: END})
    graph.add_edge("chat", END)
    return graph.compile(checkpointer=checkpointer)
