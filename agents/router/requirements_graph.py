"""The requirements loop as a LangGraph SUBGRAPH.

One graph, used twice: the app's main graph (router/graph.py) runs it as a single node, and
run_requirements() below runs it on its own for scripts and tests (tests/try_requirements.py). So the
loop is written once.

The loop, one component (one of the user's systems) at a time:

    START -> write_requirements [Vulnerability Expert] -> review_requirements [Evaluator]
                 clean, or the 2nd review done -> next component, or END when none are left
                 mistakes and a review left   -> revise_requirements [Vulnerability Expert]
                                                    -> review_requirements

The Evaluator hands each finished component on (it goes into `req_done`) with whatever mistakes
remain; the Writer shows them. Mistakes that are still there after the last review are reported,
not fixed. The rule "at most 2 reviews" is MAX_REVIEWS below.

State: the subgraph shares `results` (in) and `req_done` (out) with the main graph. Its trace
lines go in their OWN key, `req_trace`: sharing the main graph's `trace` would add the lines that
were already there a second time (the subgraph hands back its whole copy of a shared list).
"""

import asyncio
import operator
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph

from evaluator.agent import review_component
from router.tracking import step, track_node
from vulnerability_expert.requirements import (
    next_number,
    revise_component_requirements,
    write_component_requirements,
)
from writer.agent import group_rows_by_system

MAX_REVIEWS = 2  # the Vulnerability Expert may send its requirements to the Evaluator at most this many times


def needs_another_review(review, reviews_done):
    """True if the Evaluator found something the Vulnerability Expert can fix AND a review is left."""
    return reviews_done < MAX_REVIEWS and bool(review["rewrite_requests"])


class RequirementsState(TypedDict, total=False):
    results: dict  # in: {"rows": [...], "systems": [...]}, the verified CVE rows (see router/graph.py verify_cves)
    req_groups: dict  # {component: its CVE rows}
    req_queue: list  # components still to do
    req_current: dict  # the component being worked on (None between components)
    req_done: list  # out: finished components, in order, what the Writer shows
    req_trace: Annotated[list, operator.add]  # out: the steps taken, for the UI


def build_requirements_graph(generate, on_event=None):
    """The compiled subgraph. `generate` is the model backend; `on_event` is the UI's activity callback."""

    def write_requirements(state: RequirementsState):
        """Vulnerability Expert: write the requirements for the next component's CVEs."""
        groups = state.get("req_groups")
        if groups is None:  # first time: one group per system, in the user's order
            groups = {}
            rows = group_rows_by_system(state["results"]["rows"], state["results"].get("systems"))
            for row in rows:
                groups.setdefault(row["system"], []).append(row)
            queue = list(groups)
        else:
            queue = state["req_queue"]
        component, rest = queue[0], queue[1:]
        done = state.get("req_done") or []
        first_number = next_number([r for item in done for r in item["requirements"]])
        written = write_component_requirements(generate, component, groups[component], first_number)
        current = {
            "component": component,
            "requirements": written["requirements"],
            "cve_rows": groups[component],
            "write_log": written["cves"],
            "reviews_done": 0,
            "review": None,
        }
        summary = {"component": component, "requirements": len(written["requirements"]), "cves": written["cves"]}
        return {
            "req_groups": groups,
            "req_queue": rest,
            "req_current": current,
            "req_trace": [step("vulnerability_expert", "write_requirements", summary)],
        }

    def review_requirements(state: RequirementsState):
        """Evaluator: review the component. If the Vulnerability Expert can still fix something
        and a review is left, send it back. Otherwise the Evaluator hands the component on
        (it goes into req_done) with whatever mistakes remain."""
        current = state["req_current"]
        review = review_component(generate, current["component"], current["requirements"], current["cve_rows"])
        current = {**current, "reviews_done": current["reviews_done"] + 1, "review": review}
        summary = {
            "component": current["component"],
            "review": f"{current['reviews_done']} of at most {MAX_REVIEWS}",
            "overall": review["overall"],
            "requirement_status": review["requirement_status"],
            "issues": review["issues"],
            "component_issues": review["component_issues"],
            # What the model actually wrote for any review we doubted (its problems, rewrite, reasoning,
            # quote), so the user can see WHY it was flagged in the step's expander.
            "flagged_reviews": [rv for rv in review["reviews"] if rv["flags"]],
        }
        update = {"req_trace": [step("evaluator", "review_requirements", summary)]}
        if needs_another_review(review, current["reviews_done"]):
            update["req_current"] = current
        else:
            update["req_done"] = (state.get("req_done") or []) + [current]
            update["req_current"] = None
        return update

    def revise_requirements(state: RequirementsState):
        """Vulnerability Expert: rewrite the CVEs the Evaluator found problems with."""
        current = state["req_current"]
        revised = revise_component_requirements(
            generate, current["component"], current["requirements"], current["cve_rows"],
            current["review"]["rewrite_requests"],
        )
        summary = {"component": current["component"], "rewritten": revised["cves"]}
        return {
            "req_current": {**current, "requirements": revised["requirements"]},
            "req_trace": [step("vulnerability_expert", "revise_requirements", summary)],
        }

    def has_rows(state: RequirementsState):
        # Nothing to write requirements for: finish at once with no components.
        return "write_requirements" if state["results"]["rows"] else END

    def after_review(state: RequirementsState):
        if state.get("req_current"):  # the Evaluator sent it back for a rewrite
            return "revise_requirements"
        return "write_requirements" if state["req_queue"] else END

    graph = StateGraph(RequirementsState)
    for name, node in (
        ("write_requirements", write_requirements),
        ("review_requirements", review_requirements),
        ("revise_requirements", revise_requirements),
    ):
        graph.add_node(name, track_node(name, node, on_event))
    graph.add_conditional_edges(START, has_rows, {"write_requirements": "write_requirements", END: END})
    graph.add_edge("write_requirements", "review_requirements")
    graph.add_conditional_edges(
        "review_requirements",
        after_review,
        {"revise_requirements": "revise_requirements", "write_requirements": "write_requirements", END: END},
    )
    graph.add_edge("revise_requirements", "review_requirements")
    return graph.compile()


async def arun_requirements(generate, rows, systems=None, on_event=None):
    """Run the whole loop on its own and return the finished components, in order.

    Each one is {"component", "requirements", "cve_rows", "write_log", "reviews_done", "review"}.
    `rows` are CVE rows with a "system" field (the component). `systems` is the order to
    show them in (default: the order they first appear). The app runs the same subgraph inside its
    main graph; this runs it by itself.
    """
    graph = build_requirements_graph(generate, on_event)
    final = await graph.ainvoke({"results": {"rows": list(rows), "systems": systems}, "req_trace": []})
    return final.get("req_done") or []


def run_requirements(generate, rows, systems=None, on_event=None):
    """arun_requirements() for code that is not async (scripts and tests).

    It uses LangGraph's async run on purpose: with `on_event` the nodes are async (see
    router/tracking.py), and the plain synchronous run cannot call those.
    """
    return asyncio.run(arun_requirements(generate, rows, systems, on_event))
