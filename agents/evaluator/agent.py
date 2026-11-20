"""Evaluator agent: reviews the requirements written for ONE component.

It uses the "incose-evaluator" skill. The model does the judging, but code does
everything that does not need judgment and checks the model's work:

  1. Code runs the regex gate on the requirements (a baseline, shown in the review).
  2. The model reviews the requirements (the whole component in one call). Code then checks the reply:
       - every requirement was reviewed (a missing one is "not_reviewed")
       - the model's quote really appears in the requirement (else flagged
         "quote_mismatch": the model may be making things up)
       - a "revise" has named problems and a suggested rewrite
     If the model cannot answer in valid JSON, the review is "unchecked". It is
     NEVER counted as a pass.
  3. Code works out CVE coverage and duplicate ids itself (no model needed).

The Evaluator reports. It never rewrites the requirements. Its "rewrite_requests"
are grouped by CVE so the Vulnerability Expert can redo one CVE at a time, and its
"issues" are what the Writer shows the user if mistakes remain.

Use it: review_component(generate, component, requirements, cves) where `generate`
is the same model function the other agents get, `requirements` is the Vulnerability
Expert's list for this component and `cves` are the CVE rows for this component.
"""

import json

from shared.model_replies import ask_until_ok, first_json
from shared.requirements_gate import check_all
from shared.skills import get_skill

NAME = "Evaluator"

EVALUATOR_MAX_NEW_TOKENS = 3000
MAX_DESCRIPTION_CHARS = 600

SYSTEM_PROMPT = (
    "You are the Evaluator on a team of security agents. You review requirements "
    "carefully and fairly. You only mark a problem you can name and quote."
)

# What a flag means, in words for the user.
FLAG_TEXT = {
    "quote_mismatch": "the review did not quote this requirement correctly, so it needs a human check",
    "not_reviewed": "the Evaluator did not review this requirement",
    "bad_verdict": "the review gave no clear pass or revise",
    "empty_reasoning": "the review gave no reasoning, so it needs a human check",
    "revise_without_evidence": "marked for revision with no problem, reasoning or rewrite given, so it needs a human check",
}


# ---- Preparing the data -------------------------------------------------------

def _cves_of(req):
    return [str(c) for c in (req.get("sources") or {}).get("cves") or []]


def _for_the_model(req):
    """The requirement as the model sees it. gate_status is left out on purpose:
    the Evaluator must not be nudged by whether the simple word check passed."""
    return {k: v for k, v in req.items() if k != "gate_status"}


def _cve_records(cves, ids):
    wanted = set(ids)
    records = []
    for cve in cves:
        if cve["cve_id"] in wanted:
            description = " ".join(str(cve.get("description") or "N/A").split())
            if len(description) > MAX_DESCRIPTION_CHARS:
                description = description[:MAX_DESCRIPTION_CHARS].rstrip() + "..."
            records.append({"cve_id": cve["cve_id"], "system": cve.get("system") or "N/A", "description": description})
    return records


# ---- Reading and checking the model's reply -----------------------------------

def parse_json_object(text):
    """Find the first JSON object in the model's reply (code fences etc. are fine)."""
    found = first_json(text, lambda value: isinstance(value, dict))
    if found is None:
        raise ValueError("Your reply must be ONE JSON object, and nothing else.")
    return found


def _squash(text):
    return " ".join(str(text).split()).casefold()


def _not_reviewed(req):
    return {"id": req["id"], "quote": "", "reasoning": "", "problems": [], "verdict": "not_reviewed",
            "severity": "none", "suggested_rewrite": "", "flags": ["not_reviewed"]}


# A small model does not always use the exact field names or shapes the skill asks for, so we accept
# the obvious variants instead of calling a review "without evidence" over a spelling.
PROBLEM_KEYS = ("problems", "problem", "issues", "violations")
REWRITE_KEYS = ("suggested_rewrite", "suggested_rewrites", "rewrite", "suggestion")
REASONING_KEYS = ("reasoning", "reason")


def _pick(review, keys):
    """The first non-empty value among these field names (or None)."""
    for key in keys:
        if review.get(key):
            return review[key]
    return None


def _as_text(value):
    if isinstance(value, list):  # e.g. a list holding one rewrite
        value = " ".join(str(v) for v in value)
    return str(value or "")


def _as_problems(value):
    """The model's problems as a list of {"rule", "evidence", "explanation"}.

    It may write a list of objects (as asked), one object, plain text, or a list of plain text.
    Plain text is kept as the explanation, with no rule named.
    """
    if not value:
        return []
    items = value if isinstance(value, list) else [value]
    problems = []
    for item in items:
        if isinstance(item, dict):
            problems.append(item)
        elif str(item).strip():
            problems.append({"rule": "", "evidence": "", "explanation": str(item).strip()})
    return problems


def check_review(review, req):
    """Clean one model review of one requirement. Adds "flags" for anything doubtful."""
    problems = _as_problems(_pick(review, PROBLEM_KEYS))
    reasoning = _as_text(_pick(review, REASONING_KEYS))
    rewrite = _as_text(_pick(review, REWRITE_KEYS))
    verdict = review.get("verdict") if review.get("verdict") in ("pass", "revise") else None
    if verdict == "revise" and not problems and reasoning.strip():
        # The model explained what is wrong in its reasoning but left "problems" empty. Keep what it said
        # as the problem (no rule named) instead of throwing it away: it is shown to the user and the rewriter.
        problems = [{"rule": "", "evidence": "", "explanation": reasoning.strip()}]
    cleaned = {
        "id": req["id"],
        "quote": str(review.get("quote") or ""),
        "reasoning": reasoning,
        "problems": problems,
        "verdict": verdict or "not_reviewed",
        "severity": review.get("severity") if review.get("severity") in ("major", "minor") else "none",
        "suggested_rewrite": rewrite,
        "flags": [],
    }
    if verdict is None:
        cleaned["flags"].append("bad_verdict")
    if not cleaned["quote"] or _squash(cleaned["quote"]) not in _squash(req.get("statement") or ""):
        cleaned["flags"].append("quote_mismatch")  # the model did not quote what is really there
    if not cleaned["reasoning"].strip():
        cleaned["flags"].append("empty_reasoning")
    if verdict == "revise" and not problems and not rewrite.strip():
        # Nothing at all to act on: no problem, no reasoning, no rewrite. Just the word "revise".
        cleaned["flags"].append("revise_without_evidence")
    return cleaned


def check_reply(reply, requirements):
    """Match the model's reply to the requirements. Returns (reviews, other_findings, problems)."""
    found = parse_json_object(reply)  # raises ValueError if there is no JSON
    items = found.get("requirements") if isinstance(found.get("requirements"), list) else []
    by_id = {str(i.get("id")): i for i in items if isinstance(i, dict)}
    reviews, problems = [], []
    for req in requirements:
        review = by_id.get(req["id"])
        if review is None:
            problems.append(f"{req['id']} was not reviewed.")
            reviews.append(_not_reviewed(req))
            continue
        cleaned = check_review(review, req)
        if "bad_verdict" in cleaned["flags"]:
            problems.append(f"{req['id']}: verdict must be \"pass\" or \"revise\".")
        if "revise_without_evidence" in cleaned["flags"]:
            problems.append(
                f"{req['id']}: a \"revise\" needs at least one item in \"problems\" and a \"suggested_rewrite\"."
            )
        reviews.append(cleaned)
    other = {k: found[k] for k in ("duplicates", "contradictions", "terminology") if isinstance(found.get(k), list)}
    return reviews, other, problems


def _ask(generate, user_text, requirements):
    """Ask the model, check the reply, and retry once with the problems listed.

    Returns ((reviews, other), problems_left). problems_left is non-empty if even the
    last try had some (the reviews may still be partly usable). The result is None if
    the model never produced valid JSON.
    """
    skill = get_skill("incose-evaluator")
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT + "\n\n" + skill["instructions"]},
        {"role": "user", "content": user_text},
    ]

    def check(reply):
        reviews, other, problems = check_reply(reply, requirements)  # ValueError if there is no JSON in it
        return (reviews, other), problems

    return ask_until_ok(
        generate, messages, check, EVALUATOR_MAX_NEW_TOKENS, outro="Reply again with the whole corrected JSON."
    )


# ---- The agent ----------------------------------------------------------------

def review_component(generate, component, requirements, cves):
    """Review the requirements of one component, in ONE model call. Returns the review (see _build_review)."""
    no_findings = {"duplicates": [], "contradictions": [], "terminology": []}
    if not requirements:  # nothing to ask the model about
        return _build_review(component, requirements, cves, [], no_findings, None)
    cve_ids = [c for r in requirements for c in _cves_of(r)]
    user_text = (
        f"Component: {component}\n\n"
        "Requirements (JSON):\n" + json.dumps([_for_the_model(r) for r in requirements], indent=1)
        + "\n\nCVE records (JSON):\n" + json.dumps(_cve_records(cves, cve_ids), indent=1)
        + "\n\nReview them now."
    )
    outcome, problems = _ask(generate, user_text, requirements)
    if outcome is None:  # no usable JSON at all: nothing was judged
        unjudged = [_not_reviewed(r) for r in requirements]
        return _build_review(component, requirements, cves, unjudged, no_findings, problems[0])
    reviews, other = outcome
    return _build_review(component, requirements, cves, reviews, {**no_findings, **other}, None)


def _rules(review):
    """The rules the Evaluator named, like "vague_term, singular" (empty if it named none)."""
    return ", ".join(str(p["rule"]) for p in review["problems"] if isinstance(p, dict) and p.get("rule"))


def _detail(review):
    """What to tell the user or the rewriter: the suggested rewrite, else what was wrong, else the reasoning."""
    explained = "; ".join(str(p["explanation"]) for p in review["problems"] if isinstance(p, dict) and p.get("explanation"))
    return review["suggested_rewrite"] or explained or review["reasoning"]


def _issue_texts(review):
    """Words for the user about one reviewed requirement (empty if it is fine)."""
    texts = []
    if review["verdict"] == "revise":
        rules = _rules(review)
        texts.append(f"{rules + ': ' if rules else ''}{_detail(review)}".strip() or "needs revision")
    texts += [FLAG_TEXT[f] for f in review["flags"] if f in FLAG_TEXT]
    return texts


def _build_review(component, requirements, cves, reviews, other, error):
    gate = check_all(requirements)
    gate_by_id = {r["id"]: r for r in gate["results"]}
    known = {c["cve_id"] for c in cves}
    cited = {cve for r in requirements for cve in _cves_of(r)}
    ids = [r["id"] for r in requirements]
    code_checks = {
        "uncovered_cves": sorted(known - cited),  # a CVE of this component with no requirement
        "unknown_cves": sorted(cited - known),  # a requirement cites a CVE we were never given
        "duplicate_ids": sorted({i for i in ids if ids.count(i) > 1}),
    }

    issues, status = {}, {}
    for req, review in zip(requirements, reviews):
        texts = _issue_texts(review)
        texts += [f"word check: {e['rule']}" for e in gate_by_id[req["id"]]["errors"]]
        issues[req["id"]] = texts
        status[req["id"]] = "pass" if review["verdict"] == "pass" and not texts else "needs_review"

    component_issues = []
    if error:
        component_issues.append(f"The Evaluator gave no usable review: {error}")
    if not requirements:
        component_issues.append("No requirements were written for this component.")
    component_issues += [f"No requirement covers {c}." for c in code_checks["uncovered_cves"]]
    component_issues += [f"A requirement cites {c}, which is not one of this component's CVEs." for c in code_checks["unknown_cves"]]
    component_issues += [f"The id {i} is used more than once." for i in code_checks["duplicate_ids"]]
    for key, label in (("duplicates", "Duplicate"), ("contradictions", "Contradiction"), ("terminology", "Naming")):
        component_issues += [f"{label}: {item if isinstance(item, str) else json.dumps(item)}" for item in other[key]]

    # Rewrite requests, grouped by CVE because the Vulnerability Expert redoes one CVE at a time.
    requests = {}
    for req, review in zip(requirements, reviews):
        if review["verdict"] == "revise":
            text = f"{req['id']} ({_rules(review) or 'rule not named'}): {_detail(review)}"
            requests.setdefault(tuple(sorted(_cves_of(req))), []).append((req["id"], text))
    for cve_id in code_checks["uncovered_cves"]:  # give a CVE with no requirement a second chance
        requests.setdefault((cve_id,), []).append(("", f"No requirement was written for {cve_id}. Write one."))
    rewrite_requests = [
        {"cves": list(cves_), "ids": [i for i, _ in items if i], "instructions": " | ".join(t for _, t in items)}
        for cves_, items in requests.items()
    ]

    not_judged = error is not None or any(rv["verdict"] == "not_reviewed" for rv in reviews)
    if not requirements or not_judged:
        overall = "incomplete"  # something was never judged: do not call it a pass
    else:
        overall = "revise" if (component_issues or "needs_review" in status.values()) else "pass"

    return {
        "component": component,
        "overall": overall,  # "pass", "revise" or "incomplete"
        "status": "unchecked" if (error or not requirements) else "checked",
        "requirement_ids": ids,
        "reviews": reviews,
        "other": other,
        "gate": {"passed": gate["passed"], "error_count": gate["error_count"], "warning_count": gate["warning_count"]},
        "code_checks": code_checks,
        "requirement_status": status,  # id -> "pass" | "needs_review"
        "issues": issues,  # id -> [what is wrong]
        "component_issues": component_issues,  # problems with the component as a whole
        "rewrite_requests": rewrite_requests,
    }
