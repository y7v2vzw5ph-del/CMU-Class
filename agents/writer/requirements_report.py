"""The Writer's requirements output: one section per component.

Each requirement has a Quality check in its table row (Pass or Needs review). The component's own heading
shows only its name: no Pass, Needs review or any other mark next to the system's name.

Two skills do the formatting, with the model:
  - "requirements-table":  the table of one component's requirements
  - "requirements-report": the section around it (heading, CVEs, issues)
                           with a [TABLE] marker where the table goes

We do NOT trust the model blindly (same idea as the vulnerability table in agent.py).
Code checks each reply against the real data: ids, CVEs and quality checks in the table; the
exact heading (just the component's name), every CVE, every issue and no made-up ids in the section.
The model gets one chance to fix the listed problems. If it is still wrong, plain code builds that
part, so the user never sees a wrong quality check or a missing issue. Code also puts the verified
table into the section, so the model never has to copy the table twice.

The input is what the graph collected: a list with one entry per component,
{"component", "requirements", "cve_rows", "reviews_done", "review", ...}
(see router/requirements_graph.py). Pass generate=None to skip the model (code only).
"""

import json
import re

from shared.model_replies import MAX_PROBLEMS_SHOWN, ask_until_ok
from shared.skills import get_skill
from writer.tables import SEPARATOR_RE, extract_table, split_cells

PASS = "✅ Pass"
NEEDS_REVIEW = "⚠️ Needs review"

INTRO = (
    "_Written by the Vulnerability Expert from the CVE records and checked by the Evaluator against "
    "INCOSE rules. **Needs review** means a mistake was still found after the last review. "
    "A pass means the Evaluator found no mistakes. It does not mean the requirements are verified "
    "for your product._"
)

TABLE_MARKER = "[TABLE]"
TABLE_HEADER = "| ID | Requirement | CVE | CWE | Verification | Quality check |"
TABLE_SEPARATOR = "| --- | --- | --- | --- | --- | --- |"
TABLE_MAX_NEW_TOKENS = 2500  # a table with many requirements is long
SECTION_MAX_NEW_TOKENS = 1200
PREFIX_CHARS = 30  # long texts are checked by their start only: this still catches invented text

SYSTEM_PROMPT = (
    "You are the Writer on a team of security agents. You turn data into clear tables and reports. "
    "You never change or invent data."
)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
REQ_RE = re.compile(r"REQ-\d{3,}")


# ---- The data the skills (and the code fallback) work from ----------------------

def component_passes(item):
    review = item["review"]
    return (
        bool(item["requirements"])
        and review["overall"] == "pass"
        and all(s == "pass" for s in review["requirement_status"].values())
    )


def requirement_label(item, requirement):
    result = item["review"]["requirement_status"].get(requirement["id"])
    return PASS if result == "pass" else NEEDS_REVIEW


def _cve_text(row):
    parts = []
    if row.get("cvss") is not None:
        parts.append(f"CVSS {row['cvss']}")
    if row.get("severity"):
        parts.append(str(row["severity"]))
    return row["cve_id"] + (f" ({', '.join(parts)})" if parts else "")


def table_rows(item):
    """One plain-text dict per requirement: the data for the "requirements-table" skill."""
    rows = []
    for req in item["requirements"]:
        verification = req.get("verification") or {}
        how = f"{verification.get('method', '')}: {verification.get('criterion', '')}" if verification else ""
        rows.append(
            {
                "id": req["id"],
                "requirement": " ".join(str(req["statement"]).split()),
                "cve": ", ".join(req["sources"]["cves"]),
                "cwe": ", ".join(req["sources"].get("cwes") or []) or "N/A",
                "verification": " ".join(how.split()),
                "quality_check": requirement_label(item, req),
            }
        )
    return rows


def section_data(item):
    """The data for the "requirements-report" skill. `issues` is empty for a component that passes.

    There is deliberately no pass / needs-review field here: the heading is just the component's name.
    """
    reviews = item["reviews_done"]
    review = item["review"]
    issues = []
    if not component_passes(item):
        issues = [f"{rid}: {text}" for rid, texts in review["issues"].items() for text in texts]
        issues += list(review["component_issues"])
    return {
        "component": item["component"],
        "cves": [_cve_text(r) for r in item["cve_rows"]],
        "reviewed": f"Reviewed by the Evaluator {reviews} time{'' if reviews == 1 else 's'}.",
        "table": TABLE_MARKER if item["requirements"] else None,
        "issues": issues,
    }


# ---- The code versions (the safety net, and what runs without a model) ----------

def build_table(rows):
    lines = [TABLE_HEADER, TABLE_SEPARATOR]
    for r in rows:
        cells = [r["id"], r["requirement"], r["cve"], r["cwe"], r["verification"], r["quality_check"]]
        lines.append("| " + " | ".join(str(c).replace("|", "\\|") for c in cells) + " |")
    return "\n".join(lines)


def build_section(data, table_md):
    lines = [
        f"#### {data['component']}",
        "**CVEs:** " + (", ".join(data["cves"]) or "none"),
        f"_{data['reviewed']}_",
    ]
    if data["table"]:
        lines.append(table_md)
    if data["issues"]:
        lines.append("**Issues the Evaluator found:**\n\n" + "\n".join(f"- {text}" for text in data["issues"]))
    return "\n\n".join(lines)


# ---- Checking the model's work ---------------------------------------------------

def _prefix(text):
    return " ".join(str(text).split())[:PREFIX_CHARS].lower()


def check_table(text, rows):
    """Compare the model's table with the real rows. Returns a list of problems."""
    lines = [ln for ln in extract_table(text).splitlines() if not SEPARATOR_RE.match(ln)]
    if not lines:
        return ["There is no table in your reply."]
    data_lines = lines[1:]  # the first line is the header
    problems = []
    if len(data_lines) != len(rows):
        problems.append(f"The table must have exactly {len(rows)} data rows, but it has {len(data_lines)}.")
    for expected, line in zip(rows, data_lines):
        cells = split_cells(line)
        if len(cells) != 6:
            problems.append(f"Row {expected['id']} must have 6 columns, but has {len(cells)}.")
            continue
        rid, requirement, cve, cwe, verification, quality_check = cells
        if rid != expected["id"]:
            problems.append(f"The ID must be {expected['id']}, not '{rid}'.")
        if cve != expected["cve"]:
            problems.append(f"{expected['id']}: CVE must be {expected['cve']}, not '{cve}'.")
        if cwe != expected["cwe"]:
            problems.append(f"{expected['id']}: CWE must be {expected['cwe']}, not '{cwe}'.")
        if quality_check != expected["quality_check"]:
            problems.append(f"{expected['id']}: Quality check must be '{expected['quality_check']}', not '{quality_check}'.")
        if _prefix(requirement) != _prefix(expected["requirement"]):
            problems.append(f"{expected['id']}: the Requirement must be copied exactly from the data.")
        if _prefix(verification) != _prefix(expected["verification"]):
            problems.append(f"{expected['id']}: the Verification must be copied exactly from the data.")
    return problems


def _clean_section(text):
    """Drop code-fence lines the model sometimes adds around its answer."""
    return "\n".join(ln for ln in text.strip().splitlines() if not ln.strip().startswith("```")).strip()


def check_section(text, data):
    """Compare the model's section with the real data. Returns a list of problems."""
    text = _clean_section(text)
    lines = [ln.strip() for ln in text.splitlines()]
    problems = []
    heading = f"#### {data['component']}"  # exactly this: a mark the model adds next to the name is rejected
    if heading not in lines:
        problems.append(f"The heading line must be exactly: {heading}")
    for cve in data["cves"]:
        if cve not in text:
            problems.append(f"The CVE list must include: {cve}")
    if data["reviewed"] not in text:
        problems.append(f"The text must say: {data['reviewed']}")
    wanted = 1 if data["table"] else 0
    if text.count(TABLE_MARKER) != wanted:
        problems.append(f"The line {TABLE_MARKER} must appear exactly {wanted} time(s).")
    if any(ln.startswith("|") for ln in lines):
        problems.append("Do not write a table. Write the line [TABLE] and code puts the table there.")
    if data["issues"]:
        for issue in data["issues"]:
            if _prefix(issue) not in " ".join(text.split()).lower():
                problems.append(f"The issues list must include: {issue[:80]}")
    elif "issues the evaluator found" in text.lower():
        problems.append("There are no issues, so do not write an issues section.")
    # Ids the model may mention: the component's CVEs, and any id that is inside a given issue.
    allowed = {cve.split(" ")[0] for cve in data["cves"]} | set(CVE_RE.findall(" ".join(data["issues"])))
    problems += [f"{found} is not in the data. Do not invent ids." for found in CVE_RE.findall(text) if found not in allowed]
    known_reqs = set(REQ_RE.findall(" ".join(data["issues"])))
    problems += [f"{found} is not in the data. Do not invent ids." for found in REQ_RE.findall(text) if found not in known_reqs]
    return problems[:MAX_PROBLEMS_SHOWN]


# ---- Asking the model (with one chance to fix it) --------------------------------

def _ask(generate, skill_name, user_text, check, max_new_tokens):
    """Ask the model; if the reply has problems, show them and let it try once more.

    Returns the reply that passed the check, or None if neither try did.
    """
    skill = get_skill(skill_name)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT + "\n\n" + skill["instructions"]},
        {"role": "user", "content": user_text},
    ]
    reply, problems = ask_until_ok(generate, messages, lambda reply: (reply, check(reply)), max_new_tokens)
    return None if problems else reply


def write_component(generate, item):
    """The markdown for one component. Returns (markdown, {"table": source, "section": source}).

    A source is "model" (the model's version passed the checks) or "code" (the code-built
    version was used). "table" is None for a component with no requirements.
    """
    rows, data = table_rows(item), section_data(item)
    sources = {"table": None, "section": "code"}

    table_md = None
    if rows:
        reply = None
        if generate:
            text = "Requirements (JSON):\n" + json.dumps(rows, indent=1, ensure_ascii=False) + "\n\nWrite the table now."
            reply = _ask(generate, "requirements-table", text, lambda r: check_table(r, rows), TABLE_MAX_NEW_TOKENS)
        table_md, sources["table"] = (extract_table(reply), "model") if reply else (build_table(rows), "code")

    reply = None
    if generate:
        text = "Component data (JSON):\n" + json.dumps(data, indent=1, ensure_ascii=False) + "\n\nWrite the section now."
        reply = _ask(generate, "requirements-report", text, lambda r: check_section(r, data), SECTION_MAX_NEW_TOKENS)
    if reply:
        sources["section"] = "model"
        return _clean_section(reply).replace(TABLE_MARKER, table_md or ""), sources
    return build_section(data, table_md), sources


def build_requirements_report(generate, done):
    """The whole requirements section. Returns (markdown, sources) or (None, {}) if there is nothing.

    `sources` maps each component to {"table": ..., "section": ...} ("model" or "code").
    """
    if not done:
        return None, {}
    parts, sources = [], {}
    for item in done:
        markdown, sources[item["component"]] = write_component(generate, item)
        parts.append(markdown)
    text = "### Requirements\n\n" + INTRO + "\n\n" + "\n\n".join(parts)
    by_code = [name for name, s in sources.items() if "code" in (s["table"], s["section"])]
    if generate and by_code:  # same kind of note the vulnerability table gets
        text += (
            "\n\n_For some components the language model's formatting didn't match the data, so that part "
            "was built directly from the findings to keep it exact: " + ", ".join(by_code) + "._"
        )
    return text, sources
