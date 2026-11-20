"""Writer agent: turns the Vulnerability Expert's findings into the report.

Job: take the structured rows from the VE and produce a markdown table using
the "vulnerability-table" skill, then assemble the final report: the table,
plus any "no CVEs found" and error notes. (The block diagram is not in the
report: the user already confirmed it.) The language model does the
formatting, but we do NOT trust it blindly. Code checks the model's table against the real
data (CVE ids, scores, severities, row order). If the table is wrong, the
Writer asks the model to fix it once. If it's still wrong, the Writer builds
the table with plain code so the user never sees made-up numbers.

In the LangGraph (router/graph.py) this agent is one node that calls
write_report(generate, results) and returns {"markdown", "table_source"}
(table_source is "model" or "code").
"""

import json

from shared.model_replies import ask_until_ok
from shared.skills import get_skill
from writer.requirements_report import build_requirements_report
from writer.tables import SEPARATOR_RE, extract_table, split_cells

NAME = "Writer"

# A table with several CVEs is much longer than the 400-token default.
WRITER_MAX_NEW_TOKENS = 2500
# Very long descriptions make the model's job slower and riskier on CPU.
MAX_DESCRIPTION_CHARS = 400
MAX_EXCLUDED_SHOWN = 15  # how many excluded records to list in the report
MAX_DEMOTED_SHOWN = 15  # same for "not similar" (demoted) records, worst CVSS first

SYSTEM_PROMPT = (
    "You are the Writer on a team of security agents. You turn data into clear "
    "tables. You never change or invent data."
)

HEADER = "| # | System | CVE ID | CWE | Description | CVSS | Severity |"
SEPARATOR = "| --- | --- | --- | --- | --- | --- | --- |"


# ---- Preparing the data -------------------------------------------------------

def group_rows_by_system(rows, systems):
    """Put each system's rows together, in the order the user listed the systems.

    The sort is stable, so inside one system the rows keep the order they came in
    (worst CVSS first). Rows for a system that isn't in `systems` (like a direct
    CVE-id lookup) go at the end.
    """
    order = {system: i for i, system in enumerate(systems or [])}
    return sorted(rows, key=lambda row: order.get(row["system"], len(order)))


def prepare_rows(rows):
    """Number the rows and make every value plain text the model can copy."""
    prepared = []
    for number, row in enumerate(rows, start=1):
        description = " ".join((row.get("description") or "N/A").split())
        if len(description) > MAX_DESCRIPTION_CHARS:
            description = description[:MAX_DESCRIPTION_CHARS].rstrip() + "..."
        prepared.append(
            {
                "row": number,
                "system": row["system"],
                "cve_id": row["cve_id"],
                # "CWE-787, CWE-20", or N/A when NVD lists none (or the full lookup failed).
                "cwe": ", ".join(row.get("cwes") or []) or "N/A",
                "description": description,
                "cvss": str(row["cvss"]) if row.get("cvss") is not None else "N/A",
                "severity": row.get("severity") or "N/A",
            }
        )
    return prepared


def escape_cell(text):
    return str(text).replace("|", "\\|")


def build_table(prepared):
    """The plain-code table. Always correct; used as the safety net."""
    lines = [HEADER, SEPARATOR]
    for r in prepared:
        cells = [r["row"], r["system"], r["cve_id"], r["cwe"], r["description"], r["cvss"], r["severity"]]
        lines.append("| " + " | ".join(escape_cell(c) for c in cells) + " |")
    return "\n".join(lines)


# ---- Checking the model's table -----------------------------------------------

def check_table(text, prepared):
    """Compare the model's table with the real data. Returns a list of problems."""
    table = extract_table(text)
    lines = [ln for ln in table.splitlines() if not SEPARATOR_RE.match(ln)]
    if not lines:
        return ["There is no table in your reply."]
    data_lines = lines[1:]  # first line is the header
    problems = []
    if len(data_lines) != len(prepared):
        problems.append(
            f"The table must have exactly {len(prepared)} data rows, but it has {len(data_lines)}."
        )
    for expected, line in zip(prepared, data_lines):
        n = expected["row"]
        cells = split_cells(line)
        if len(cells) != 7:
            problems.append(f"Row {n} must have 7 columns, but has {len(cells)}.")
            continue
        number, system, cve_id, cwe, description, cvss, severity = cells
        if number != str(n):
            problems.append(f"Row {n}: the # column must be {n}, not '{number}'.")
        if system.lower() != expected["system"].lower():
            problems.append(f"Row {n}: System must be '{expected['system']}', not '{system}'.")
        if cve_id != expected["cve_id"]:
            problems.append(f"Row {n}: CVE ID must be {expected['cve_id']}, not '{cve_id}'.")
        if cwe != expected["cwe"]:
            problems.append(f"Row {n}: CWE must be {expected['cwe']}, not '{cwe}'.")
        if cvss != expected["cvss"]:
            problems.append(f"Row {n}: CVSS must be {expected['cvss']}, not '{cvss}'.")
        if severity.upper() != expected["severity"].upper():
            problems.append(f"Row {n}: Severity must be {expected['severity']}, not '{severity}'.")
        # Descriptions are long, so only check the start. This still catches invented text.
        if description[:30].lower() != expected["description"][:30].lower():
            problems.append(f"Row {n}: the Description must be copied exactly from the data.")
    return problems


# ---- The agent ----------------------------------------------------------------

def write_report(generate, results):
    """Make the table (if there are rows) and assemble the report.

    The block diagram is not part of it: the Router already showed the diagram
    and got the user's OK before the CVE lookup started.
    """
    prepared = prepare_rows(group_rows_by_system(results["rows"], results.get("systems")))
    table, source = None, None
    if prepared:
        table, source = _make_table(generate, prepared)
    return {"markdown": _assemble(table, source, results), "table_source": source}


def write_requirements_report(generate, requirements):
    """The requirements report, after the user said yes to the offer under the table.

    `requirements` is the list the graph collected (one entry per component, see
    router/requirements_graph.py). Each requirement lists the CVE(s) it traces to, and each
    component is marked Pass or Needs review. The model formats them with the
    "requirements-table" and "requirements-report" skills; code checks its work and falls
    back to a code-built version (see writer/requirements_report.py).
    "requirements_sources" says which parts the model wrote and which code built.
    """
    markdown, sources = build_requirements_report(generate, requirements)
    return {
        "markdown": markdown or "There were no requirements to write.",
        "table_source": "requirements",
        "requirements_sources": sources,
    }


def _make_table(generate, prepared):
    skill = get_skill("vulnerability-table")
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT + "\n\n" + skill["instructions"]},
        {
            "role": "user",
            "content": "Findings (JSON):\n"
            + json.dumps(prepared, indent=1)
            + "\n\nWrite the table now.",
        },
    ]
    # One chance to fix it, with the exact problems listed.
    table, problems = ask_until_ok(
        generate,
        messages,
        lambda reply: (extract_table(reply), check_table(reply, prepared)),
        WRITER_MAX_NEW_TOKENS,
        intro="Your table has problems:",
        outro="Write the whole table again, fixed.",
    )
    if not problems:
        return table, "model"
    return build_table(prepared), "code"  # safety net: never show a wrong table


def zero_cve_warnings(results):
    """One warning for each of the user's systems that has no CVEs in the table.

    Says what was searched, how many records were found but filtered out (a different
    product, or a different kind of product), and that no results is not a clean bill
    of health. Systems whose search FAILED are not here: they already get an error note.
    """
    systems = results.get("systems") or []
    searched = results.get("searched") or {}
    excluded, demoted = {}, {}
    for record in results.get("excluded") or []:
        excluded[record["system"]] = excluded.get(record["system"], 0) + 1
    for record in results.get("demoted") or []:
        demoted[record["system"]] = demoted.get(record["system"], 0) + 1

    warnings = []
    for system in results["no_results"]:
        if system not in systems:
            continue  # not a system (a CVE id from a direct lookup)
        text = f"⚠️ **No CVEs matched {system}.**"
        queries = searched.get(system) or []
        if queries:
            text += " I searched for " + ", then ".join(f'"{q}"' for q in queries) + "."
        filtered = []
        if excluded.get(system):
            filtered.append(f"{excluded[system]} matched a keyword but were about other products")
        if demoted.get(system):
            filtered.append(f"{demoted[system]} looked like the right vendor but a different kind of product")
        if filtered:
            text += " Records found but left out: " + "; ".join(filtered) + "."
        text += (
            " Please check that the name and version are spelled correctly. "
            "No results does not mean this system is secure."
        )
        warnings.append(text)
    return warnings


def _assemble(table, source, results):
    parts = []
    if table:
        parts.append("### Vulnerability table\n\n" + table)
        if source == "code":
            parts.append(
                "_The language model's table didn't match the data, so this table "
                "was built directly from the findings to keep the numbers exact._"
            )
    elif results.get("demoted"):
        parts.append("No CVEs closely matching your systems were found.")
    else:
        parts.append("No CVEs were found.")
    parts += zero_cve_warnings(results)
    other = [x for x in results["no_results"] if x not in (results.get("systems") or [])]
    if other:  # e.g. CVE ids from a direct lookup that NVD doesn't know
        parts.append("No CVEs found for: " + ", ".join(other))
    for system, query in (results.get("broadened") or {}).items():
        parts.append(
            f"_Searching for \"{system}\" found nothing relevant, so I also searched for \"{query}\". "
            "Those results may be about other versions or models of the product._"
        )
    excluded = results.get("excluded") or []
    if excluded:
        shown = excluded[:MAX_EXCLUDED_SHOWN]
        lines = [f"- {e['cve_id']} ({e['system']}): {e['reason'] or 'no reason given'}" for e in shown]
        if len(excluded) > len(shown):
            lines.append(f"- ...and {len(excluded) - len(shown)} more")
        parts.append(
            f"_The Systems Expert excluded {len(excluded)} CVE record(s) that matched a keyword "
            "but are not about your system:_\n\n" + "\n".join(lines)
        )
    demoted = sorted(results.get("demoted") or [], key=lambda d: d.get("cvss") or 0, reverse=True)
    if demoted:
        shown = demoted[:MAX_DEMOTED_SHOWN]
        lines = [
            f"- {d['cve_id']} ({d['system']}, CVSS {d['cvss'] if d.get('cvss') is not None else 'N/A'}): {d['reason']}"
            for d in shown
        ]
        if len(demoted) > len(shown):
            lines.append(f"- ...and {len(demoted) - len(shown)} more")
        parts.append(
            f"_{len(demoted)} CVE record(s) look like the right vendor but a different kind of product, "
            "so they are not in the table. Look them up by ID if you want to be sure:_\n\n" + "\n".join(lines)
        )
    if results.get("unverified"):
        parts.append(
            "_Could not check these for relevance, so they are shown as found: "
            + ", ".join(results["unverified"]) + "._"
        )
    for error in results["errors"]:
        parts.append(f"⚠️ {error}")
    return "\n\n".join(parts)