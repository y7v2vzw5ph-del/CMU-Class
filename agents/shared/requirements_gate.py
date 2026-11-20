"""Lightweight regex gate for INCOSE-style requirements.

Used by the requirements agents (see skills/incose-requirements). Plain code,
no model. Agent code calls check_all(new, existing) after the Writer answers
for one CVE, and sends the errors back to the Writer if it fails.

    from shared.requirements_gate import check_all
    report = check_all(new_requirements, accepted_requirements)
    report["passed"]   # False -> make the Writer rewrite that CVE (max 3 tries)

Command line, for trying it by hand:
    uv run agents/shared/requirements_gate.py NEW.json [--existing ALL.json]

NEW.json      JSON list of requirement objects (or {"requirements": [...]}).
--existing    Requirements already accepted. Used only to detect duplicate IDs.

Prints a JSON report. Exit code 0 = no errors (warnings allowed), 1 = errors.

This gate only catches SURFACE problems. Passing it does not mean a
requirement is good. Judgment calls belong to the evaluator.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REQUIRED_FIELDS = (
    "id",
    "component",
    "statement",
    "rationale",
    "sources",
    "verification",
)
VERIFICATION_METHODS = {"Test", "Inspection", "Analysis", "Demonstration"}
ID_RE = re.compile(r"^REQ-\d{3,}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Each rule: (rule_name, compiled regex, message). Matched case-insensitively.
ERROR_RULES = [
    ("forbidden_verb", r"\b(should|will|must|may)\b",
     "Use 'shall' as the only requirement verb."),
    ("and_or", r"\band/or\b",
     "Avoid 'and/or'; state the logic explicitly."),
    ("tbd", r"\b(tbd|tbr|to be determined)\b",
     "No TBD/TBR; move the gap to assumptions."),
    ("open_ended", r"\b(etc\.?|and so on|including but not limited to)",
     "Open-ended list; enumerate the items."),
    ("vague_term",
     r"\b(adequate|appropriate|sufficient|reasonable|robust|user-friendly|"
     r"easy|easily|flexible|fast|quickly|as needed|as required)\b",
     "Vague or subjective term; make it measurable."),
    ("vague_secure", r"\b(be|is|are)\s+secure\b",
     "'Secure' is unverifiable; state the specific property."),
    ("escape_clause",
     r"\b(where possible|if possible|where feasible|as far as|so far as|"
     r"if practicable|as applicable)\b",
     "Escape clause; remove or state the real condition."),
]

WARNING_RULES = [
    ("possible_compound", r"\b(and|or|as well as)\b",
     "Possible compound requirement; confirm it is singular."),
    ("absolute", r"\b(all|every|always|never|any)\b",
     "Absolute term; confirm it is intended and verifiable."),
    ("vague_quantity",
     r"\b(many|several|some|few|large|small|high|low|minimal|maximum|minimum)\b",
     "Unquantified amount; give a number and unit if possible."),
    ("pronoun", r"\b(it|its|they|them|their)\b",
     "Pronoun with possible unclear referent; name the subject."),
    ("negative_form", r"\bshall not\b",
     "Negative form; prefer a positive form unless a true prohibition."),
    ("generic_subject", r"\bthe system shall\b",
     "Generic subject; name the specific component."),
]

QUANTITY_WORDS = re.compile(
    r"\b(within|at least|at most|no more than|no less than|less than|"
    r"greater than|longer than|shorter than|per second|per minute)\b",
    re.IGNORECASE,
)
MAX_WORDS = 40


def _compile(rules):
    return [(n, re.compile(p, re.IGNORECASE), m) for n, p, m in rules]


_ERRORS = _compile(ERROR_RULES)
_WARNINGS = _compile(WARNING_RULES)


def load_requirements(path: Path) -> list[dict]:
    # utf-8-sig tolerates the BOM that Windows PowerShell adds to files.
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(data, dict):
        data = data.get("requirements", [])
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a list of requirements")
    return data


def _issue(rule: str, message: str, match: str | None = None) -> dict:
    issue = {"rule": rule, "message": message}
    if match:
        issue["match"] = match
    return issue


def check_requirement(req: dict, seen_ids: set[str]) -> dict:
    """Check one requirement. Returns {id, errors, warnings}."""
    errors: list[dict] = []
    warnings: list[dict] = []
    rid = str(req.get("id", "<missing>"))

    # --- structure ---------------------------------------------------------
    for field in REQUIRED_FIELDS:
        if not req.get(field):
            errors.append(_issue("missing_field", f"Missing required field '{field}'."))

    if req.get("id"):
        if not ID_RE.match(rid):
            errors.append(_issue("bad_id", "ID must look like REQ-001.", rid))
        if rid in seen_ids:
            errors.append(_issue("duplicate_id", "ID already used.", rid))

    sources = req.get("sources") or {}
    cves = sources.get("cves") if isinstance(sources, dict) else None
    if req.get("sources") and not cves:
        errors.append(_issue("missing_source", "sources.cves must list at least one CVE."))
    for cve in cves or []:
        if not CVE_RE.match(str(cve)):
            errors.append(_issue("bad_cve_id", "CVE ID must look like CVE-2023-12345.", str(cve)))

    verification = req.get("verification") or {}
    if verification and not isinstance(verification, dict):
        errors.append(_issue("bad_verification", "verification must be an object with method and criterion."))
    elif verification:
        if verification.get("method") not in VERIFICATION_METHODS:
            errors.append(_issue(
                "bad_verification_method",
                f"verification.method must be one of {sorted(VERIFICATION_METHODS)}.",
                str(verification.get("method")),
            ))
        if not verification.get("criterion"):
            errors.append(_issue("missing_field", "Missing verification.criterion."))

    # --- statement text ----------------------------------------------------
    statement = str(req.get("statement") or "")
    if statement:
        if not re.search(r"\bshall\b", statement, re.IGNORECASE):
            errors.append(_issue("missing_shall", "Statement must contain 'shall'."))
        for name, rx, msg in _ERRORS:
            m = rx.search(statement)
            if m:
                errors.append(_issue(name, msg, m.group(0)))
        for name, rx, msg in _WARNINGS:
            m = rx.search(statement)
            if m:
                warnings.append(_issue(name, msg, m.group(0)))

        words = len(statement.split())
        if words > MAX_WORDS:
            warnings.append(_issue("long_statement", f"{words} words; limit is about {MAX_WORDS}."))
        if len(re.findall(r"[.!?](\s|$)", statement)) > 1:
            warnings.append(_issue("multiple_sentences", "More than one sentence; keep it to one."))
        if QUANTITY_WORDS.search(statement) and not re.search(r"\d", statement):
            warnings.append(_issue("quantity_without_number", "Quantity wording but no number."))

    return {"id": rid, "errors": errors, "warnings": warnings}


def check_all(new: list[dict], existing: list[dict] | None = None) -> dict:
    seen = {str(r.get("id")) for r in (existing or []) if r.get("id")}
    results = []
    for req in new:
        result = check_requirement(req, seen)
        results.append(result)
        if req.get("id"):
            seen.add(str(req["id"]))
    return {
        "passed": all(not r["errors"] for r in results),
        "error_count": sum(len(r["errors"]) for r in results),
        "warning_count": sum(len(r["warnings"]) for r in results),
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("new", type=Path, help="JSON file with the new requirements")
    parser.add_argument("--existing", type=Path, help="JSON file with accepted requirements")
    args = parser.parse_args(argv)

    new = load_requirements(args.new)
    existing = load_requirements(args.existing) if args.existing else None
    report = check_all(new, existing)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
