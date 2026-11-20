"""A fake model for testing the requirements loop (no network, no GPU).

It answers the three kinds of prompt the loop sends:
- the Vulnerability Expert's "CVE record" prompt (write, or rewrite after the Evaluator's problems)
- the Evaluator's "Component:" prompt (review)
- the Systems Expert's CVE label prompt (so the whole graph can run)

A requirement is "bad" when its statement contains BAD_PHRASE: the fake Evaluator marks
those "revise" and the rest "pass". It lets a test say which CVEs are written badly the
first time (`bad_first`) and which are never fixed, even when rewritten (`never_fixed`).
"""

import json

BAD_PHRASE = "handle input correctly"


def first_json(text, after):
    """The first JSON value that follows `after` in `text`."""
    start = text.index(after) + len(after)
    value, _ = json.JSONDecoder().raw_decode(text, start)
    return value


class ScriptedModel:
    def __init__(self, bad_first=(), never_fixed=(), bad_formatting=False):
        self.bad_first = set(bad_first)
        self.never_fixed = set(never_fixed)
        self.bad_formatting = bad_formatting  # the Writer's table and section come back wrong
        self.calls = []  # "write", "revise", "review", "table", "section" or "other", in order

    def __call__(self, messages, tools, **kwargs):
        # The ORIGINAL request decides what this is, even on a retry (where the last message is
        # "Your reply has problems..."), like a real model reading the whole conversation.
        user = next(m["content"] for m in messages if m["role"] == "user")
        if "product_family" in messages[0]["content"] and "CVE-" in user:
            self.calls.append("other")
            return '{"product_family": "same", "cve_industry": "IoT", "reason": ""}'
        if user.startswith("CVE record"):
            return self._write(user)
        if user.startswith("Component:"):
            return self._review(user)
        if user.startswith("Requirements (JSON):"):
            return self._table(user)
        if user.startswith("Component data (JSON):"):
            return self._section(user)
        self.calls.append("other")
        return "no table from me"

    def _table(self, user):
        """The Writer's "requirements-table" skill, done the way the skill says."""
        self.calls.append("table")
        if self.bad_formatting:
            return "no formatting from me"
        rows = first_json(user, "Requirements (JSON):\n")
        lines = ["| ID | Requirement | CVE | CWE | Verification | Quality check |", "| --- | --- | --- | --- | --- | --- |"]
        lines += [
            f"| {r['id']} | {r['requirement']} | {r['cve']} | {r['cwe']} | {r['verification']} | {r['quality_check']} |"
            for r in rows
        ]
        return "\n".join(lines)

    def _section(self, user):
        """The Writer's "requirements-report" skill, done the way the skill says."""
        self.calls.append("section")
        if self.bad_formatting:
            return "no formatting from me"
        data = first_json(user, "Component data (JSON):\n")
        parts = [f"#### {data['component']}", "**CVEs:** " + ", ".join(data["cves"]), f"_{data['reviewed']}_"]
        if data["table"]:
            parts.append("[TABLE]")
        if data["issues"]:
            parts.append("**Issues the Evaluator found:**\n\n" + "\n".join(f"- {i}" for i in data["issues"]))
        return "\n\n".join(parts)

    def _write(self, user):
        record = first_json(user, "CVE record (JSON):\n")
        revising = "The Evaluator found" in user
        self.calls.append("revise" if revising else "write")
        bad = record["cve_id"] in self.never_fixed or (record["cve_id"] in self.bad_first and not revising)
        statement = (
            f"The {record['system']} shall {BAD_PHRASE}." if bad
            else f"When {record['system']} receives untrusted input, {record['system']} shall reject input that triggers {record['cve_id']}."
        )
        return json.dumps([{
            "id": "REQ-999", "component": "ignored", "statement": statement,
            "rationale": "Stops the weakness.", "sources": {"cves": ["CVE-0-0"], "cwes": []},
            "verification": {"method": "Test", "criterion": "The crafted input is rejected."},
            "assumptions": [], "gate_status": "passed",
        }])

    def _review(self, user):
        self.calls.append("review")
        reqs = first_json(user, "Requirements (JSON):\n")
        reviews = []
        for r in reqs:
            bad = BAD_PHRASE in r["statement"]
            reviews.append({
                "id": r["id"], "quote": r["statement"], "reasoning": "Checked against the rules.",
                "problems": [{"rule": "verifiable", "evidence": BAD_PHRASE, "explanation": "No limit."}] if bad else [],
                "verdict": "revise" if bad else "pass", "severity": "major" if bad else "none",
                "suggested_rewrite": f"{r['component']} shall reject input longer than 255 bytes." if bad else "",
            })
        return json.dumps({"requirements": reviews, "duplicates": [], "contradictions": [], "terminology": []})
