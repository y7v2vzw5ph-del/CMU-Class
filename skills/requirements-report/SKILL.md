---
name: requirements-report
description: Used by the Writer. Writes the report section for ONE component's requirements - a heading with the component's name, the CVEs, how often it was reviewed, a [TABLE] marker, and the issues the Evaluator found.
triggers:
---

You will be given JSON data about one component. Write its report section.
Your job is only to format. Do not add, remove, change, or invent anything.
You do not write the table: write the line [TABLE] and code puts the table
there.

The JSON has these fields: "component", "cves" (a list), "reviewed",
"table" and "issues" (a list).

Write these parts, in this order, each separated by a blank line:
1. A heading line: #### then the component, and NOTHING else on that line.
   Example: #### Cisco RV340
2. A line starting with **CVEs:** followed by every item of "cves", copied
   exactly, separated by commas.
3. The "reviewed" text copied exactly, with an underscore before and after it.
4. The line [TABLE] on its own, but ONLY if "table" is not null. If "table" is
   null, leave this part out.
5. If "issues" is not empty: the line **Issues the Evaluator found:**, a blank
   line, then one bullet (starting with "- ") for each item of "issues",
   copied exactly. If "issues" is empty, leave this part out completely.

Rules:
- Never put Pass, Needs review, a tick, a warning sign or any other mark or
  word next to the component's name.
- Copy every value exactly. Never make up a CVE id or a requirement id.
- Never write a table or a line that starts with |.
- Reply with ONLY the section. No introduction, no notes, no code fences.

Example. Input:
{"component": "Cisco RV340", "cves": ["CVE-2023-12345 (CVSS 9.8, CRITICAL)"], "reviewed": "Reviewed by the Evaluator 2 times.", "table": "[TABLE]", "issues": ["REQ-001: verifiable: Give the filename limit in bytes."]}

Output:
#### Cisco RV340

**CVEs:** CVE-2023-12345 (CVSS 9.8, CRITICAL)

_Reviewed by the Evaluator 2 times._

[TABLE]

**Issues the Evaluator found:**

- REQ-001: verifiable: Give the filename limit in bytes.
