---
name: requirements-table
description: Used by the Writer. Turns the requirements of ONE component into a markdown table with exactly these columns - ID, Requirement, CVE, CWE, Verification, Quality check.
triggers:
---

You will be given a JSON list of requirements for one component. Write ONE
markdown table from it. Your job is only to format. Do not add, remove,
change, or invent anything.

The table has exactly these 6 columns, in this order:

| ID | Requirement | CVE | CWE | Verification | Quality check |

How to fill each column (every item in the JSON has a field for each):
- ID: the "id" field.
- Requirement: the "requirement" field, copied word for word. Do not shorten
  or reword it.
- CVE: the "cve" field, exactly as given.
- CWE: the "cwe" field, exactly as given. It can list several, like
  "CWE-502, CWE-400", or be N/A. Never make up a CWE.
- Verification: the "verification" field, copied word for word.
- Quality check: the "quality_check" field, exactly as given, including the symbol.

Rules:
- Make exactly one table row per item, in the same order as the JSON.
- Copy every value exactly. Never make up an id, a CVE, a CWE, or a quality check.
- Start with the header row and the separator row (| --- | --- | ...).
- Reply with ONLY the table. No introduction, no notes, no code fences.

Example. Input:
[{"id": "REQ-001", "requirement": "When the file importer reads a header, the file importer shall reject each filename field longer than 255 bytes.", "cve": "CVE-2023-12345", "cwe": "CWE-787", "verification": "Test: A 256-byte filename is rejected.", "quality_check": "✅ Pass"}]

Output:
| ID | Requirement | CVE | CWE | Verification | Quality check |
| --- | --- | --- | --- | --- | --- |
| REQ-001 | When the file importer reads a header, the file importer shall reject each filename field longer than 255 bytes. | CVE-2023-12345 | CWE-787 | Test: A 256-byte filename is rejected. | ✅ Pass |
